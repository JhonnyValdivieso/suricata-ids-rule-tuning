#!/usr/bin/env python3
"""
Suricata IDS rule test suite.

Runs a set of attacks (plus one benign case) against the lab, then checks
Suricata's eve.json to VERIFY that the expected alert (signature_id / SID)
was generated. This proves the rules actually fire -- it does not just launch
the attack and hope.

Design notes (worth reading before you clone this):

- We read eve.json from INSIDE the Suricata container (via `docker exec`),
  not from the file mounted on the host. On Docker Desktop / WSL2 the
  host-mounted file lags a few seconds behind, which made the tests flaky.

- We read only the bytes written AFTER the attack (a byte offset). eve.json is
  append-only, so reading from the start would match OLD alerts from previous
  runs and give false passes.

- Each test case restarts Suricata first. Suricata rate-limits repeated alerts
  of the same SID with the `threshold` keyword. Without a clean restart, a
  second test that reuses a SID gets silently suppressed and looks like a
  failure -- even though the rule matched. Restarting clears the counters so
  every case starts from a known state.

- THREE outcomes, not two. "I could not verify" is NOT a pass and NOT a fail.
  A dead sensor, an attack command that never ran, or a truncated log all mean
  the test proved nothing -- so they are reported as ERROR. A suite that
  silently turns "I couldn't check" into a green tick is worthless.
"""

import subprocess
import sys
import time
import json
import os

CONTAINER = "suricata_ids"             # Suricata container name (see docker-compose.yml)
EVE = "/var/log/suricata/eve.json"     # Suricata JSON event log, path INSIDE the container
SURILOG = "/var/log/suricata/suricata.log"  # Suricata engine log, path INSIDE the container

PASS, FAIL, ERROR = "PASS", "FAIL", "ERROR"


# ---------------------------------------------------------------------------
# Low-level helpers
# ---------------------------------------------------------------------------

def docker_exec(args):
    """Run a command inside the Suricata container.

    Returns (stdout, ok). `ok` is True only if the command exited cleanly.
    Every caller MUST propagate `ok` up to the pass/fail decision: it is what
    lets us tell 'no alerts were found' apart from 'I could not even read the
    file' (e.g. container down)."""
    result = subprocess.run(
        ["docker", "exec", CONTAINER] + args,
        capture_output=True, text=True,
        encoding="utf-8", errors="ignore",
    )
    return result.stdout, result.returncode == 0


def file_size(path):
    """Size of a file inside the container, in bytes. Returns (size, ok).

    We record this BEFORE an attack so that afterwards we can skip everything
    that was already there and read only the new events. Note it returns `ok`
    rather than falling back to 0 -- a silent 0 would mean 'read the whole
    file', which matches alerts from previous runs and fakes a pass."""
    output, ok = docker_exec(["stat", "-c", "%s", path])
    if not ok:
        return 0, False
    try:
        return int(output.strip()), True
    except ValueError:
        return 0, False


def read_from(path, offset):
    """Read a file inside the container starting at `offset` bytes.

    Returns (text, ok). `tail -c +N` prints the file from byte N onward. Heads
    up: tail counts from 1, not 0, so to skip `offset` bytes we ask for
    offset + 1 (off-by-one).

    Truncation guard: if the file is now SMALLER than the offset we recorded,
    it was rotated or truncated underneath us. Reading would silently return
    nothing, which looks exactly like 'no alerts'. We refuse instead."""
    size, ok = file_size(path)
    if not ok:
        return "", False
    if size < offset:
        return "", False
    output, ok = docker_exec(["tail", "-c", f"+{offset + 1}", path])
    return output, ok


def run_attack(command):
    """Fire an attack command (a curl / ping / nmap from the attacker container).

    Returns ok. We do not care about the output, but we DO care that the
    command actually ran: if curl or nmap never executes there is no traffic,
    no alerts, and a negative test would pass for the wrong reason."""
    result = subprocess.run(command, capture_output=True, text=True)
    return result.returncode == 0


# ---------------------------------------------------------------------------
# eve.json parsing
# ---------------------------------------------------------------------------

def new_alerts(offset):
    """Collect the signature_ids of every alert written after `offset`.

    Returns (sids, dropped, ok)."""
    output, ok = read_from(EVE, offset)
    if not ok:
        return [], 0, False

    sids = []
    dropped = 0
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            # A line can be half-written if we read while Suricata is writing.
            # We skip it, but we COUNT it: silently dropping log lines is a real
            # log-evasion vector, so a healthy pipeline should report the drops.
            dropped += 1
            continue
        if event.get("event_type") == "alert":
            sid = event.get("alert", {}).get("signature_id")
            if sid is not None:
                sids.append(sid)
    return sids, dropped, True


def wait_for_alert(offset, expected_sid, timeout=15):
    """Poll eve.json until `expected_sid` appears, or until `timeout` seconds
    pass. Returns (found, sids, dropped, ok).

    Polling returns the moment the alert shows up, so a passing test is fast;
    only a failing test waits the full timeout."""
    deadline = time.time() + timeout
    sids, dropped, ok = [], 0, False
    while time.time() < deadline:
        sids, dropped, ok = new_alerts(offset)
        if not ok:
            return False, [], 0, False
        if expected_sid in sids:
            return True, sids, dropped, True
        time.sleep(0.5)
    # One last read after the timeout, in case it arrived right at the end.
    sids, dropped, ok = new_alerts(offset)
    return (expected_sid in sids), sids, dropped, ok


# ---------------------------------------------------------------------------
# Sensor lifecycle
# ---------------------------------------------------------------------------

def restart_suricata(timeout=45):
    """Restart Suricata and WAIT until the engine reports it is capturing.

    Returns ok. We used to sleep a fixed number of seconds and hope; if rule
    loading took longer than the guess, the first packets of the attack were
    missed and the test failed intermittently. Instead we tail suricata.log
    from the point of the restart and wait for the engine-started line.

    We also parse the rule-load summary: if any rule failed to load (a syntax
    error, or a DUPLICATE SID) the whole run is meaningless, so we say so
    loudly instead of testing against a ruleset that is not what is on disk."""
    log_offset, _ = file_size(SURILOG)  # ok is not required: 0 just means read all

    result = subprocess.run(["docker", "compose", "restart", "suricata"],
                            capture_output=True, text=True)
    if result.returncode != 0:
        print("    [!] ERROR: `docker compose restart suricata` failed")
        return False

    deadline = time.time() + timeout
    while time.time() < deadline:
        output, ok = read_from(SURILOG, log_offset)
        if ok and "engine started" in output.lower():
            for line in output.splitlines():
                # e.g. "1 rule files processed. 5 rules successfully loaded, 0 rules failed"
                if "rules failed" in line:
                    failed = line.rsplit("loaded,", 1)[-1].strip()
                    if not failed.startswith("0 "):
                        print(f"    [!] ERROR: Suricata failed to load rules -> {failed}")
                        print("        (a duplicate sid or a syntax error in rules/local.rules)")
                        return False
            return True
        time.sleep(0.5)

    print("    [!] ERROR: Suricata did not report 'engine started' in time")
    return False


def preflight():
    """Refuse to run at all if the environment is not what the suite assumes."""
    if not os.path.exists("docker-compose.yml"):
        print("[!] Run this from the repository root (docker-compose.yml not found).")
        return False
    _, ok = file_size(EVE)
    if not ok:
        print(f"[!] Cannot read {EVE} inside '{CONTAINER}'. Is the lab up?")
        print("    Try: docker compose up -d")
        return False
    return True


# ---------------------------------------------------------------------------
# Test cases
# ---------------------------------------------------------------------------

def report(status, name, detail=""):
    marker = {PASS: "[+]", FAIL: "[-]", ERROR: "[!]"}[status]
    print(f"{marker} {status:<5} {name}" + (f"  ({detail})" if detail else ""))
    return status


def run_case(name, command, expected_sid, isolate=True):
    """POSITIVE test: launch an attack and assert the expected SID fires."""
    if isolate and not restart_suricata():
        return report(ERROR, name, "sensor not ready, nothing was verified")

    offset, ok = file_size(EVE)          # remember where the log ends right now
    if not ok:
        return report(ERROR, name, "could not read eve.json")

    if not run_attack(command):          # launch the attack
        return report(ERROR, name, "attack command did not run")

    found, sids, dropped, ok = wait_for_alert(offset, expected_sid)
    if not ok:
        return report(ERROR, name, "eve.json unreadable or truncated mid-test")

    if found:
        status = report(PASS, name, f"SID {expected_sid} detected")
        # Overlapping coverage is not a failure, but an analyst should know:
        # one request firing several rules means duplicated alerts in the SOC.
        extra = sorted(set(sids) - {expected_sid})
        if extra:
            print(f"    [i] NOTE: same traffic also fired {extra} (overlapping signatures)")
    else:
        # Showing what we DID see distinguishes 'nothing fired' ([]) from
        # 'the wrong rule fired' ([some other SID]).
        status = report(FAIL, name, f"expected SID {expected_sid}, got: {sids}")

    if dropped:
        print(f"    [!] WARNING: {dropped} malformed JSON lines dropped")
    return status


def run_negative_case(name, command, wait=6, isolate=True):
    """NEGATIVE test: send benign traffic and assert NO alert fires.

    To prove *absence* we must wait the full time and then check, because an
    alert could still arrive a second or two after the request. Absence of
    evidence only counts if we are certain we could have seen the evidence --
    hence every `ok` below is checked."""
    if isolate and not restart_suricata():
        return report(ERROR, name, "sensor not ready, nothing was verified")

    offset, ok = file_size(EVE)
    if not ok:
        return report(ERROR, name, "could not read eve.json")

    if not run_attack(command):
        return report(ERROR, name, "benign traffic command did not run")

    time.sleep(wait)
    sids, dropped, ok = new_alerts(offset)
    if not ok:
        return report(ERROR, name, "eve.json unreadable or truncated mid-test")

    if not sids:
        status = report(PASS, name, "no alerts, as expected")
    else:
        # Any SID here is a false positive: some rule is too aggressive.
        status = report(FAIL, name, f"false positives: {sids}")

    if dropped:
        print(f"    [!] WARNING: {dropped} malformed JSON lines dropped")
    return status


# ---------------------------------------------------------------------------
# Suite
# ---------------------------------------------------------------------------

def main():
    if not preflight():
        return 2

    results = []

    # SID 1000001 - ICMP echo (ping sweep / host discovery)
    results.append(run_case(
        "ICMP ping sweep",
        ["docker", "exec", "attacker", "ping", "-c", "4", "victim"],
        1000001,
    ))

    # Negative - a plain HTTP GET must NOT trigger any rule
    results.append(run_negative_case(
        "Benign HTTP traffic",
        ["docker", "exec", "attacker", "curl", "-s", "http://victim/"],
    ))

    # SID 1000002 - Nmap SYN scan across 100 ports (well over the threshold)
    results.append(run_case(
        "Nmap SYN port scan",
        ["docker", "exec", "attacker", "nmap", "-sS", "-p", "1-100", "victim"],
        1000002,
    ))

    # SID 1000003 - UNION-based SQLi, normal spacing
    results.append(run_case(
        "SQLi UNION-SELECT (normal)",
        ["docker", "exec", "attacker", "curl", "-s",
         "http://victim/?id=1%20UNION%20SELECT%201,2,3"],
        1000003,
    ))

    # SID 1000003 - UNION-based SQLi, padded to defeat a `within:` limit.
    # "%20" * 12 = 12 encoded spaces between UNION and SELECT. This case fails
    # against the old rule (within:20) and passes against the fixed one
    # (distance:0, no within). It's the evasion this lab was built to show.
    results.append(run_case(
        "SQLi UNION-SELECT (evasive, >20 bytes padding)",
        ["docker", "exec", "attacker", "curl", "-s",
         "http://victim/?id=1%20UNION" + "%20" * 12 + "SELECT%201,2,3"],
        1000003,
    ))

    # SID 1000004 - Tautology / auth bypass:  admin' OR '1'='1
    results.append(run_case(
        "SQLi tautology / auth bypass",
        ["docker", "exec", "attacker", "curl", "-s",
         "http://victim/login?user=admin%27%20OR%20%271%27=%271"],
        1000004,
    ))

    # SID 1000005 - Blind time-based:  1' OR SLEEP(5)--
    # Expect an overlap NOTE here: the payload also carries a quote + OR, so
    # SID 1000004 fires on the same request. Documented, not a bug.
    results.append(run_case(
        "SQLi blind time-based",
        ["docker", "exec", "attacker", "curl", "-s",
         "http://victim/?id=1%27%20OR%20SLEEP%285%29--"],
        1000005,
    ))

    passed = results.count(PASS)
    failed = results.count(FAIL)
    errored = results.count(ERROR)
    print(f"\n{passed}/{len(results)} cases passed"
          f"  ({failed} failed, {errored} not verified)")

    # Exit non-zero unless every case genuinely passed, so the suite can be
    # used in CI or chained with && instead of being read by a human.
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
