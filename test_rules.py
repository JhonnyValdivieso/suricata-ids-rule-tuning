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
"""

import subprocess
import json
import time

CONTAINER = "suricata_ids"          # Suricata container name (see docker-compose.yml)
EVE = "/var/log/suricata/eve.json"  # Suricata JSON event log, path INSIDE the container


def docker_exec(args):
    """Run a command inside the Suricata container.

    Returns (stdout, ok). `ok` is True only if the command exited cleanly.
    Keeping `ok` lets us tell 'no alerts were found' apart from
    'I could not even read the file' (e.g. container down)."""
    result = subprocess.run(
        ["docker", "exec", CONTAINER] + args,
        capture_output=True, text=True,
        encoding="utf-8", errors="ignore",
    )
    return result.stdout, result.returncode == 0


def current_size():
    """Return the size of eve.json in bytes, read from inside the container.

    We record this number BEFORE an attack so that afterwards we can skip
    everything that was already there and read only the new events."""
    output, ok = docker_exec(["stat", "-c", "%s", EVE])
    if not ok:
        return 0
    try:
        return int(output.strip())
    except ValueError:
        return 0


def run_attack(command):
    """Fire an attack command (a curl / ping / nmap from the attacker container).
    We ignore its output here; we only care about the alert it triggers."""
    subprocess.run(command, capture_output=True, text=True)


def new_alerts(offset):
    """Read eve.json starting at `offset` bytes and collect the signature_ids
    of every alert found there. Returns (list_of_sids, dropped_lines).

    `tail -c +N` prints the file from byte N onward. Heads up: tail counts from
    1, not 0, so to skip `offset` bytes we ask for offset + 1 (off-by-one)."""
    output, ok = docker_exec(["tail", "-c", f"+{offset + 1}", EVE])
    if not ok:
        return [], 0

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
            sids.append(event["alert"]["signature_id"])
    return sids, dropped


def wait_for_alert(offset, expected_sid, timeout=15):
    """Poll eve.json until `expected_sid` appears, or until `timeout` seconds
    pass. Returns (found, sids_seen, dropped).

    Polling returns the moment the alert shows up, so a passing test is fast;
    only a failing test waits the full timeout."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        sids, dropped = new_alerts(offset)
        if expected_sid in sids:
            return True, sids, dropped
        time.sleep(0.5)
    # One last read after the timeout, in case it arrived right at the end.
    sids, dropped = new_alerts(offset)
    return expected_sid in sids, sids, dropped


def restart_suricata():
    """Restart Suricata and give it a few seconds to load rules and start
    capturing. This clears any pending `threshold` counters so each test case
    starts clean (see the design notes at the top of the file)."""
    subprocess.run(["docker", "compose", "restart", "suricata"],
                   capture_output=True, text=True)
    time.sleep(5)


def run_case(name, command, expected_sid, isolate=True):
    """POSITIVE test: launch an attack and assert the expected SID fires."""
    if isolate:
        restart_suricata()

    offset = current_size()          # remember where the log ends right now
    run_attack(command)              # launch the attack
    found, sids, dropped = wait_for_alert(offset, expected_sid)

    if found:
        print(f"[+] PASS  {name}  (SID {expected_sid} detected)")
    else:
        # Printing what we DID see distinguishes 'nothing fired' ([]) from
        # 'the wrong rule fired' ([some other SID]).
        print(f"[-] FAIL  {name}  (expected SID {expected_sid}, got: {sids})")

    if dropped > 0:
        print(f"    [!] WARNING: {dropped} malformed JSON lines dropped")

    return found


def run_negative_case(name, command, wait=6, isolate=True):
    """NEGATIVE test: send benign traffic and assert NO alert fires.

    To prove *absence* we must wait the full time and then check, because an
    alert could still arrive a second or two after the request."""
    if isolate:
        restart_suricata()

    offset = current_size()
    run_attack(command)
    time.sleep(wait)
    sids, dropped = new_alerts(offset)

    if not sids:
        print(f"[+] PASS  {name}  (no alerts, as expected)")
        ok = True
    else:
        # Any SID here is a false positive: some rule is too aggressive.
        print(f"[-] FAIL  {name}  (false positives: {sids})")
        ok = False

    if dropped > 0:
        print(f"    [!] WARNING: {dropped} malformed JSON lines dropped")

    return ok


if __name__ == "__main__":
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
    results.append(run_case(
        "SQLi blind time-based",
        ["docker", "exec", "attacker", "curl", "-s",
         "http://victim/?id=1%27%20OR%20SLEEP%285%29--"],
        1000005,
    ))

    print(f"\n{sum(results)}/{len(results)} cases passed")