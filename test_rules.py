import subprocess
import time

def print_header(text):
    print("\n" + "=" * 60)
    print(f"  {text}")
    print("=" * 60)

def run_command(description, command):
    print(f"\n> [{description}]")
    print(f"  Executing: {command}")
    try:
        # Runs the Docker command in the system shell
        subprocess.run(command, shell=True, check=True, text=True, capture_output=True)
        print("  Status: SUCCESS")
    except subprocess.CalledProcessError:
        # Handles cases where the target server returns an error HTTP status
        print("  Status: EXECUTED (Event sent to network interface)")

def main():
    print_header("STARTING AUTOMATED IDS TEST SUITE - SURICATA")
    
    # Test 1: ICMP Ping Discovery
    run_command(
        "1/3 - ICMP Traffic Test (Ping)", 
        "docker run --rm --network host alpine ping -c 3 1.1.1.1"
    )
    time.sleep(2)

    # Test 2: Nmap SYN Port Scan
    run_command(
        "2/3 - TCP SYN Port Scan (Nmap)", 
        "docker run --rm --network host instrumentisto/nmap -sS -p 1-100 1.1.1.1"
    )
    time.sleep(2)

    # Test 3: SQL Injection Attempt
    run_command(
        "3/3 - SQL Injection Attempt (HTTP UNION)",
        'docker run --rm --network host alpine wget -qO- "http://127.0.0.1:2376/index.php?id=1 UNION SELECT 1,2,3--"'
    )

    print_header("✅ ALL TESTS EXECUTED - CHECK YOUR FAST.LOG MONITOR")

if __name__ == "__main__":
    main()