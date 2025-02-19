import re
import time
import subprocess
from collections import defaultdict

# Log file path (adjust based on system)
log_file = "/var/log/auth.log"  # Example: Linux authentication log

# Security settings
threshold = 5  # Max failed attempts before blocking
time_window = 600  # 10 minutes in seconds
privileged_accounts = ["root", "admin", "administrator"]  # Modify as needed

# Dictionaries for tracking failed attempts and blocked IPs
failed_attempts = defaultdict(list)
blocked_ips = set()

# Private/internal IP ranges to avoid blocking
PRIVATE_IP_RANGES = ["10.", "172.16.", "192.168.", "127.", "::1"]

def is_private_ip(ip):
    """Check if an IP is private/internal."""
    return any(ip.startswith(prefix) for prefix in PRIVATE_IP_RANGES)

def block_ip(ip):
    """Block an IP using iptables (Linux)"""
    if is_private_ip(ip):
        print(f"[WARNING] Skipping block for private/internal IP: {ip}")
        return
    
    if ip in blocked_ips:
        return  # IP already blocked

    print(f"[ALERT] Blocking IP: {ip}")

    try:
        subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
        print(f"[INFO] IP {ip} blocked.")

        # Log the blocked IP
        with open("blocked_ips.txt", "a") as log:
            log.write(f"{ip} blocked at {time.ctime()}\n")

        blocked_ips.add(ip)
    
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Failed to block IP {ip}: {e}")

def analyze_logs():
    """Monitor logs for failed logins and privileged account logins."""
    while True:
        try:
            with open(log_file, "r") as f:
                for line in f:
                    # Regex to extract failed login attempts
                    match = re.search(r"(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*(Failed|failure|invalid) password", line, re.IGNORECASE)

                    if match:
                        ip = match.group("ip")
                        failed_attempts[ip].append(time.time())

                        # Keep only recent attempts
                        now = time.time()
                        failed_attempts[ip] = [t for t in failed_attempts[ip] if now - t < time_window]

                        # Block if threshold exceeded
                        if len(failed_attempts[ip]) >= threshold:
                            print(f"[ALERT] Brute-force detected from {ip} ({len(failed_attempts[ip])} failed attempts)")
                            block_ip(ip)

                    # Monitor privileged account logins
                    for user in privileged_accounts:
                        if f"Accepted password for {user}" in line:
                            print(f"[ALERT] Privileged account login detected: {line.strip()}")

            time.sleep(60)  # Check logs every minute

        except FileNotFoundError:
            print(f"[ERROR] Log file '{log_file}' not found.")
            break
        except Exception as e:
            print(f"[ERROR] An error occurred: {e}")
            break

def simulate_failed_logins():
    """Simulate failed logins for testing."""
    test_ip = "192.168.1.100"
    now = time.time()

    print("[INFO] Simulating failed logins...")

    for _ in range(threshold):
        failed_attempts[test_ip].append(now)
        time.sleep(2)  # Simulate time gaps

    analyze_logs()  # Run detection logic

if __name__ == "__main__":
    print("[INFO] Monitoring login attempts...")
    # Simulate failed logins
    simulate_failed_logins()
    analyze_logs()
