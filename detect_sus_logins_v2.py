import re
import time
import subprocess
import os
from collections import defaultdict

# Log file path (adjust based on system)
log_file = "/var/log/auth.log"

# Security settings
threshold = 5  # Max failed attempts before blocking
time_window = 600  # 10 minutes in seconds
privileged_accounts = ["root", "admin", "administrator"]  # Modify as needed

# Dictionaries for tracking failed attempts and blocked IPs
failed_attempts = defaultdict(list)
blocked_ips = set()

def block_ip(ip):
    """Block an IP using iptables (Linux)"""
    
    if ip in blocked_ips:
        print(f'[ALERT] Previously Blocked IP detected: {ip} , Check IP Tables rules')
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
                current_inode = os.stat(log_file).st_ino
                f.seek(0,2)
                while True:
                    if os.stat(log_file).st_ino != current_inode:
                        f.close()
                        f = open(log_file,'r')
                        current_inode = os.stat(log_file).st_ino
                        print('[INFO] Log file rotated, reopening')
                    line = f.readline()
                    if not line:
                        time.sleep(1)
                        continue
                        # Regex to extract failed login attempts
                    match = re.search(r"Failed password for .*? from (\d+\.\d+\.\d+\.\d+)",line, re.IGNORECASE)

                    if match:
                        # ip = match.group("ip")
                        ip = match.group(1)
                        failed_attempts[ip].append(time.time())

                        # Keep only recent attempts
                        now = time.time()
                        failed_attempts[ip] = [t for t in failed_attempts[ip] if now - t < time_window]
                        print(f"[INFO] Failed login attempt from {ip} ({len(failed_attempts[ip])} failed attempts)")

                        # Block if threshold exceeded
                        if len(failed_attempts[ip]) >= threshold:
                            print(f"[ALERT] Brute-force detected from {ip} ({len(failed_attempts[ip])} failed attempts)")
                            block_ip(ip)

                    # Monitor privileged account logins
                    for user in privileged_accounts:
                        if f"Accepted password for {user}" in line:
                            print(f"[ALERT] Privileged account login detected: {line.strip()}")

        except FileNotFoundError:
            print(f"[ERROR] Log file '{log_file}' not found.")
            break
        except Exception as e:
            print(f"[ERROR] An error occurred: {e}")
            break

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("[ERROR] Must be ran as root")
        os._exit(1)
    print("[INFO] Monitoring login attempts...")
    analyze_logs()