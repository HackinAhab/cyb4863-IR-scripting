import os
import json
import subprocess
from datetime import datetime

def get_installed_apps():
    apps = {}
    if os.path.exists("/etc/debian_version"):
        cmd = "dpkg-query -W -f='${Package} ${Version}\n'"
    elif os.path.exists("/etc/redhat-release"):
        cmd = "rpm -qa --queryformat '%{NAME} %{VERSION}\n'"
    else:
        return {"error": "Unsupported Linux distribution"}
    
    try:
        result = subprocess.check_output(cmd, shell=True, text=True).strip()
        for line in result.split('\n'):
            if line:
                name, version = line.split(" ", 1)
                apps[name] = version
    except subprocess.CalledProcessError:
        return {"error": "Failed to retrieve installed applications"}
    
    return apps

def get_listening_services():
    services = []
    try:
        result = subprocess.check_output("ss -tulnp", shell=True, text=True).strip()
        for line in result.split('\n')[1:]:
            services.append(line.strip())
    except subprocess.CalledProcessError:
        return ["Failed to retrieve listening services"]
    
    return services

def get_running_processes():
    processes = []
    try:
        result = subprocess.check_output("ps aux", shell=True, text=True).strip()
        for line in result.split('\n')[1:]:
            processes.append(line)
    except subprocess.CalledProcessError:
        return ["Failed to retrieve processes"]
    
    return processes

def get_active_user_processes():
    active_user_processes = {}
    try:
        active_users = get_active_users()
        for user in active_users:
            username = user.split()[0]
            cmd = f"ps -u {username} -o user,pid,cmd"
            result = subprocess.check_output(cmd, shell=True, text=True).strip()
            active_user_processes[username] = result.split('\n')[1:] if result else []
    except subprocess.CalledProcessError:
        return {"error": "Failed to retrieve active user processes"}
    
    return active_user_processes

def get_all_users():
    users = []
    try:
        with open("/etc/passwd", "r") as f:
            for line in f:
                users.append(f'username:{line.split(":")[0]} uid:{line.split(":")[2]} gid:{line.split(":")[3]} home directory:{line.split(":")[5]}')
    except Exception as e:
        return [f"Failed to retrieve users {e}"]
    
    return users

def get_active_users():
    active_users = []
    try:
        result = subprocess.check_output("who", shell=True, text=True).strip()
        for line in result.split('\n'):
            if line:
                active_users.append(line)
    except subprocess.CalledProcessError:
        return ["Failed to retrieve active users"]
    
    return active_users

def check_sudoers():
    sudoers = []
    extra_includedir = []
    try:
        # Check default sudoers file
        with open("/etc/sudoers", "r") as f:
            for line in f:
                # Look for extra included directories
                if line.startswith("@includedir") and not "/etc/sudoers.d" in line:
                    extra_includedir.append(line.strip().split()[1])
                    sudoers.append(f"Non-Default sudoer includedir: {line.strip().split()[1]}")
                # Skip comments and empty lines, and default options
                if not line.startswith("#") and not line.startswith("\n") and not line.startswith("Defaults") and not line.startswith("@includedir"):
                    sudoers.append(line.strip())
        # check default extra sudoers files
        extra_sudoers = subprocess.check_output("ls /etc/sudoers.d", shell=True, text=True).strip().split('\n')
        for file in extra_sudoers:
            with open(f"/etc/sudoers.d/{file}", "r") as f:
                for line in f:
                    if not line.startswith("#") and not line.startswith("\n") and not line.startswith("Defaults"):
                        sudoers.append(line.strip())
        # check extra included directories if found
        for extra_dir in extra_includedir:
            extra_sudoers = subprocess.check_output(f"ls {extra_dir}", shell=True, text=True).strip().split('\n')
            for file in extra_sudoers:
                with open(f"{extra_dir}/{file}", "r") as f:
                    for line in f:
                        if not line.startswith("#") and not line.startswith("\n") and not line.startswith("Defaults"):
                            sudoers.append(line.strip())
    except Exception as e:
        return [f"Failed to retrieve sudoers: {e}"]
    
    return sudoers

def get_device_history():
    history = {}
    try:
        result = subprocess.check_output("lsblk -o NAME,MOUNTPOINT", shell=True, text=True).strip()
        history["current_devices"] = result.split('\n')[1:]
        
        if os.path.exists("/var/log/syslog"):
            log_cmd = "grep -i 'usb' /var/log/syslog | tail -n 20"
        elif os.path.exists("/var/log/messages"):
            log_cmd = "grep -i 'usb' /var/log/messages | tail -n 20"
        else:
            return {"error": "Log file not found for USB history"}
        
        usb_logs = subprocess.check_output(log_cmd, shell=True, text=True).strip()
        history["usb_history"] = usb_logs.split('\n') if usb_logs else ["No recent USB history"]
    except subprocess.CalledProcessError:
        return {"error": "Failed to retrieve device history"}
    
    return history

def collect_inventory():
    inventory = {
        "timestamp": datetime.now().isoformat(),
        "installed_apps": get_installed_apps(),
        "listening_services": get_listening_services(),
        "running_processes": get_running_processes(),
        "all_users": get_all_users(),
        "active_users": get_active_users(),
        "active_user_processes": get_active_user_processes(),
        "sudoers": check_sudoers(),
        "device_history": get_device_history(),
    }
    
    with open("device_inventory.json", "w") as f:
        json.dump(inventory, f, indent=4)
    
    print(json.dumps(inventory, indent=4))
    
    
    print(f"Inventory saved to {os.path.dirname(os.path.realpath(__file__))}/device_inventory.json")
    return inventory

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Please run this script as root")
        os._exit(1)
    collect_inventory()