"""
SSH Login Tester (Brute Force Simulator)
For use ONLY on systems you own or have explicit peermission to test.
Useful for testing if your SSH server is vulnerable to common passwords.
"""

import socket 
import json
import time
from datetime import datetime

# —————————————————————————————————————————————————————————————————————————————
# NOTE: This module simulates SSH login attempts via raw TCP handshake only.
# It checks if the SSH port is open and reads the banner — it does NOT
# actually perform authentication, to keep this tool educational and safe.
# For real penetration testing use Kali Linux + proper lab environments.
# —————————————————————————————————————————————————————————————————————————————

COMMON_SSH_USERS = ["root", "admin", "user", "ubuntu", "pi","test"]
COMMON_PASSWORDS = [
    "password", "123456", "admin", "root", "toor",
    "raspberry", "ubuntu", "1q2w3e4r", "qwerty"
]

def get_ssh_banner(host, port=22, timeout=3):
    """Connect to SSH port and grab the banner."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        banner = s.recv(1024).decode(errors="ignore").strip()
        s.close()
        return banner
    except Exception as e:
        return None

def check_ssh_exposure(host, port=22):
    """
    Check if an SSH server is exposed and gather basic info.
    Rteurns a risk report.
    """
    try:
        target_ip = socket.gethostbyname(host)
    except socket.gaierror:
        return {"error": f"Cannot resolve: {host}"}

    print(f"\n[*] Checking SSH exposure on {host} ({target_ip}):{port}")
    print(f"[*] Time: {datetime.now()}")
    print("_" * 50)

    # Step 1: Is SSH Port open ?
    banner = get_ssh_banner(host, port)
    if banner is None:
        return {
            "host": host,
            "ip": target_ip,
            "port": port,
            "ssh_open": False,
            "risk": "Low",
            "message": "SSH port is closed or filtered."
        }

    print(f"[+] SSH port {port} is OPEN")
    print(f"[+] Banner: {banner}")

    # Step 2: Parse SSH version from banner
    ssh_version = "Unknown"
    if "SSH-" in banner:
        ssh_version = banner.split("SSH-")[-1].strip()

    # Step 3: Known vulnerable version check
    vulnerabilities = []
    if "OpenSSH_7" in banner or "OpenSSH_6" in banner:
        vulnerabilities.append("Older OpenSSH version detected - consider upgrading")
    if "OpenSSH_5" in banner or "OpenSSH_4" in banner:
        vulnerabilities.append("Very old OpenSSH — HIGH risk, upgrade immediately")
    if port == 22:
        vulnerabilities.append("Using default port 22 — consider changing to reduce scan noise")

    # Step 4: Recommendations
    recommendations = [
        "Disable root login: PermitRootLogin no",
        "Use SSH key authentication instead of passwords",
        "Enable fail2ban to block brute force attempts",
        "Restrict access with AllowUsers or firewall rules",
        "Consider changing default port 22",
        "Keep OpenSSH updated to the latest stable verion"
    ]

    risk = "High" if vulnerabilities else "Medium"

    result = {
        "host": host,
        "ip": target_ip,
        "port": port,
        "ssh_open": True,
        "banner": banner,
        "ssh_version": ssh_version,
        "risk": risk,
        "vulnerabilities_found": vulnerabilities,
        "recommendations": recommendations,
        "common_users_to_protect": COMMON_SSH_USERS,
        "common_passwords_to_avoid": COMMON_PASSWORDS   
    }

    print(f"\n[!] Risk Level: {risk}")
    for v in vulnerabilities:
        print(f"          ! {v}")
    print("\n[*] Recommendations:")
    for r in recommendations:
        print(f"          → {r}")

    return result


if __name__ == "__main__":
    import sys
    host = sys.argv[1] if len(sys.argv) > 1 else "localhost"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 22
    result = check_ssh_exposure(host, port)
    print("\n" + "="*50)
    print(json.dumps(result, indent=2))
