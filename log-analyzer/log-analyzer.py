"""
Log Analyzer
Parses web server / auth logs and detects suspicious activity.
"""

import re
import json
from collections import defaultdict
from datetime import datetime

# ——— Regex patterns ———————————————————————————————————————

APACHE_PATTERN = re.compile(
    r'(?P<ip>\d+\.\d+\.\d+\.\d+) - - \[(?P<time>[^\]]+)\] '
    r'"(?P<method>\w+) (?P<path>[^\s]+) [^"]+" '
    r'(?P<status>\d{3}) (?P<size>\d+|-)'
)

SSH_FAILED_PATTERN = re.compile(
    r'(?P<time>\w+\s+\d+\s+[\d:]+).*Failed password for (?:invalid user )?'
    r'(?P<user>\w+) from (?P<ip>\d+\.\d+\.\d+\.\d+)'
)

BRUTE_FORCE_THRESHOLD = 10   # failed attempts per IP berfore flagging

# ——— Parsers ————————————————————————————————————————————————

def parse_apache_log(lines):
    """Parse Apache/Nginx access log lines."""
    entries = []
    for line in lines:
        m = APACHE_PATTERN.match(line.strip())
        if m:
            entries.append(m.groupdict())
    return entries

def parse_ssh_log(lines):
    """Parse SSH auth log lines for failed logins."""
    entries = []
    for line in lines:
        m = SSH_FAILED_PATTERN.search(line)
        if m:
            entries.append(m.groupdict())
    return entries

# ——— Analysis ———————————————————————————————————————————————

def analyze_apache(entries):
    """Analyze parsed Apache entries and return threat summary."""
    ip_counts      = defaultdict(int)
    status_counts  = defaultdict(int)
    path_counts    = defaultdict(int)
    suspicious_ips = []
    suspicious_paths = ["/admin", "/wp-admin", "/phpmyadmin",
                        "/.env", "/etc/passwd", "../", "eval(", "<script"]

    flagged = []

    for e in entries:
        ip_counts[e["ip"]] += 1
        status_counts[e["status"]] += 1
        path_counts[e["path"]] += 1

        # Flag suspicious paths
        for s in suspicious_paths:
            if s in e["path"]:
                flagged.append({
                    "type": "Suspicious Path",
                    "ip": e["ip"],
                    "path": e["path"],
                    "time": e["time"]
                })
                break

    # Flag IPs with too many requests (possible scraper/attacker)
    for ip, count in ip_counts.items():
        if count > BRUTE_FORCE_THRESHOLD:
                suspicious_ips.append({"ip": ip, "requests": count})

    return {
        "total_requests": len(entries),
        "unique_ips": len(ip_counts),
        "status_breakdown": dict(status_counts),
        "top_ips": sorted(ip_counts.items(), key=lambda x: -x[1])[:10],
        "top_paths": sorted(path_counts.items(), key=lambda x: -x[1])[:10],
        "high_volume_ips": suspicious_ips,
        "flagged_requests": flagged
    }

def analyze_ssh(entries):
    """Analyze SSH failed login entries."""
    ip_counts   = defaultdict(int)
    user_counts = defaultdict(int)

    for e in entries:
        ip_counts[e["ip"]] += 1
        user_counts[e["user"]] += 1

    brute_force_ips = [
        {"ip": ip, "attempts": count}
        for ip, count in ip_counts.items()
        if count >= BRUTE_FORCE_THRESHOLD  
    ]

    return {
        "total_failed_logins": len(entries),
        "unique_ips": len(ip_counts),
        "brute_force_suspects": brute_force_ips,
        "targeted_usernames": sorted(user_counts.items(), key=lambda x: -x[1])[:10]
    }

# ——— Main entry point ———————————————————————————————————————————————

def analyze_file(filepath, log_type="apache"):
    """
    Analyze a log file.
    log_type: 'apache" or 'ssh'
    Returns analyses dict.
    """
    try:
        with open(filepath, "r", errors="ignore") as f:
            lines = f.readlines()
    except FileNotFoundError:
        return {"error": f"File not found: {filepath}"}

    if log_type == "apache":
        entries = parse_apache_log(lines)
        return analyze_apache(entries)
    elif log_type == "ssh":
        entries = parse_ssh_log(lines)
        return analyze_ssh(entries)
    else:
        return {"error": f"Unknown log type: {log_type}"}



def demo():
    """Generate a quick demo with sample log lines."""
    sample_apache = [
        '192.168.1.1 - - [28/Jun/2026:10:00:00 +0000] "GET /index.html HTTP/1.1" 200 1234',
        '10.0.0.5 - - [28/Jun/2026:10:00:01 +0000] "GET /wp-admin HTTP/1.1" 404 512',
        '10.0.0.5 - - [28/Jun/2026:10:00:02 +0000] "GET /.env HTTP/1.1" 403 256',
    ] * 6  # repeat to trigger high-volume detection

    entries = parse_apache_log(sample_apache)
    result = analyze_apache(entries)
    print(json.dumps(result, indent=2))

if __name__ == "__main__":
    import sys
    if len(sys.argv) == 3:
        print(json.dumps(analyze_file(sys.argv[1], sys.argv[2]), indent=2))
    else:
        print("Demo mode (no file provided):")
        demo()