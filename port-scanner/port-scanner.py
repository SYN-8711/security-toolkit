"""
Port Scanner - Advanced
Scans common or custom port ranges using threading for speed.
"""
import socket
import json
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 3306: "MySQL", 
    3389: "RDP", 5432: "PostgreSQL", 6379: "Redis",
    8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 27017: "MongoDB"
}

def grab_banner(ip, port, timeout=1.0):
    """Try to grab service banner for more info."""
    try:
        s = socket.socket()
        s.settimeout(timeout)
        s.connect((ip, port))
        s.send(b"HEAD / HTTP/1.0\r\n\r\n")
        banner = s.recv(1024).decode(errors="ignore").strip()
        s.close()
        return banner.split("\n")[0] if banner else ""
    except:
        return ""

def scan_single_port(ip, port, service, timeout=1.0):
    """Scan a single port and return result dict."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    result = s.connect_ex((ip, port))
    s.close()
    if result == 0:
        banner = grab_banner(ip, port, timeout)
        return {
            "port": port,
            "service": service,
            "status": "open",
            "banner": banner
        }
    return None

def run_scan(target_host, port_range=None, timeout=1.0):
    """
    Main scan function. Returns a results dict.
    port_range: list of ports, or None to use COMMON_PORTS.
    """
    try:
        target_ip = socket.gethostbyname(target_host)
    except socket.gaierror:
        return {"error": f"Cannot resolve hostname: {target_host}"}

    ports_to_scan = {}
    if port_range:
        for p in port_range:
            ports_to_scan[p] = COMMON_PORTS.get(p, "Unknown")
    else:
        ports_to_scan = COMMON_PORTS

    open_ports = []
    start_time = datetime.now()

    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = {
            executor.submit(scan_single_port, target_ip, port, svc, timeout): port
            for port, svc in ports_to_scan.items()
        }
        for future in as_completed(futures):
            result = future.result()
            if result:
                open_ports.append(result)

    open_ports.sort(key=lambda x: x["port"])
    elapsed = (datetime.now() - start_time).total_seconds()

    return {
        "target": target_host,
        "ip": target_ip,
        "scan_time": str(start_time),
        "elapsed_seconds": round(elapsed, 2),
        "open_ports": open_ports,
        "total_scanned": len(ports_to_scan)
    }


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "localhost"
    results = run_scan(target)
    print(json.dumps(results, indent=2))
