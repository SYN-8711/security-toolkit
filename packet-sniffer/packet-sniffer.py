"""
Packet Sniffer
Captures and analyzes network packets using raw sockets.
Note: Requires root/admin privileges to run.
"""

import socket
import struct
import textwrap
import json
from datetime import datetime

# —— Ethernet frame decoder ————————————————————————————————

def parse_ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack("! 6s 6s H", data[:14])
    return (
        format_mac(dest_mac),
        format_mac(src_mac),
        socket.htons(proto),
        data[14:]
    )

def format_mac(mac_bytes):
    return ":".join(f"{b:02x}" for b in mac_bytes)

# —— IPv4 packet decoder ————————————————————————————————————

def parse_ipv4_packet(data):
    version_header_len = data[0]
    header_len = (version_header_len & 15) * 4
    ttl, proto, src, target = struct.unpack("! 8x B B 2x 4s 4s", data[:20])
    return (
        ttl,
        proto,
        format_ipv4(src),
        format_ipv4(target),
        data[header_len:]
    )

def format_ipv4(addr):
    return ".".join(map(str, addr))

# —— TCP / UDP / ICMP decoders ———————————————————————————————

def parse_tcp_segment(data):
    src_port, dest_port, seq, ack, offset_reserved_flags = struct.unpack(
        "! H H L L H", data[:14]
    )
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8)  >> 3
    flag_rst = (offset_reserved_flags & 4)  >> 2
    flag_syn = (offset_reserved_flags & 2)  >> 1
    flag_fin = offset_reserved_flags & 1
    return {
        "src_port": src_port, "dest_port": dest_port,
        "seq": seq, "ack": ack,
        "flags": {
            "URG": flag_urg, "ACK": flag_ack, "PSH": flag_psh,
            "RST": flag_rst, "SYN": flag_syn, "FIN": flag_fin
        },
        "payload": data[offset:]
    }

def parse_udp_segment(data):
    src_port, dest_port, size = struct.unpack("! H H 2x H", data[:8])
    return {"src_port": src_port, "dest_port": dest_port,
            "size": size, "payload": data[8:]}

def parse_icmp_packet(data):
    icmp_type, code, checksum = struct.unpack("! B B H", data[:4])
    return {"type": icmp_type, "code": code,
            "checksum": checksum, "payload": data[4:]}

# —— Main sniffer ————————————————————————————————————————————

def sniff(packet_count=20, output_file=None, verbose=False):
    """
    Capture `packet_count` packets.
    Returns a list of packet summary dicts.
    Saves to output_file (JSON) if provided.
    """
    captured = []

    try:
        conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                            socket.ntohs(3))
    except PermissionError:
        return {"error": "Root privileges required. Run with sudo."}
    except OSError:
        return {"error": "AF_PACKET not supported on this OS (Linux only)."}

    print(f"[*] Sniffing {packet_count} packets... (Ctrl+C to stop)")

    try:
        for i in range(packet_count):
            raw_data, addr = conn.recvfrom(65535)
            timestamp = str(datetime.now())

            dest_mac, src_mac, eth_proto, payload = parse_ethernet_frame(raw_data)
            pkt = {
                "id": i + 1,
                "timestamp": timestamp,
                "eth": {"dest_mac": dest_mac, "src_mac": src_mac, "proto": eth_proto}
            }

            # IPv4
            if eth_proto == 8:
                ttl, proto, src_ip, dest_ip, ip_payload = parse_ipv4_packet(payload)
                pkt["ipv4"] = {"src": src_ip, "dest": dest_ip, "ttl": ttl, "proto": proto}

                if proto == 6:        #TCP
                    tcp = parse_tcp_segment(ip_payload)
                    pkt["tcp"] = {k: v for k, v in tcp.items() if k != "payload"}
                    pkt["protocol"] = "TCP"
                elif proto == 17:     #UDP
                    udp = parse_udp_segment(ip_payload)
                    pkt["udp"] = {k: v for k, v in udp.items() if k != "payload"}
                    pkt["protocol"] = "UDP"
                elif proto == 1:
                    icmp = parse_icmp_packet(ip_payload)
                    pkt["icmp"] = {k: v for k, v in icmp.items() if k != "payload"}
                    pkt["protocol"] = "ICMP"
                else:
                    pkt["protocol"] = f"Other({proto})"
            else:
                pkt["protocol"] = f"Non-IPv4(eth_proto={eth_proto})"

            captured.append(pkt)
            if verbose:
                print(f"[{i+1}] {pkt.get('protocol','?')} | "
                      f"{pkt.get('ipv4', {}).get('src','?')} → "
                      f"{pkt.get('ipv4', {}).get('dest','?')}")

    except KeyboardInterrupt:
        print("\n[-] Stopped by user.")
    finally:
        conn.close()

    if output_file:
        with open(output_file, "w") as f:
            json.dump(captured, f, indent=2)
        print(f"[+] Saved {len(captured)} packets to {output_file}")

    return captured


if __name__ == "__main__":
    import sys
    count = int(sys.argv[1] if len(sys.argv) > 1 else 10)
    results = sniff(packet_count=count, verbose=True)
    if isinstance(results, dict) and "error" in results:
        print(f"[!] {results['error']}")
    else:
        print(f"\n[+] Captured {len(results)} packets.")
    
    
