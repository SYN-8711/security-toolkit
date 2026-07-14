# security-toolkit
A collection of cybersecurity tools, scripts, and automation tasks written in Python.
This repository is built for learning purposes, security research, and personal project showcase.

## Projects 
- [Password Checker](./password-checker/): A tool to evaluate password complexity and security strength.

- [Port Scanner](./port-scanner/): A multi-threaded tool to scan open ports and grab service banners.
 
   **Features:**
   - Scans 17 common ports
   - Banner grabbing
   - Fast threading
   
   **Usage:**
   ```bash
   python port-scanner.py google.com
   python port-scanner.py 192.168.1.1
   ```
- [Log Analyzer](./log-analyzer/): An intelligent tool designed to analyze server logs and detect suspicious behaviors, such as unauthorized attempts to access sensitive files or administrative panels. It helps webmasters and cybersecurity professionals quickly identify automated scanning attacks.

   **Features:**
  - Suspicious Path Detection: Detects access attempts to sensitive files like `.env` or management paths like `/wp-admin`.
  - Attacker Profiling: Extracts and logs suspicious IP addresses along with the exact timestamp of the event.
  - Structured Output: Displays logs in a clean, readable JSON format for further analysis.

   **Usage:**
   ```bash
   python log-analyzer/log-analyzer.py
   ```
   
- [SSH Tester](./ssh-tester/): A lightweight tool designed to test SSH connections, verify credentials, and check server availability.
   
   **Features:**
   - Quick port availability check
   - Automates verification of specified credentials
   - Detailed error reporting for failed attempts
   
   **Usage:**
   ```bash
   python ssh-tester/ssh-tester.py
   ```
   
- [Packet Sniffer](./packet-sniffer/): A powerful, low-level network analysis tool written in Python that captures, decodes, and inspects live network packets using raw sockets.

   **Features:**
   - **Ethernet Frame Decoding:** Unpacks Ethernet headers to extract Source/Destination MAC addresses and ethernet protocol types.
   - **IPv4 Header Parsing:** Decodes IPv4 packets to retrieve Source/Destination IPs, Time-To-Live (TTL), and protocol types.
   - **Multi-Protocol Support:** Deeply parses transport layer protocols including TCP (with flags like SYN, ACK, FIN), UDP (ports and sizes), and ICMP (type and code).
   - **Structured JSON Logging:** Saves captured packets in a highly structured, clean JSON format for further analysis and debugging.

   **Usage:**
   > ⚠️ **Note:** Packet sniffing requires raw socket access, which needs administrative (root) privileges. This tool is designed to run on Linux environments supporting `AF_PACKET`.

    ```bash
    sudo python packet-sniffer/packet_sniffer.py 10
    ```
   
