# Network Firewall Simulator (CLI)

A rule-based packet filtering firewall simulator built in Python with zero third-party dependencies. It models layer 3 and layer 4 network packet inspection, evaluates policies sequentially, and maintains an audit log of allowed and dropped network traffic[cite: 8].

---

## Features

- **IP Blacklisting:** Evaluates incoming source IP addresses against a blacklist and drops malicious/untrusted hosts[cite: 8].
- **Port Filtering:** Supports explicit blacklisting of high-risk ports (e.g., Telnet: 23, SMB: 445, FTP: 21) as well as whitelist enforcement for standard allowed services (e.g., HTTP: 80, HTTPS: 443, SSH: 22, DNS: 53)[cite: 8].
- **Protocol Filtering:** Drops restricted traffic types such as ICMP to mitigate ping sweeps and reconnaissance attacks[cite: 8].
- **Persistent Logging:** Writes every packet inspection event with timestamps, network coordinates, verdict (`ALLOWED` / `BLOCKED`), and triggered policy rule to `firewall.log`[cite: 8].
- **Traffic Simulator:** Generates continuous synthetic network packets to demo real-time color-coded packet classification[cite: 8].
- **Manual Packet Testing:** Interactive CLI mode to test arbitrary IP/Port/Protocol combinations against active policies.

---

## File Structure

```text
firewall-simulator/
├── main.py          # Complete firewall engine, rules, and CLI interface
├── firewall.log     # Generated audit trail of all inspected packets
├── .gitignore       # Ignores runtime cache and build files
└── README.md        # Documentation and usage guide
