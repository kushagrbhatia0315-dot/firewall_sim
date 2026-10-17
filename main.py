import datetime
import random
import time
from typing import Dict, Set

LOG_FILE = "firewall.log"


class Firewall:
    def __init__(self, log_filepath: str = LOG_FILE):
        self.log_filepath = log_filepath

        # Default rules
        self.blocked_ips: Set[str] = {
            "192.168.1.100",
            "10.0.0.66",
            "45.33.32.156",
            "203.0.113.19",
        }
        self.blocked_ports: Set[int] = {21, 23, 445, 3389}  # FTP, Telnet, SMB, RDP
        self.allowed_ports: Set[int] = {80, 443, 22, 53, 8080}  # HTTP, HTTPS, SSH, DNS, Dev
        self.blocked_protocols: Set[str] = {"ICMP"}  # Blocks ICMP / ping flood packets

        # Write session header to log file
        with open(self.log_filepath, "a", encoding="utf-8") as f:
            f.write(f"\n--- Firewall Session Initialized: {datetime.datetime.now().isoformat()} ---\n")

    def inspect_packet(self, packet: Dict[str, any]) -> Dict[str, any]:
        """
        Evaluates a packet sequentially against firewall filtering rules.
        Returns a dict: {"action": "ALLOWED" | "BLOCKED", "reason": str}
        """
        ip = packet["source_ip"]
        port = packet["dest_port"]
        protocol = packet["protocol"].upper()

        # Rule 1: Check IP blacklist
        if ip in self.blocked_ips:
            return {"action": "BLOCKED", "reason": f"Source IP {ip} is blacklisted"}

        # Rule 2: Check protocol blocklist
        if protocol in self.blocked_protocols:
            return {"action": "BLOCKED", "reason": f"Protocol {protocol} is restricted"}

        # Rule 3: Check port blacklist
        if port in self.blocked_ports:
            return {"action": "BLOCKED", "reason": f"Destination port {port} is explicitly blocked"}

        # Rule 4: Check port whitelist policy
        if self.allowed_ports and port not in self.allowed_ports:
            return {"action": "BLOCKED", "reason": f"Port {port} is not in allowed services list"}

        # Default disposition
        return {"action": "ALLOWED", "reason": "Passed all rule inspections"}

    def log_verdict(self, packet: Dict[str, any], verdict: Dict[str, any]):
        """Logs verdict to console with ANSI colors and appends to persistent log file."""
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ip = packet["source_ip"]
        port = packet["dest_port"]
        protocol = packet["protocol"].upper()
        action = verdict["action"]
        reason = verdict["reason"]

        log_line = (
            f"[{timestamp}] {action:<7} | Proto: {protocol:<4} | "
            f"Src: {ip:<15} | Port: {port:<5} | Reason: {reason}"
        )

        # ANSI terminal colors (Green = ALLOWED, Red = BLOCKED)
        color = "\033[92m" if action == "ALLOWED" else "\033[91m"
        reset = "\033[0m"
        print(f"{color}{log_line}{reset}")

        # Persistent log file storage
        with open(self.log_filepath, "a", encoding="utf-8") as f:
            f.write(log_line + "\n")


def simulate_network_traffic(firewall: Firewall, packet_count: int = 15):
    """Generates synthetic network packets to demonstrate automated filtering."""
    sample_ips = [
        "192.168.1.50", "192.168.1.100", "10.0.0.12",
        "10.0.0.66", "172.16.0.4", "45.33.32.156", "192.168.1.10"
    ]
    sample_ports = [80, 443, 22, 21, 23, 53, 3389, 445, 9000]
    sample_protocols = ["TCP", "UDP", "ICMP"]

    print(f"\n--- Simulating Stream of {packet_count} Network Packets ---")
    for _ in range(packet_count):
        pkt = {
            "source_ip": random.choice(sample_ips),
            "dest_port": random.choice(sample_ports),
            "protocol": random.choice(sample_protocols),
        }
        verdict = firewall.inspect_packet(pkt)
        firewall.log_verdict(pkt, verdict)
        time.sleep(0.12)


def manual_packet_inspection(firewall: Firewall):
    """Allows manual user input of packet headers to test edge cases."""
    print("\n--- Test Custom Packet Headers ---")
    ip = input("Source IP (e.g., 192.168.1.100): ").strip() or "192.168.1.1"
    try:
        port = int(input("Destination Port (e.g., 80, 22, 23, 445): ").strip())
    except ValueError:
        print("Invalid port number. Aborting test.")
        return
    protocol = input("Protocol (TCP/UDP/ICMP): ").strip().upper() or "TCP"

    pkt = {"source_ip": ip, "dest_port": port, "protocol": protocol}
    verdict = firewall.inspect_packet(pkt)
    print("\nEvaluation Verdict:")
    firewall.log_verdict(pkt, verdict)


def view_audit_log():
    """Displays recent records from the persistent log file."""
    print(f"\n--- Recent Log Entries ({LOG_FILE}) ---")
    try:
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            lines = f.readlines()
            if not lines:
                print("Log file is empty.")
                return
            for line in lines[-25:]:
                print(line.strip())
    except FileNotFoundError:
        print("No log file found. Run a simulation or packet test first.")


def main():
    fw = Firewall()

    while True:
        print("\n=== NETWORK FIREWALL SIMULATOR ===")
        print("1. Run Traffic Simulation")
        print("2. Test a Custom Packet")
        print("3. View Active Rules & Policies")
        print("4. Add IP to Blocklist")
        print("5. View Audit Log File")
        print("6. Exit")

        choice = input("Select an option (1-6): ").strip()
        if choice == "1":
            simulate_network_traffic(fw)
        elif choice == "2":
            manual_packet_inspection(fw)
        elif choice == "3":
            print("\nActive Firewall Rules:")
            print(f"  • Blocked IPs       : {sorted(list(fw.blocked_ips))}")
            print(f"  • Blocked Ports     : {sorted(list(fw.blocked_ports))}")
            print(f"  • Allowed Ports     : {sorted(list(fw.allowed_ports))}")
            print(f"  • Blocked Protocols : {sorted(list(fw.blocked_protocols))}")
        elif choice == "4":
            new_ip = input("Enter IP address to block: ").strip()
            if new_ip:
                fw.blocked_ips.add(new_ip)
                print(f"✓ Added {new_ip} to blocked IPs list.")
        elif choice == "5":
            view_audit_log()
        elif choice == "6":
            print("Firewall daemon terminated.")
            break
        else:
            print("Invalid selection. Please choose 1-6.")


if __name__ == "__main__":
    main()
