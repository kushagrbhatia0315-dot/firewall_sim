import unittest
from main import Firewall


class TestFirewallRules(unittest.TestCase):

    def setUp(self):
        self.fw = Firewall(log_filepath="test_firewall.log")

    def test_block_blacklisted_ip(self):
        pkt = {"source_ip": "192.168.1.100", "dest_port": 80, "protocol": "TCP"}
        verdict = self.fw.inspect_packet(pkt)
        self.assertEqual(verdict["action"], "BLOCKED")
        self.assertIn("blacklisted", verdict["reason"])

    def test_block_restricted_protocol(self):
        pkt = {"source_ip": "192.168.1.50", "dest_port": 80, "protocol": "ICMP"}
        verdict = self.fw.inspect_packet(pkt)
        self.assertEqual(verdict["action"], "BLOCKED")
        self.assertIn("Protocol ICMP is restricted", verdict["reason"])

    def test_block_forbidden_port(self):
        pkt = {"source_ip": "192.168.1.50", "dest_port": 23, "protocol": "TCP"}
        verdict = self.fw.inspect_packet(pkt)
        self.assertEqual(verdict["action"], "BLOCKED")
        self.assertIn("explicitly blocked", verdict["reason"])

    def test_allow_legitimate_traffic(self):
        pkt = {"source_ip": "192.168.1.50", "dest_port": 443, "protocol": "TCP"}
        verdict = self.fw.inspect_packet(pkt)
        self.assertEqual(verdict["action"], "ALLOWED")


if __name__ == "__main__":
    unittest.main()
