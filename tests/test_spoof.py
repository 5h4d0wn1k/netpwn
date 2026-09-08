import unittest

from netpwn import spoof, safety
from netpwn.fixtures import IP_SPOOFED_ICMP


class TestIPSpoof(unittest.TestCase):
    def test_build_forged_src(self):
        pkt = spoof.build_ip_spoofed_icmp(src_ip="192.0.2.255",
                                          dst_ip="127.0.0.1")
        # src IP is at offset 26-30 (Ethernet 14 + IP 12)
        import socket
        self.assertEqual(socket.inet_ntoa(pkt[26:30]), "192.0.2.255")

    def test_length(self):
        pkt = spoof.build_ip_spoofed_icmp()
        self.assertEqual(len(pkt), 42)

    def test_fixture_forged_src(self):
        import socket
        self.assertEqual(socket.inet_ntoa(IP_SPOOFED_ICMP[26:30]), "192.0.2.255")

    def test_dst_is_loopback(self):
        import socket
        pkt = spoof.build_ip_spoofed_icmp(dst_ip="127.0.0.1")
        self.assertEqual(socket.inet_ntoa(pkt[30:34]), "127.0.0.1")

    def test_icmp_type_echo(self):
        pkt = spoof.build_ip_spoofed_icmp()
        self.assertEqual(pkt[34], 8)  # ICMP echo request type

    def test_ip_checksum_valid(self):
        import struct
        pkt = spoof.build_ip_spoofed_icmp()
        ip = pkt[14:34]
        s = 0
        for i in range(0, 20, 2):
            s += (ip[i] << 8) | ip[i + 1]
        while s >> 16:
            s = (s & 0xFFFF) + (s >> 16)
        self.assertEqual((~s) & 0xFFFF, 0)


class TestMACChange(unittest.TestCase):
    def test_dry_run(self):
        r = spoof.simulate_mac_change(iface="lo", dry_run=True)
        self.assertEqual(r["mode"], "dry-run")

    def test_live_requires_gates(self):
        with self.assertRaises(safety.LiveActionBlocked):
            spoof.simulate_mac_change(iface="lo", dry_run=False,
                                      yes=False, allowlist={"lo"})


class TestReverseDNS(unittest.TestCase):
    def test_loopback(self):
        r = spoof.reverse_dns_sim("127.0.0.1")
        self.assertTrue(r["found"])

    def test_docnet_not_found_or_safe(self):
        # Should not crash; returns a dict regardless
        r = spoof.reverse_dns_sim("192.0.2.1")
        self.assertIn("hostname", r)


class TestICMPSweep(unittest.TestCase):
    def test_sweep_count(self):
        results = spoof.icmp_sweep_sim("192.0.2.0/24", count=5)
        self.assertEqual(len(results), 5)

    def test_sweep_lengths(self):
        results = spoof.icmp_sweep_sim("198.51.100.0/24", count=3)
        self.assertTrue(all(r["packet_len"] == 42 for r in results))

    def test_sweep_targets(self):
        results = spoof.icmp_sweep_sim("203.0.113.0/24", count=2)
        self.assertEqual(results[0]["target"], "203.0.113.1")


if __name__ == "__main__":
    unittest.main()
