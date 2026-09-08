import unittest

from netpwn import arp, safety
from netpwn.fixtures import (
    ARP_REQUEST, ARP_REPLY, ARP_GRATUITOUS,
)


class TestARPBuildParse(unittest.TestCase):
    def test_build_parse_roundtrip_request(self):
        pkt = arp.build_arp(1, "00:11:22:33:44:55", "192.0.2.1",
                            target_mac="aa:bb:cc:dd:ee:ff", target_ip="192.0.2.2")
        parsed = arp.parse_arp(pkt)
        self.assertEqual(parsed["opcode"], 1)
        self.assertEqual(parsed["sender_mac"], "00:11:22:33:44:55")
        self.assertEqual(parsed["sender_ip"], "192.0.2.1")
        self.assertEqual(parsed["target_ip"], "192.0.2.2")

    def test_build_parse_roundtrip_reply(self):
        pkt = arp.build_arp(2, "aa:bb:cc:dd:ee:ff", "192.0.2.10",
                            target_mac="00:11:22:33:44:55", target_ip="192.0.2.1")
        parsed = arp.parse_arp(pkt)
        self.assertEqual(parsed["opcode"], 2)
        self.assertEqual(parsed["sender_mac"], "aa:bb:cc:dd:ee:ff")
        self.assertEqual(parsed["target_ip"], "192.0.2.1")

    def test_fixture_request_byte_exact(self):
        parsed = arp.parse_arp(ARP_REQUEST)
        self.assertEqual(parsed["sender_ip"], "192.0.2.10")
        self.assertEqual(parsed["target_ip"], "192.0.2.1")
        self.assertEqual(parsed["opcode"], 1)

    def test_fixture_reply_byte_exact(self):
        parsed = arp.parse_arp(ARP_REPLY)
        self.assertEqual(parsed["opcode"], 2)
        self.assertEqual(parsed["sender_ip"], "192.0.2.1")
        self.assertEqual(parsed["sender_mac"], "aa:bb:cc:dd:ee:ff")

    def test_fixture_gratuitous(self):
        parsed = arp.parse_arp(ARP_GRATUITOUS)
        self.assertEqual(parsed["target_ip"], parsed["sender_ip"])

    def test_gratuitous_builder(self):
        g = arp.gratuitous_arp("aa:bb:cc:dd:ee:ff", "192.0.2.1")
        parsed = arp.parse_arp(g)
        self.assertEqual(parsed["target_ip"], "192.0.2.1")
        self.assertEqual(parsed["sender_ip"], "192.0.2.1")
        self.assertEqual(parsed["target_mac"], "aa:bb:cc:dd:ee:ff")

    def test_frame_length(self):
        pkt = arp.build_arp(1, "00:11:22:33:44:55", "192.0.2.1")
        self.assertEqual(len(pkt), 42)  # 14 ETH + 28 ARP

    def test_rejects_short_frame(self):
        with self.assertRaises(ValueError):
            arp.parse_arp(b"\x00" * 10)

    def test_rejects_non_arp(self):
        frame = b"\x00" * 14
        frame = frame[:12] + b"\x08\x00" + frame[14:]
        with self.assertRaises(ValueError):
            arp.parse_arp(frame + b"\x00" * 30)


class TestARPReplayDemo(unittest.TestCase):
    def test_spoof_dry_run(self):
        r = arp.spoof_demo(dry_run=True)
        self.assertEqual(r["mode"], "dry-run")
        self.assertIn("spoof_packet", r)
        self.assertIn("restore_packet", r)
        # verify both packets are valid ARP
        arp.parse_arp(r["spoof_packet"])
        arp.parse_arp(r["restore_packet"])

    def test_spoof_live_requires_gates(self):
        with self.assertRaises(safety.LiveActionBlocked):
            arp.spoof_demo(iface="eth0", dry_run=False, yes=False, allowlist={"lo"})
        with self.assertRaises(safety.LiveActionBlocked):
            arp.spoof_demo(iface="eth0", dry_run=False, yes=True, allowlist={"lo"})

    def test_spoof_live_blocked_by_allowlist(self):
        with self.assertRaises(safety.LiveActionBlocked):
            arp.spoof_demo(iface="eth123", dry_run=False, yes=True,
                           allowlist={"lo", "192.0.2.0/24"})

    def test_cache_harness_dry_run(self):
        r = arp.arp_cache_harness(dry_run=True)
        self.assertTrue(r["roundtrip_ok"])


class TestSafety(unittest.TestCase):
    def test_require_live_gate_dry_run(self):
        with self.assertRaises(safety.LiveActionBlocked):
            safety.require_live_gate("eth0", True, {"lo"}, dry_run=True)

    def test_require_live_gate_no_iface(self):
        with self.assertRaises(safety.LiveActionBlocked):
            safety.require_live_gate(None, True, {"lo"}, dry_run=False)

    def test_require_live_gate_no_yes(self):
        with self.assertRaises(safety.LiveActionBlocked):
            safety.require_live_gate("eth0", False, {"lo"}, dry_run=False)

    def test_require_live_gate_no_allowlist(self):
        with self.assertRaises(safety.LiveActionBlocked):
            safety.require_live_gate("eth0", True, set(), dry_run=False)

    def test_require_live_gate_not_allowed(self):
        with self.assertRaises(safety.LiveActionBlocked):
            safety.require_live_gate("eth9", True, {"lo"}, dry_run=False)

    def test_require_live_gate_allows_cidr(self):
        # permit by CIDR
        iface = safety.require_live_gate("192.0.2.44", True,
                                         {"192.0.2.0/24"}, dry_run=False)
        self.assertEqual(iface, "192.0.2.44")

    def test_require_live_gate_ok(self):
        iface = safety.require_live_gate("lo", True, {"lo"}, dry_run=False)
        self.assertEqual(iface, "lo")

    def test_mac_bytes(self):
        self.assertEqual(safety.mac_bytes("aa:bb:cc:dd:ee:ff"),
                         bytes.fromhex("aabbccddeeff"))

    def test_mac_str(self):
        self.assertEqual(safety.mac_str(bytes.fromhex("aabbccddeeff")),
                         "aa:bb:cc:dd:ee:ff")

    def test_random_mac_deterministic(self):
        self.assertEqual(safety.random_mac(1), safety.random_mac(1))
        self.assertNotEqual(safety.random_mac(1), safety.random_mac(2))

    def test_random_mac_locally_administered(self):
        mac = safety.random_mac(5)
        first = int(mac.split(":")[0], 16)
        self.assertEqual(first & 0x02, 0x02)  # locally administered


if __name__ == "__main__":
    unittest.main()
