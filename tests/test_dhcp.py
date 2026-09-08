import unittest

from netpwn import dhcp, safety
from netpwn.fixtures import (
    DHCP_DISCOVER, DHCP_OFFER, DHCP_REQUEST, DHCP_ACK,
)


class TestDHCPParse(unittest.TestCase):
    def test_fixture_discover(self):
        p = dhcp.parse_dhcp(DHCP_DISCOVER)
        self.assertEqual(p["msg_type_str"], "DISCOVER")
        self.assertEqual(p["chaddr"], "00:11:22:33:44:55")
        self.assertEqual(p["xid"], 0x12345678)

    def test_fixture_offer(self):
        p = dhcp.parse_dhcp(DHCP_OFFER)
        self.assertEqual(p["msg_type_str"], "OFFER")
        self.assertEqual(p["yiaddr"], "192.0.2.100")

    def test_fixture_request(self):
        p = dhcp.parse_dhcp(DHCP_REQUEST)
        self.assertEqual(p["msg_type_str"], "REQUEST")

    def test_fixture_ack(self):
        p = dhcp.parse_dhcp(DHCP_ACK)
        self.assertEqual(p["msg_type_str"], "ACK")
        self.assertEqual(p["yiaddr"], "192.0.2.100")

    def test_all_length_300(self):
        for pkt in (DHCP_DISCOVER, DHCP_OFFER, DHCP_REQUEST, DHCP_ACK):
            self.assertEqual(len(pkt), 300)

    def test_rejects_short(self):
        with self.assertRaises(ValueError):
            dhcp.parse_dhcp(b"\x00" * 100)


class TestDHCPBuild(unittest.TestCase):
    def test_build_parse_roundtrip(self):
        pkt = dhcp.build_dhcp(xid=0xBEEF0001, chaddr="aa:bb:cc:dd:ee:ff",
                              msg_type=1)
        p = dhcp.parse_dhcp(pkt)
        self.assertEqual(p["xid"], 0xBEEF0001)
        self.assertEqual(p["chaddr"], "aa:bb:cc:dd:ee:ff")
        self.assertEqual(p["msg_type_str"], "DISCOVER")

    def test_build_length(self):
        pkt = dhcp.build_dhcp()
        self.assertEqual(len(pkt), 300)

    def test_build_msg_type(self):
        pkt = dhcp.build_dhcp(msg_type=3)
        p = dhcp.parse_dhcp(pkt)
        self.assertEqual(p["msg_type_str"], "REQUEST")

    def test_build_offer_with_options(self):
        import socket
        pkt = dhcp.build_dhcp(op=2, msg_type=2, options_extra={
            3: socket.inet_aton("192.0.2.1"),
            51: __import__("struct").pack("!I", 600),
        })
        p = dhcp.parse_dhcp(pkt)
        self.assertEqual(p["msg_type_str"], "OFFER")
        self.assertEqual(p["options"][3], socket.inet_aton("192.0.2.1"))

    def test_build_reply_scan(self):
        import socket
        for msg_type in (1, 2, 3, 5, 6, 7, 8):
            pkt = dhcp.build_dhcp(op=1, msg_type=msg_type)
            p = dhcp.parse_dhcp(pkt)
            self.assertEqual(p["msg_type"], msg_type)


class TestDHCPStarvation(unittest.TestCase):
    def test_unique_macs(self):
        results = dhcp.starvation_sim(10)
        macs = [r["mac"] for r in results]
        self.assertEqual(len(set(macs)), 10)

    def test_deterministic(self):
        r1 = dhcp.starvation_sim(5, seed=42)
        r2 = dhcp.starvation_sim(5, seed=42)
        self.assertEqual(r1, r2)

    def test_count(self):
        self.assertEqual(len(dhcp.starvation_sim(25)), 25)

    def test_each_packet_parses(self):
        for r in dhcp.starvation_sim(10):
            self.assertEqual(r["parsed_msg_type"], "DISCOVER")


class TestDHCPRogue(unittest.TestCase):
    def test_rogue_offer(self):
        r = dhcp.rogue_dhcp_demo(dry_run=True)
        self.assertEqual(r["parsed"]["msg_type_str"], "OFFER")
        self.assertEqual(r["parsed"]["yiaddr"], "192.0.2.50")


if __name__ == "__main__":
    unittest.main()
