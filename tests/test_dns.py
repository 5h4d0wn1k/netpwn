import unittest

from netpwn import dns
from netpwn.fixtures import (
    DNS_QUERY_A, DNS_RESPONSE_A, DNS_RESPONSE_MISMATCH, DNS_RESPONSE_REBIND,
)


class TestDNSBuildParse(unittest.TestCase):
    def test_build_query_roundtrip(self):
        q = dns.build_dns_query("www.example.com", tx_id=0xABCD)
        p = dns.parse_dns(q)
        self.assertEqual(p["tx_id"], 0xABCD)
        self.assertEqual(p["questions"][0]["name"], "www.example.com")
        self.assertEqual(p["questions"][0]["type"], 1)

    def test_fixture_query_hex_matches(self):
        q = dns.build_dns_query("www.google.com", tx_id=0xABCD)
        self.assertEqual(q, DNS_QUERY_A)

    def test_fixture_query_parse(self):
        p = dns.parse_dns(DNS_QUERY_A)
        self.assertEqual(p["questions"][0]["name"], "www.google.com")

    def test_fixture_response_parse(self):
        p = dns.parse_dns(DNS_RESPONSE_A)
        self.assertEqual(p["answers"][0]["rdata"], "142.250.46.17")
        self.assertTrue(p["is_response"])

    def test_tx_id_preserved(self):
        for pkt in (DNS_QUERY_A, DNS_RESPONSE_A):
            p = dns.parse_dns(pkt)
            self.assertEqual(p["tx_id"], 0xABCD)

    def test_rejects_short(self):
        with self.assertRaises(ValueError):
            dns.parse_dns(b"\x00" * 5)

    def test_build_response(self):
        import socket
        r = dns.build_dns_response("www.example.com",
                                   [("192.0.2.1", 60, 4, socket.inet_aton("192.0.2.1"))],
                                   tx_id=0xBEEF)
        p = dns.parse_dns(r)
        self.assertEqual(p["tx_id"], 0xBEEF)
        self.assertTrue(p["is_response"])
        self.assertEqual(p["answers"][0]["rdata"], "192.0.2.1")


class TestDNSSpoofDetection(unittest.TestCase):
    def test_exact_replay_valid(self):
        results = dns.detect_dns_spoof(0xABCD, [DNS_RESPONSE_A])
        self.assertTrue(results[0]["valid"])

    def test_id_mismatch_flagged(self):
        results = dns.detect_dns_spoof(0xABCD,
                                       [DNS_RESPONSE_A, DNS_RESPONSE_MISMATCH])
        self.assertTrue(results[0]["valid"])
        self.assertFalse(results[1]["valid"])
        self.assertIn("mismatch", results[1]["reason"].lower())

    def test_two_legit_responses(self):
        results = dns.detect_dns_spoof(0xABCD, [DNS_RESPONSE_A, DNS_RESPONSE_A])
        self.assertTrue(all(r["valid"] for r in results))


class TestDNSRebinding(unittest.TestCase):
    def test_rebind_detected(self):
        r = dns.rebinding_demo()
        self.assertTrue(r["rebound"])
        self.assertNotEqual(r["first_ip"], r["second_ip"])
        self.assertEqual(r["tx_id"], 0xABCD)

    def test_rebind_fixture(self):
        p1 = dns.parse_dns(DNS_RESPONSE_A)
        p2 = dns.parse_dns(DNS_RESPONSE_REBIND)
        self.assertEqual(p1["tx_id"], p2["tx_id"])
        self.assertNotEqual(p1["answers"][0]["rdata"],
                            p2["answers"][0]["rdata"])


if __name__ == "__main__":
    unittest.main()
