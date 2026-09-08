import os
import tempfile
import unittest

from netpwn import sniff
from netpwn.fixtures import (
    ARP_REQUEST, ARP_REPLY, ARP_GRATUITOUS,
    DHCP_DISCOVER, DHCP_OFFER,
    DNS_QUERY_A, DNS_RESPONSE_A, DNS_RESPONSE_MISMATCH,
)


class TestPcapReader(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "test.pcap")

    def tearDown(self):
        if os.path.exists(self.path):
            os.unlink(self.path)
        os.rmdir(self.dir)

    def _write(self, packets):
        return sniff.create_pcap(packets, self.path)

    def test_read_back(self):
        self._write([ARP_REQUEST, ARP_REPLY])
        reader = sniff.PcapReader(self.path)
        pkts = list(reader)
        reader.close()
        self.assertEqual(len(pkts), 2)
        self.assertEqual(pkts[0]["data"], ARP_REQUEST)
        self.assertEqual(pkts[1]["data"], ARP_REPLY)

    def test_empty(self):
        self._write([])
        reader = sniff.PcapReader(self.path)
        pkts = list(reader)
        reader.close()
        self.assertEqual(len(pkts), 0)

    def test_captured_length(self):
        self._write([ARP_REQUEST])
        reader = sniff.PcapReader(self.path)
        pkts = list(reader)
        reader.close()
        self.assertEqual(pkts[0]["captured_len"], len(ARP_REQUEST))
        self.assertEqual(pkts[0]["original_len"], len(ARP_REQUEST))


class TestFlowExtraction(unittest.TestCase):
    def test_arp_flows(self):
        flows = sniff.extract_flows([ARP_REQUEST, ARP_REPLY, ARP_GRATUITOUS])
        self.assertEqual(len(flows["arp"]), 3)

    def test_dhcp_flows_wrapped(self):
        packets = [
            sniff.wrap_udp(DHCP_DISCOVER, 68, 67),
            sniff.wrap_udp(DHCP_OFFER, 67, 68),
        ]
        flows = sniff.extract_flows(packets)
        self.assertEqual(len(flows["dhcp"]), 2)

    def test_dns_flows_wrapped(self):
        packets = [
            sniff.wrap_udp(DNS_QUERY_A, 53000, 53),
            sniff.wrap_udp(DNS_RESPONSE_A, 53, 53000),
        ]
        flows = sniff.extract_flows(packets)
        self.assertEqual(len(flows["dns"]), 2)

    def test_wrap_udp_len(self):
        w = sniff.wrap_udp(DNS_QUERY_A, 53000, 53)
        self.assertEqual(len(w), 14 + 20 + 8 + len(DNS_QUERY_A))

    def test_mixed(self):
        packets = [
            ARP_REQUEST,
            sniff.wrap_udp(DHCP_DISCOVER, 68, 67),
            sniff.wrap_udp(DNS_RESPONSE_A, 53, 53000),
        ]
        flows = sniff.extract_flows(packets)
        self.assertEqual(len(flows["arp"]), 1)
        self.assertEqual(len(flows["dhcp"]), 1)
        self.assertEqual(len(flows["dns"]), 1)

    def test_short_packets_ignored(self):
        flows = sniff.extract_flows([b"\x00" * 5])
        self.assertEqual(sum(len(v) for v in flows.values()), 0)


class TestAnomalyDetection(unittest.TestCase):
    def test_arp_conflict(self):
        from netpwn.arp import parse_arp
        arp_flows = [parse_arp(ARP_REQUEST), parse_arp(ARP_REPLY)]
        # ARP_REPLY claims 192.0.2.1 with aa:... MAC, ARP_REQUEST claims 192.0.2.10
        # no conflict here
        parsed_flows = {"arp": arp_flows, "dhcp": [], "dns": []}
        anomalies = sniff.detect_anomalies(parsed_flows)
        self.assertEqual(len(anomalies), 0)

    def test_arp_conflict_detected_same_ip_two_macs(self):
        from netpwn.arp import parse_arp
        import copy
        reply_a = parse_arp(ARP_REPLY)  # 192.0.2.1 from aa:bb:cc:dd:ee:ff
        reply_b = copy.deepcopy(reply_a)
        reply_b["sender_mac"] = "66:77:88:99:aa:bb"  # same IP, different MAC
        flows = {"arp": [reply_a, reply_b], "dhcp": [], "dns": []}
        anomalies = sniff.detect_anomalies(flows)
        self.assertTrue(any(a["type"] == "ARP_CONFLICT" for a in anomalies))

    def test_dhcp_starvation(self):
        from netpwn.dhcp import parse_dhcp, build_dhcp
        from netpwn import safety
        discovers = []
        for i in range(8):
            pkt = build_dhcp(xid=0xAA000000 + i,
                             chaddr=safety.random_mac(100 + i), msg_type=1)
            discovers.append(parse_dhcp(pkt))
        flows = {"arp": [], "dhcp": discovers, "dns": []}
        anomalies = sniff.detect_anomalies(flows)
        self.assertTrue(any(a["type"] == "DHCP_STARVATION" for a in anomalies))

    def test_dns_id_mismatch(self):
        from netpwn.dns import parse_dns
        r1 = parse_dns(DNS_RESPONSE_A)
        r2 = parse_dns(DNS_RESPONSE_MISMATCH)
        flows = {"arp": [], "dhcp": [], "dns": [r1, r2]}
        anomalies = sniff.detect_anomalies(flows)
        self.assertTrue(any(a["type"] == "DNS_SPOOF_SUSPECTED" for a in anomalies))


class TestPcapEndToEnd(unittest.TestCase):
    def test_fixture_flows_extract(self):
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "e2e.pcap")
        try:
            sniff.create_pcap([
                ARP_REQUEST,
                sniff.wrap_udp(DHCP_DISCOVER, 68, 67),
                sniff.wrap_udp(DNS_RESPONSE_A, 53, 53000),
            ], self.path)
            reader = sniff.PcapReader(self.path)
            pkts = list(reader)
            reader.close()
            flows = sniff.extract_flows([p["data"] for p in pkts])
            self.assertEqual(len(flows["arp"]), 1)
            self.assertEqual(len(flows["dhcp"]), 1)
            self.assertEqual(len(flows["dns"]), 1)
        finally:
            if os.path.exists(self.path):
                os.unlink(self.path)
            os.rmdir(self.dir)


if __name__ == "__main__":
    unittest.main()
