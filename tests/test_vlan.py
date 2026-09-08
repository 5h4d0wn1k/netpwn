import unittest

from netpwn import vlan
from netpwn.fixtures import VLAN_SINGLE_TAGGED, VLAN_DOUBLE_TAGGED


class TestVLANBuildParse(unittest.TestCase):
    def test_single_tag_roundtrip(self):
        frame = vlan.build_vlan_frame(vid=100)
        p = vlan.parse_vlan_frame(frame)
        self.assertEqual(p["tags"][0]["vid"], 100)
        self.assertFalse(p["double_tagged"])

    def test_single_tag_roundtrip_round(self):
        for vid in (1, 100, 1000, 4094):
            frame = vlan.build_vlan_frame(vid=vid)
            p = vlan.parse_vlan_frame(frame)
            self.assertEqual(p["tags"][0]["vid"], vid)

    def test_double_tag_roundtrip(self):
        frame = vlan.build_vlan_frame(vid=100, inner_vid=200)
        p = vlan.parse_vlan_frame(frame)
        self.assertTrue(p["double_tagged"])
        self.assertEqual(p["tags"][0]["vid"], 200)  # outer
        self.assertEqual(p["tags"][1]["vid"], 100)  # inner

    def test_fixture_single_parse(self):
        p = vlan.parse_vlan_frame(VLAN_SINGLE_TAGGED)
        self.assertEqual(p["tags"][0]["vid"], 100)
        self.assertEqual(len(p["tags"]), 1)

    def test_fixture_double_parse(self):
        p = vlan.parse_vlan_frame(VLAN_DOUBLE_TAGGED)
        self.assertTrue(p["double_tagged"])
        self.assertEqual(p["tags"][0]["vid"], 200)
        self.assertEqual(p["tags"][1]["vid"], 100)

    def test_rejects_short(self):
        with self.assertRaises(ValueError):
            vlan.parse_vlan_frame(b"\x00" * 5)

    def test_ethertype(self):
        frame = vlan.build_vlan_frame(vid=100)
        p = vlan.parse_vlan_frame(frame)
        self.assertEqual(p["ether_type"], 0x0800)


class TestVLANAnomaly(unittest.TestCase):
    def test_same_vid_flagged(self):
        frame = vlan.build_vlan_frame(vid=100, inner_vid=100)
        anomalies = vlan.detect_tag_anomalies(frame)
        self.assertTrue(any("same VID" in a for a in anomalies))

    def test_vid_zero_flagged(self):
        frame = vlan.build_vlan_frame(vid=0)
        anomalies = vlan.detect_tag_anomalies(frame)
        self.assertTrue(any("VID 0" in a for a in anomalies))

    def test_clean_single_tag_no_anomaly(self):
        frame = vlan.build_vlan_frame(vid=100)
        self.assertEqual(vlan.detect_tag_anomalies(frame), [])

    def test_valid_double_tag_outer_vid0_not_ok(self):
        frame = vlan.build_vlan_frame(vid=100, inner_vid=0)
        anomalies = vlan.detect_tag_anomalies(frame)
        self.assertTrue(any("inner" in a.lower() or "VID 0" in a for a in anomalies))


if __name__ == "__main__":
    unittest.main()
