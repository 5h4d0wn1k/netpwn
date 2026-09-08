import unittest

from netpwn import knock, safety
from netpwn.fixtures import KNOCK_PORTS, SECRET_PORT, KNOCK_SECRET


class TestKnockBuild(unittest.TestCase):
    def test_send_dry_run(self):
        r = knock.send_knock(dry_run=True)
        self.assertEqual(r["mode"], "dry-run")
        self.assertEqual(len(r["packets"]), 3)

    def test_syn_builder_length(self):
        syn = knock.build_syn("127.0.0.1", 7000)
        self.assertEqual(len(syn), 20)

    def test_syn_flags(self):
        syn = knock.build_syn("127.0.0.1", 7000, seq=1000)
        # flags byte at offset 13, SYN bit = 0x02
        self.assertEqual(syn[13] & 0x02, 0x02)

    def test_syn_ports(self):
        import struct
        syn = knock.build_syn("127.0.0.1", 8000)
        dst = struct.unpack("!H", syn[2:4])[0]
        self.assertEqual(dst, 8000)

    def test_syn_different_ports(self):
        p1 = knock.build_syn("127.0.0.1", 8999, src_port=40000)
        p2 = knock.build_syn("127.0.0.1", 9000, src_port=40001)
        self.assertNotEqual(p1, p2)


class TestKnockE2E(unittest.TestCase):
    def test_end_to_end_opens_secret_port(self):
        result = knock.knock_e2e_test()
        self.assertTrue(result["ok"], f"E2E failed: {result}")
        self.assertTrue(result["secret_matched"])

    def test_knock_ports_fixture(self):
        self.assertEqual(KNOCK_PORTS, [7000, 8000, 9000])
        self.assertEqual(SECRET_PORT, 9999)


class TestKnockListener(unittest.TestCase):
    def test_knock_tracking(self):
        listener = knock.KnockListener(knock_ports=[7000, 8000])
        listener.handle_syn_on_knock_port(7000, "192.0.2.1")
        listener.handle_syn_on_knock_port(8000, "192.0.2.1")
        self.assertTrue(listener._is_knocked("192.0.2.1"))

    def test_knock_tracking_incomplete(self):
        listener = knock.KnockListener(knock_ports=[7000, 8000])
        listener.handle_syn_on_knock_port(7000, "192.0.2.2")
        self.assertFalse(listener._is_knocked("192.0.2.2"))


if __name__ == "__main__":
    unittest.main()
