import os
import tempfile
import unittest

from netpwn import mitm
from netpwn.fixtures import ARP_REQUEST, ARP_REPLY


class TestCaptureStore(unittest.TestCase):
    def test_insert_count(self):
        store = mitm.CaptureStore(":memory:")
        store.insert(src_mac="aa:bb:cc:dd:ee:ff", ethertype=0x0806,
                     length=42, description="test")
        self.assertEqual(store.count(), 1)
        store.close()

    def test_rows(self):
        store = mitm.CaptureStore(":memory:")
        store.insert(src_mac="aa:bb:cc:dd:ee:ff", ethertype=0x0806,
                     length=42, description="arp")
        store.insert(ethertype=0x0800, length=100, description="ip")
        rows = store.all_rows()
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["desc"], "arp")
        self.assertEqual(rows[1]["etype"], 0x0800)
        store.close()

    def test_empty_count(self):
        store = mitm.CaptureStore(":memory:")
        self.assertEqual(store.count(), 0)
        store.close()


class TestMITMInterceptor(unittest.TestCase):
    def test_dry_run(self):
        i = mitm.MITMInterceptor(dry_run=True)
        r = i.start()
        self.assertEqual(r["mode"], "dry-run")

    def test_dry_plan(self):
        plan = mitm.dry_mitm_plan("lo")
        self.assertEqual(plan["steps"], 6)

    def test_live_loopback_capture(self):
        import socket, time
        store = mitm.CaptureStore(":memory:")
        i = mitm.MITMInterceptor(store=store, dry_run=False, port=20091)
        lr = i.start()
        self.assertEqual(lr["mode"], "live")
        time.sleep(0.2)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.0)
        s.connect(("127.0.0.1", 20091))
        s.sendall(b"hello-mitm")
        s.close()
        time.sleep(0.6)
        sr = i.stop()
        self.assertGreaterEqual(sr["captured"], 1)
        store.close()


class TestMITMDryRun(unittest.TestCase):
    def test_multi_store_demo(self):
        path = os.path.join(tempfile.gettempdir(), "netpwn_capture_store.db")
        if os.path.exists(path):
            os.unlink(path)
        store = mitm.CaptureStore(path)
        for _ in range(3):
            store.insert(ethertype=0x0806, length=42)
        self.assertEqual(store.count(), 3)
        store.close()
        os.unlink(path)


if __name__ == "__main__":
    unittest.main()
