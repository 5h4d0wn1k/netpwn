import unittest
from netpwn.cli import main


class TestCLI(unittest.TestCase):
    def test_no_args_help(self):
        self.assertEqual(main([]), 0)

    def test_version(self):
        with self.assertRaises(SystemExit):
            main(["--version"])

    def test_demo_exit_zero(self):
        # --demo must exit 0
        self.assertEqual(main(["--demo"]), 0)

    def test_arp_build_output(self):
        rc = main(["arp", "build", "--sender-ip", "192.0.2.5"])
        self.assertEqual(rc, 0)

    def test_arp_parse(self):
        rc = main(["arp", "parse"])
        self.assertEqual(rc, 0)

    def test_arp_demo(self):
        self.assertEqual(main(["arp", "demo"]), 0)

    def test_dhcp_starve(self):
        rc = main(["dhcp", "starve", "--count", "5"])
        self.assertEqual(rc, 0)

    def test_dns_query(self):
        rc = main(["dns", "query", "--name", "www.example.com"])
        self.assertEqual(rc, 0)

    def test_dns_spoof_check(self):
        rc = main(["dns", "spoof-check"])
        self.assertEqual(rc, 0)

    def test_dns_rebind(self):
        rc = main(["dns", "rebind"])
        self.assertEqual(rc, 0)

    def test_vlan_build(self):
        rc = main(["vlan", "build", "--vid", "200"])
        self.assertEqual(rc, 0)

    def test_vlan_detect(self):
        rc = main(["vlan", "detect"])
        self.assertEqual(rc, 0)

    def test_spoof_icmp(self):
        rc = main(["spoof", "icmp"])
        self.assertEqual(rc, 0)

    def test_spoof_sweep(self):
        rc = main(["spoof", "sweep", "--count", "3"])
        self.assertEqual(rc, 0)

    def test_spoof_mac_dry(self):
        rc = main(["spoof", "mac", "--dry-run"])
        self.assertEqual(rc, 0)

    def test_knock_send_dry(self):
        rc = main(["knock", "send"])
        self.assertEqual(rc, 0)

    def test_knock_e2e(self):
        rc = main(["knock", "e2e"])
        self.assertEqual(rc, 0)

    def test_mitm_plan_dry(self):
        rc = main(["mitm", "plan"])
        self.assertEqual(rc, 0)

    def test_report_demo(self):
        rc = main(["report", "demo"])
        self.assertEqual(rc, 0)

    def test_invalid_subcommand(self):
        with self.assertRaises(SystemExit):
            main(["nope", "x"])


if __name__ == "__main__":
    unittest.main()
