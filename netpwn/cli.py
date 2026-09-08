"""CLI — argparse subcommands: arp, dhcp, dns, vlan, spoof, knock, mitm, sniff, report, --demo."""

from __future__ import annotations

import argparse
import json
import sys
import os
from typing import Sequence

from . import __version__
from . import safety


def _common_flags(sub: argparse.ArgumentParser) -> None:
    """Add flags common to every subcommand."""
    sub.add_argument("--dry-run", action="store_true", default=True,
                     help="Dry-run mode (default). No live network action.")
    sub.add_argument("--live", action="store_true", default=False,
                     help="Enable live mode (disables dry-run).")
    sub.add_argument("--iface", type=str, default=None,
                     help="Network interface for live actions.")
    sub.add_argument("--yes", action="store_true", default=False,
                     help="Confirm live action.")
    sub.add_argument("--lab-allowlist", type=str, default=None,
                     help="Path to lab allowlist file.")


def _resolve_dry(args) -> bool:
    if args.live:
        return False
    return args.dry_run


def _get_allowlist(args) -> set[str] | None:
    if args.lab_allowlist:
        return safety.load_allowlist(args.lab_allowlist)
    return None


# ---------------------------------------------------------------------------
# Subcommand handlers
# ---------------------------------------------------------------------------

def cmd_arp(args) -> int:
    from . import arp
    if args.action == "build":
        pkt = arp.build_arp(
            opcode=args.opcode,
            sender_mac=args.sender_mac,
            sender_ip=args.sender_ip,
            target_mac=args.target_mac,
            target_ip=args.target_ip,
        )
        parsed = arp.parse_arp(pkt)
        print(json.dumps(parsed, indent=2))
        return 0
    elif args.action == "parse":
        if args.file:
            with open(args.file, "rb") as f:
                data = f.read()
        else:
            # Parse fixture
            from .fixtures import ARP_REQUEST
            data = ARP_REQUEST
        parsed = arp.parse_arp(data)
        print(json.dumps(parsed, indent=2))
        return 0
    elif args.action == "spoof":
        dry = _resolve_dry(args)
        allowlist = _get_allowlist(args)
        result = arp.spoof_demo(
            iface=args.iface, dry_run=dry,
            yes=args.yes, allowlist=allowlist,
        )
        print(json.dumps({k: v for k, v in result.items() if k != "spoof_packet" and k != "restore_packet"}, indent=2))
        return 0
    elif args.action == "demo":
        arp.demo()
        return 0
    return 1


def cmd_dhcp(args) -> int:
    from . import dhcp
    if args.action == "parse":
        if args.file:
            with open(args.file, "rb") as f:
                data = f.read()
        else:
            from .fixtures import DHCP_DISCOVER
            data = DHCP_DISCOVER
        parsed = dhcp.parse_dhcp(data)
        print(json.dumps(parsed, indent=2))
        return 0
    elif args.action == "starve":
        count = args.count or 10
        results = dhcp.starvation_sim(count)
        print(json.dumps(results, indent=2))
        return 0
    elif args.action == "rogue":
        dry = _resolve_dry(args)
        result = dhcp.rogue_dhcp_demo(dry_run=dry)
        print(json.dumps({k: v for k, v in result.items() if k != "offer"}, indent=2))
        return 0
    elif args.action == "demo":
        dhcp.demo()
        return 0
    return 1


def cmd_dns(args) -> int:
    from . import dns
    if args.action == "query":
        q = dns.build_dns_query(args.name or "www.example.com",
                                 qtype=args.qtype or 1,
                                 tx_id=args.txid or 0x1234)
        parsed = dns.parse_dns(q)
        print(json.dumps(parsed, indent=2))
        return 0
    elif args.action == "response":
        from .fixtures import DNS_RESPONSE_A
        parsed = dns.parse_dns(DNS_RESPONSE_A)
        print(json.dumps(parsed, indent=2))
        return 0
    elif args.action == "spoof-check":
        from .fixtures import DNS_RESPONSE_A, DNS_RESPONSE_MISMATCH
        results = dns.detect_dns_spoof(0xABCD, [DNS_RESPONSE_A, DNS_RESPONSE_MISMATCH])
        print(json.dumps(results, indent=2))
        return 0
    elif args.action == "rebind":
        rb = dns.rebinding_demo()
        print(json.dumps(rb, indent=2))
        return 0
    elif args.action == "demo":
        dns.demo()
        return 0
    return 1


def cmd_vlan(args) -> int:
    from . import vlan
    if args.action == "build":
        inner = args.inner_vid
        frame = vlan.build_vlan_frame(
            vid=args.vid or 100,
            inner_vid=inner,
        )
        parsed = vlan.parse_vlan_frame(frame)
        print(json.dumps({k: v for k, v in parsed.items() if k != "payload"}, indent=2))
        return 0
    elif args.action == "detect":
        from .fixtures import VLAN_DOUBLE_TAGGED
        anomalies = vlan.detect_tag_anomalies(VLAN_DOUBLE_TAGGED)
        print(json.dumps(anomalies, indent=2))
        return 0
    elif args.action == "demo":
        vlan.demo()
        return 0
    return 1


def cmd_spoof(args) -> int:
    from . import spoof
    if args.action == "icmp":
        pkt = spoof.build_ip_spoofed_icmp(
            src_ip=args.src_ip or "192.0.2.255",
            dst_ip=args.dst_ip or "127.0.0.1",
        )
        print(f"ICMP spoofed frame: {len(pkt)} bytes")
        return 0
    elif args.action == "sweep":
        results = spoof.icmp_sweep_sim(args.network or "192.0.2.0/24",
                                        args.count or 5)
        print(json.dumps(results, indent=2))
        return 0
    elif args.action == "mac":
        dry = _resolve_dry(args)
        allowlist = _get_allowlist(args)
        result = spoof.simulate_mac_change(
            iface=args.iface, new_mac=args.mac or "de:ad:be:ef:00:01",
            dry_run=dry, yes=args.yes, allowlist=allowlist,
        )
        print(json.dumps(result, indent=2))
        return 0
    elif args.action == "rdns":
        result = spoof.reverse_dns_sim(args.ip or "127.0.0.1")
        print(json.dumps(result, indent=2))
        return 0
    elif args.action == "demo":
        spoof.demo()
        return 0
    return 1


def cmd_knock(args) -> int:
    from . import knock
    if args.action == "send":
        dry = _resolve_dry(args)
        result = knock.send_knock(
            target=args.target or "127.0.0.1",
            dry_run=dry,
        )
        print(json.dumps(result, indent=2))
        return 0
    elif args.action == "e2e":
        result = knock.knock_e2e_test()
        print(json.dumps(result, indent=2))
        return 0
    elif args.action == "demo":
        knock.demo()
        return 0
    return 1


def cmd_mitm(args) -> int:
    from . import mitm
    if args.action == "plan":
        dry = _resolve_dry(args)
        if not dry:
            # live mode - start actual interceptor briefly
            store = mitm.CaptureStore(":memory:")
            interceptor = mitm.MITMInterceptor(store=store, dry_run=False,
                                                port=args.port or 19876)
            r = interceptor.start()
            print(json.dumps(r, indent=2))
            import time
            time.sleep(1)
            sr = interceptor.stop()
            store.close()
            print(json.dumps(sr, indent=2))
            return 0
        result = mitm.dry_mitm_plan(args.iface or "lo")
        print(json.dumps(result, indent=2))
        return 0
    elif args.action == "demo":
        mitm.demo()
        return 0
    return 1


def cmd_sniff(args) -> int:
    from . import sniff
    if args.action == "read":
        if not args.file:
            print("Error: --file required for sniff read", file=sys.stderr)
            return 1
        reader = sniff.PcapReader(args.file)
        pkts = list(reader)
        reader.close()
        raw = [p["data"] for p in pkts]
        flows = sniff.extract_flows(raw)
        anomalies = sniff.detect_anomalies(flows)
        print(json.dumps({
            "packets": len(pkts),
            "flows": {k: len(v) for k, v in flows.items()},
            "anomalies": anomalies,
        }, indent=2))
        return 0
    elif args.action == "demo":
        sniff.demo()
        return 0
    return 1


def cmd_report(args) -> int:
    from . import report
    if args.action == "generate":
        data = json.loads(args.data) if args.data else {"status": "empty"}
        paths = report.generate_report(data, path=args.output or "reports")
        print(json.dumps(paths, indent=2))
        return 0
    elif args.action == "demo":
        report.demo()
        return 0
    return 1


def cmd_demo(args) -> int:
    """Run all module demos."""
    from . import arp, dhcp, dns, vlan, spoof, knock, mitm, sniff, report
    modules = [
        ("ARP", arp.demo),
        ("DHCP", dhcp.demo),
        ("DNS", dns.demo),
        ("VLAN", vlan.demo),
        ("Spoof", spoof.demo),
        ("Knock", knock.demo),
        ("MITM", mitm.demo),
        ("Sniff", sniff.demo),
        ("Report", report.demo),
    ]
    passed = 0
    failed = 0
    for name, fn in modules:
        try:
            fn()
            passed += 1
        except Exception as e:
            print(f"[{name}] FAILED: {e}")
            failed += 1
    print(f"\n{'='*50}")
    print(f"Demo complete: {passed}/{passed+failed} modules passed")
    return 0 if failed == 0 else 1


# ---------------------------------------------------------------------------
# Main parser
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netpwn",
        description="L2/L3 MITM & network attack suite — dry-run default",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--demo", action="store_true", default=False,
                        help="Run all module demos (offline, exit 0)")

    sub = parser.add_subparsers(dest="command", help="Module subcommand")

    # ARP
    arp_p = sub.add_parser("arp", help="ARP spoof/parse/build")
    arp_p.add_argument("action", choices=["build", "parse", "spoof", "demo"])
    arp_p.add_argument("--opcode", type=int, default=1)
    arp_p.add_argument("--sender-mac", default="00:11:22:33:44:55")
    arp_p.add_argument("--sender-ip", default="192.0.2.1")
    arp_p.add_argument("--target-mac", default="00:00:00:00:00:00")
    arp_p.add_argument("--target-ip", default="192.0.2.2")
    arp_p.add_argument("--file", default=None)
    _common_flags(arp_p)

    # DHCP
    dhcp_p = sub.add_parser("dhcp", help="DHCP parse/starve/rogue")
    dhcp_p.add_argument("action", choices=["parse", "starve", "rogue", "demo"])
    dhcp_p.add_argument("--count", type=int, default=10)
    dhcp_p.add_argument("--file", default=None)
    _common_flags(dhcp_p)

    # DNS
    dns_p = sub.add_parser("dns", help="DNS query/response/spoof-check/rebind")
    dns_p.add_argument("action", choices=["query", "response", "spoof-check", "rebind", "demo"])
    dns_p.add_argument("--name", default=None)
    dns_p.add_argument("--qtype", type=int, default=1)
    dns_p.add_argument("--txid", type=int, default=None)
    _common_flags(dns_p)

    # VLAN
    vlan_p = sub.add_parser("vlan", help="VLAN build/detect")
    vlan_p.add_argument("action", choices=["build", "detect", "demo"])
    vlan_p.add_argument("--vid", type=int, default=100)
    vlan_p.add_argument("--inner-vid", type=int, default=None)
    _common_flags(vlan_p)

    # Spoof
    spoof_p = sub.add_parser("spoof", help="IP spoof/MAC/ICMP sweep")
    spoof_p.add_argument("action", choices=["icmp", "sweep", "mac", "rdns", "demo"])
    spoof_p.add_argument("--src-ip", default=None)
    spoof_p.add_argument("--dst-ip", default=None)
    spoof_p.add_argument("--network", default=None)
    spoof_p.add_argument("--count", type=int, default=5)
    spoof_p.add_argument("--mac", default=None)
    spoof_p.add_argument("--ip", default=None)
    _common_flags(spoof_p)

    # Knock
    knock_p = sub.add_parser("knock", help="Port-knock send/e2e")
    knock_p.add_argument("action", choices=["send", "e2e", "demo"])
    knock_p.add_argument("--target", default="127.0.0.1")
    _common_flags(knock_p)

    # MITM
    mitm_p = sub.add_parser("mitm", help="MITM interceptor plan/start")
    mitm_p.add_argument("action", choices=["plan", "demo"])
    mitm_p.add_argument("--port", type=int, default=19876)
    _common_flags(mitm_p)

    # Sniff
    sniff_p = sub.add_parser("sniff", help="pcap reader/anomaly detection")
    sniff_p.add_argument("action", choices=["read", "demo"])
    sniff_p.add_argument("--file", default=None)
    _common_flags(sniff_p)

    # Report
    report_p = sub.add_parser("report", help="Generate JSON+MD reports")
    report_p.add_argument("action", choices=["generate", "demo"])
    report_p.add_argument("--data", default=None, help="JSON string")
    report_p.add_argument("--output", default="reports")
    _common_flags(report_p)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.demo:
        return cmd_demo(args)

    if not args.command:
        parser.print_help()
        return 0

    handlers = {
        "arp": cmd_arp,
        "dhcp": cmd_dhcp,
        "dns": cmd_dns,
        "vlan": cmd_vlan,
        "spoof": cmd_spoof,
        "knock": cmd_knock,
        "mitm": cmd_mitm,
        "sniff": cmd_sniff,
        "report": cmd_report,
    }

    handler = handlers.get(args.command)
    if handler:
        return handler(args)
    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
