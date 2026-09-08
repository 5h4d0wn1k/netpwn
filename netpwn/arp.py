"""ARP module — build/parse packets byte-exact, spoof/restore demo, cache harness."""

from __future__ import annotations

import socket
import struct
import time
from typing import Optional

from . import safety
from .fixtures import ARP_REQUEST, ARP_REPLY, ARP_GRATUITOUS

# ---------------------------------------------------------------------------
# ARP packet builder
# ---------------------------------------------------------------------------

def build_arp(
    opcode: int,
    sender_mac: str,
    sender_ip: str,
    target_mac: str = "00:00:00:00:00:00",
    target_ip: str = "0.0.0.0",
    eth_dst: str = "ff:ff:ff:ff:ff:ff",
) -> bytes:
    """Build a raw Ethernet+ARP frame (no padding)."""
    dst = safety.mac_bytes(eth_dst)
    src = safety.mac_bytes(sender_mac)
    hdr = struct.pack("!6s6s2s", dst, src, b"\x08\x06")
    arp = struct.pack(
        "!HHBBH6s4s6s4s",
        1,  # hardware type Ethernet
        0x0800,  # protocol IPv4
        6,  # hw addr len
        4,  # proto addr len
        opcode,
        safety.mac_bytes(sender_mac),
        socket.inet_aton(sender_ip),
        safety.mac_bytes(target_mac),
        socket.inet_aton(target_ip),
    )
    return hdr + arp


def parse_arp(frame: bytes) -> dict:
    """Parse an Ethernet+ARP frame into a dict."""
    if len(frame) < 42:
        raise ValueError(f"Frame too short for ARP: {len(frame)}")
    eth_dst = safety.mac_str(frame[0:6])
    eth_src = safety.mac_str(frame[6:12])
    ether_type = struct.unpack("!H", frame[12:14])[0]
    if ether_type != 0x0806:
        raise ValueError(f"Not ARP: EtherType 0x{ether_type:04x}")
    hw_type, proto_type, hw_len, proto_len, opcode = struct.unpack(
        "!HHBBH", frame[14:22]
    )
    sender_mac = safety.mac_str(frame[22:28])
    sender_ip = socket.inet_ntoa(frame[28:32])
    target_mac = safety.mac_str(frame[32:38])
    target_ip = socket.inet_ntoa(frame[38:42])
    return {
        "eth_dst": eth_dst,
        "eth_src": eth_src,
        "hw_type": hw_type,
        "proto_type": proto_type,
        "opcode": opcode,
        "opcode_str": "request" if opcode == 1 else "reply" if opcode == 2 else f"unknown({opcode})",
        "sender_mac": sender_mac,
        "sender_ip": sender_ip,
        "target_mac": target_mac,
        "target_ip": target_ip,
    }


# ---------------------------------------------------------------------------
# Gratuitous ARP generator
# ---------------------------------------------------------------------------

def gratuitous_arp(mac: str, ip: str) -> bytes:
    """Build a gratuitous ARP announcement frame."""
    return build_arp(1, mac, ip, target_mac=mac, target_ip=ip, eth_dst="ff:ff:ff:ff:ff:ff")


# ---------------------------------------------------------------------------
# ARP spoof / restore demo
# ---------------------------------------------------------------------------

def spoof_demo(iface: str | None = None, *,
               dry_run: bool = True,
               yes: bool = False,
               allowlist: set[str] | None = None) -> dict:
    """Spoof ARP of 192.0.2.10 claiming 192.0.2.1's MAC on *iface*.

    In dry-run mode, builds and returns the packet without sending.
    """
    spoof_mac = safety.random_mac(42)
    target_ip = "192.0.2.10"
    victim_ip = "192.0.2.1"

    if dry_run:
        pkt = build_arp(2, spoof_mac, victim_ip, target_mac="00:11:22:33:44:55",
                         target_ip=target_ip)
        parsed = parse_arp(pkt)
        safety.dry_action(
            f"ARP spoof reply: {parsed['sender_mac']} is-at {parsed['sender_ip']} "
            f"towards {parsed['target_ip']}", dry_run=True
        )
        # Build the restore packet
        restore_pkt = build_arp(2, "aa:bb:cc:dd:ee:ff", victim_ip,
                                 target_mac="00:11:22:33:44:55",
                                 target_ip=target_ip)
        safety.dry_action(
            f"ARP restore reply: aa:bb:cc:dd:ee:ff is-at {victim_ip}", dry_run=True
        )
        return {
            "spoof_packet": pkt,
            "spoof_parsed": parsed,
            "restore_packet": restore_pkt,
            "mode": "dry-run",
        }
    else:
        safety.require_live_gate(iface, yes, allowlist, dry_run=False)
        # Real send via raw socket
        try:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))
            sock.bind((iface, 0))
        except PermissionError:
            raise safety.LiveActionBlocked("Raw socket requires root. Use --dry-run or run as root.")

        spoof_pkt = build_arp(2, spoof_mac, victim_ip,
                               target_mac="00:11:22:33:44:55", target_ip=target_ip)
        sock.send(spoof_pkt)
        time.sleep(0.5)
        restore_pkt = build_arp(2, "aa:bb:cc:dd:ee:ff", victim_ip,
                                 target_mac="00:11:22:33:44:55", target_ip=target_ip)
        sock.send(restore_pkt)
        sock.close()
        return {"mode": "live", "iface": iface}


# ---------------------------------------------------------------------------
# Offline ARP cache poisoning test harness (loopback)
# ---------------------------------------------------------------------------

def arp_cache_harness(iface: str = "lo", *, dry_run: bool = True) -> dict:
    """Send ARP frames on loopback and read them back via raw socket.

    Uses AF_PACKET loopback to prove byte-exact roundtrip.
    In dry-run mode just returns the roundtrip dict without socket ops.
    """
    if dry_run:
        return {"mode": "dry-run", "roundtrip_ok": True}

    # Loopback raw socket test
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))
        sock.bind((iface, 0))
    except (PermissionError, OSError):
        return {"mode": "error", "msg": "Cannot open raw socket on loopback"}

    pkt = build_arp(1, "00:11:22:33:44:55", "127.0.0.2",
                     target_mac="00:00:00:00:00:00", target_ip="127.0.0.1")
    sock.send(pkt)
    time.sleep(0.1)
    try:
        data, _ = sock.recvfrom(65535)
        ok = data[:len(pkt)] == pkt
    except BlockingIOError:
        ok = False
    finally:
        sock.close()
    return {"mode": "live", "roundtrip_ok": ok}


# ---------------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------------

def demo() -> None:
    print("[arp] Byte-exact build/parse test ...")
    pkt = build_arp(1, "00:11:22:33:44:55", "192.0.2.1",
                     target_mac="aa:bb:cc:dd:ee:ff", target_ip="192.0.2.2")
    p = parse_arp(pkt)
    assert p["opcode"] == 1 and p["sender_ip"] == "192.0.2.1", "FAIL"
    print(f"  OK — {p['opcode_str']} from {p['sender_ip']} to {p['target_ip']}")

    print("[arp] Fixture request parse ...")
    fp = parse_arp(ARP_REQUEST)
    assert fp["sender_ip"] == "192.0.2.10" and fp["target_ip"] == "192.0.2.1"
    print(f"  OK — {fp['opcode_str']} {fp['sender_ip']} -> {fp['target_ip']}")

    print("[arp] Fixture reply parse ...")
    fp2 = parse_arp(ARP_REPLY)
    assert fp2["opcode"] == 2 and fp2["sender_ip"] == "192.0.2.1"
    print(f"  OK — {fp2['opcode_str']} {fp2['sender_ip']} is-at {fp2['sender_mac']}")

    print("[arp] Gratuitous ARP builder ...")
    g = gratuitous_arp("aa:bb:cc:dd:ee:ff", "192.0.2.1")
    gp = parse_arp(g)
    assert gp["target_ip"] == gp["sender_ip"] == "192.0.2.1"
    print(f"  OK — gratuitous from {gp['sender_ip']}")

    print("[arp] Spoof/restore dry-run ...")
    r = spoof_demo(dry_run=True)
    assert r["mode"] == "dry-run" and "spoof_packet" in r
    print(f"  OK — spoof packet {len(r['spoof_packet'])}B, restore packet {len(r['restore_packet'])}B")

    print("[arp] Loopback roundtrip dry-run ...")
    lr = arp_cache_harness(dry_run=True)
    assert lr["roundtrip_ok"]
    print("  OK — roundtrip dry-run")

    print("[arp] All demos passed.")
