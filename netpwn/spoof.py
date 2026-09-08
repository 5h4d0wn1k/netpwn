"""Spoofing toolkit — IP spoof, MAC change, reverse-DNS, ICMP sweep sim."""

from __future__ import annotations

import hashlib
import socket
import struct
from typing import Optional

from .fixtures import IP_SPOOFED_ICMP
from . import safety

# ---------------------------------------------------------------------------
# IP spoofed packet builder
# ---------------------------------------------------------------------------

def build_ip_spoofed_icmp(
    src_ip: str = "192.0.2.255",
    dst_ip: str = "127.0.0.1",
    src_mac: str = "00:11:22:33:44:55",
    icmp_id: int = 1,
    icmp_seq: int = 1,
) -> bytes:
    """Build an ICMP echo request with a forged source IP (raw Ethernet frame)."""
    eth_dst = "ff:ff:ff:ff:ff:ff"
    dst_mac = safety.mac_bytes(eth_dst)
    src_mac_b = safety.mac_bytes(src_mac)
    eth_header = struct.pack("!6s6s2s", dst_mac, src_mac_b, b"\x08\x00")

    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,       # ver=4, ihl=5
        0x00,       # DSCP
        28,         # total length (20 IP + 8 ICMP)
        0x0000,     # identification
        0x4000,     # flags: don't fragment, frag offset 0
        64,         # TTL
        1,          # proto ICMP
        0,          # checksum (filled below)
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip),
    )
    # Compute IP checksum
    csum = _ip_checksum(ip_header)
    ip_header = ip_header[:10] + struct.pack("!H", csum) + ip_header[12:]

    icmp = struct.pack("!BBHHH", 8, 0, 0, icmp_id, icmp_seq)
    icmp_csum = _icmp_checksum(icmp)
    icmp = struct.pack("!BBHHH", 8, 0, icmp_csum, icmp_id, icmp_seq)

    return eth_header + ip_header + icmp


def _ip_checksum(header: bytes) -> int:
    """Compute IPv4 header checksum."""
    if len(header) % 2:
        header += b"\x00"
    s = 0
    for i in range(0, len(header), 2):
        s += (header[i] << 8) | header[i + 1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def _icmp_checksum(data: bytes) -> int:
    """Compute ICMP checksum."""
    if len(data) % 2:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) | data[i + 1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


# ---------------------------------------------------------------------------
# MAC change simulation
# ---------------------------------------------------------------------------

def simulate_mac_change(iface: str | None = None, new_mac: str = "de:ad:be:ef:00:01",
                        *, dry_run: bool = True, yes: bool = False,
                        allowlist: set[str] | None = None) -> dict:
    """Simulate changing a NIC's MAC address.

    Uses SIOCSIFHWADDR ioctl in live mode. Dry-run prints what would happen.
    """
    if dry_run:
        safety.dry_action(
            f"Would change MAC on {iface or '<default>'} to {new_mac}",
            dry_run=True,
        )
        return {"mode": "dry-run", "new_mac": new_mac, "iface": iface}

    safety.require_live_gate(iface, yes, allowlist, dry_run=False)
    import fcntl
    SIOCSIFHWADDR = 0x8924
    ARPHRD_ETHER = 1

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)
    try:
        mac_b = safety.mac_bytes(new_mac)
        ifr = struct.pack("256s", iface[:15].encode("utf-8"))
        ifr = ifr[:15] + mac_b + ifr[31:]
        fcntl.ioctl(s.fileno(), SIOCSIFHWADDR, ifr)
        return {"mode": "live", "new_mac": new_mac, "iface": iface, "ok": True}
    except Exception as e:
        return {"mode": "live", "error": str(e)}
    finally:
        s.close()


# ---------------------------------------------------------------------------
# Reverse-DNS simulation
# ---------------------------------------------------------------------------

def reverse_dns_sim(ip: str = "192.0.2.1") -> dict:
    """Attempt a real reverse-DNS lookup (safe: read-only DNS PTR query)."""
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return {"ip": ip, "hostname": hostname, "found": True}
    except (socket.herror, socket.gaierror):
        return {"ip": ip, "hostname": None, "found": False}


# ---------------------------------------------------------------------------
# ICMP sweep simulation (offline)
# ---------------------------------------------------------------------------

def icmp_sweep_sim(network: str = "192.0.2.0/24", count: int = 5) -> list[dict]:
    """Simulate an ICMP sweep by generating crafted packets (no actual send)."""
    import ipaddress
    net = ipaddress.ip_network(network, strict=False)
    hosts = list(net.hosts())[:count]
    results = []
    for i, host in enumerate(hosts):
        pkt = build_ip_spoofed_icmp(
            src_ip="192.0.2.255",
            dst_ip=str(host),
            icmp_id=i,
            icmp_seq=i + 1,
        )
        results.append({
            "target": str(host),
            "packet_len": len(pkt),
            "icmp_id": i,
            "icmp_seq": i + 1,
        })
    return results


# ---------------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------------

def demo() -> None:
    print("[spoof] IP-spoofed ICMP build ...")
    pkt = build_ip_spoofed_icmp(src_ip="192.0.2.255", dst_ip="127.0.0.1")
    assert len(pkt) == 42, f"Expected 42 bytes, got {len(pkt)}"
    # Verify src IP is at offset 26-30 in the Ethernet frame (after ETH header)
    src_in_frame = socket.inet_ntoa(pkt[26:30])
    assert src_in_frame == "192.0.2.255", f"Wrong src IP: {src_in_frame}"
    print(f"  OK — {len(pkt)}B frame, forged src={src_in_frame}")

    print("[spoof] Fixture ICMP parse ...")
    fpkt = IP_SPOOFED_ICMP
    assert socket.inet_ntoa(fpkt[26:30]) == "192.0.2.255"
    print(f"  OK — fixture src=192.0.2.255, {len(fpkt)} bytes")

    print("[spoof] MAC change dry-run ...")
    r = simulate_mac_change(iface="lo", new_mac="de:ad:be:ef:00:01", dry_run=True)
    assert r["mode"] == "dry-run"
    print(f"  OK — would change to {r['new_mac']}")

    print("[spoof] Reverse-DNS sim ...")
    rdns = reverse_dns_sim("127.0.0.1")
    print(f"  OK — 127.0.0.1 -> {rdns['hostname'] or 'N/A'} (found={rdns['found']})")

    print("[spoof] ICMP sweep sim (192.0.2.0/24, 5 hosts) ...")
    sweep = icmp_sweep_sim("192.0.2.0/24", 5)
    assert len(sweep) == 5
    assert all(r["packet_len"] == 42 for r in sweep)
    print(f"  OK — {len(sweep)} targets, {sweep[0]['packet_len']}B each")

    print("[spoof] All demos passed.")
