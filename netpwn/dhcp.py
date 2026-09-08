"""DHCP module — build/parse BOOTP/DHCP packets, starvation sim, rogue-DHCP demo."""

from __future__ import annotations

import random
import socket
import struct
from typing import Optional

from .fixtures import (
    DHCP_DISCOVER, DHCP_OFFER, DHCP_REQUEST, DHCP_ACK,
)
from . import safety

# ---------------------------------------------------------------------------
# DHCP option helpers
# ---------------------------------------------------------------------------

_DHCP_OPT_MSG_TYPE = 53
_DHCP_OPT_END = 0xFF

MSG_TYPES = {
    1: "DISCOVER", 2: "OFFER", 3: "REQUEST",
    4: "DECLINE", 5: "ACK", 6: "NAK", 7: "RELEASE", 8: "INFORM",
}


def _parse_options(data: bytes) -> list[tuple[int, int, bytes]]:
    """Parse DHCP options from *data* (after magic cookie)."""
    opts = []
    i = 0
    while i < len(data):
        if data[i] == 0xFF:
            break
        if data[i] == 0x00:
            i += 1
            continue
        opt_code = data[i]
        opt_len = data[i + 1] if i + 1 < len(data) else 0
        opt_val = data[i + 2 : i + 2 + opt_len]
        opts.append((opt_code, opt_len, opt_val))
        i += 2 + opt_len
    return opts


def _build_options(msg_type: int, extra: dict[int, bytes] | None = None) -> bytes:
    """Build DHCP options block ending with 0xFF."""
    parts = [struct.pack("BBB", _DHCP_OPT_MSG_TYPE, 1, msg_type)]
    if extra:
        for code, val in sorted(extra.items()):
            parts.append(struct.pack("BB", code, len(val)) + val)
    parts.append(b"\xff")
    return b"".join(parts)


# ---------------------------------------------------------------------------
# DHCP packet builder
# ---------------------------------------------------------------------------

def build_dhcp(
    *,
    op: int = 1,  # 1=bootrequest, 2=bootreply
    xid: int = 0x12345678,
    flags: int = 0x8000,
    ciaddr: str = "0.0.0.0",
    yiaddr: str = "0.0.0.0",
    siaddr: str = "0.0.0.0",
    giaddr: str = "0.0.0.0",
    chaddr: str = "00:11:22:33:44:55",
    msg_type: int = 1,
    options_extra: dict[int, bytes] | None = None,
) -> bytes:
    """Build a minimal DHCP/BOOTP packet (padded to 300 bytes)."""
    mac = safety.mac_bytes(chaddr)
    _ci = int.from_bytes(socket.inet_aton(ciaddr), "big")
    _yi = int.from_bytes(socket.inet_aton(yiaddr), "big")
    _si = int.from_bytes(socket.inet_aton(siaddr), "big")
    _gi = int.from_bytes(socket.inet_aton(giaddr), "big")
    hdr = struct.pack(
        "!BBBBIHHIIII",
        op, 1, 6, 0,  # op, htype, hlen, hops
        xid,
        0,  # secs (2 bytes)
        flags,
        _ci, _yi, _si, _gi,
    )
    hdr += mac + b"\x00" * 10  # chaddr (6 + 10 padding)
    hdr += b"\x00" * 64       # sname
    hdr += b"\x00" * 128      # file
    hdr += bytes.fromhex("63825363")  # magic cookie
    opts = _build_options(msg_type, options_extra)
    pkt = hdr + opts
    # Pad to minimum BOOTP size (300 bytes)
    if len(pkt) < 300:
        pkt += b"\x00" * (300 - len(pkt))
    return pkt


def parse_dhcp(pkt: bytes) -> dict:
    """Parse a DHCP/BOOTP packet."""
    if len(pkt) < 236:
        raise ValueError(f"Packet too short for DHCP: {len(pkt)}")
    op, htype, hlen, hops = struct.unpack("!BBBB", pkt[0:4])
    xid = struct.unpack("!I", pkt[4:8])[0]
    flags = struct.unpack("!H", pkt[10:12])[0]
    ciaddr = socket.inet_ntoa(pkt[12:16])
    yiaddr = socket.inet_ntoa(pkt[16:20])
    siaddr = socket.inet_ntoa(pkt[20:24])
    giaddr = socket.inet_ntoa(pkt[24:28])
    chaddr = safety.mac_str(pkt[28:34])
    magic = pkt[236:240]
    opts_raw = pkt[240:]
    opts = _parse_options(opts_raw) if magic == bytes.fromhex("63825363") else []
    msg_type_val = 0
    extra_opts = {}
    for code, length, val in opts:
        if code == _DHCP_OPT_MSG_TYPE:
            msg_type_val = val[0] if val else 0
        else:
            extra_opts[code] = val
    return {
        "op": op,
        "htype": htype,
        "hlen": hlen,
        "xid": xid,
        "flags": flags,
        "ciaddr": ciaddr,
        "yiaddr": yiaddr,
        "siaddr": siaddr,
        "giaddr": giaddr,
        "chaddr": chaddr,
        "msg_type": msg_type_val,
        "msg_type_str": MSG_TYPES.get(msg_type_val, f"UNKNOWN({msg_type_val})"),
        "options": extra_opts,
        "packet_len": len(pkt),
    }


# ---------------------------------------------------------------------------
# Starvation simulation
# ---------------------------------------------------------------------------

def starvation_sim(count: int = 10, seed: int = 0) -> list[dict]:
    """Generate *count* fake DHCP discovers with deterministic MACs."""
    results = []
    for i in range(count):
        mac = safety.random_mac(seed + i)
        xid = 0xAA000000 + i
        pkt = build_dhcp(xid=xid, chaddr=mac, msg_type=1)
        parsed = parse_dhcp(pkt)
        results.append({
            "index": i,
            "mac": mac,
            "xid": xid,
            "packet_len": len(pkt),
            "parsed_msg_type": parsed["msg_type_str"],
        })
    return results


# ---------------------------------------------------------------------------
# Rogue DHCP demo
# ---------------------------------------------------------------------------

def rogue_dhcp_demo(dry_run: bool = True) -> dict:
    """Demonstrate rogue DHCP offer construction (offline only)."""
    rogue_mac = safety.random_mac(99)
    rogue_ip = "192.0.2.200"
    victim_mac = "00:11:22:33:44:55"
    xid = 0xDEADBEEF

    # Build rogue OFFER
    rogue_offer = build_dhcp(
        op=2,
        xid=xid,
        yiaddr="192.0.2.50",
        chaddr=victim_mac,
        msg_type=2,
        options_extra={
            3: socket.inet_aton("192.0.2.200"),   # router
            6: socket.inet_aton("192.0.2.200"),   # DNS
            1: bytes([255, 255, 255, 0]),          # subnet
            51: struct.pack("!I", 600),            # lease 600s
        },
    )
    parsed = parse_dhcp(rogue_offer)
    safety.dry_action(
        f"Rogue DHCP OFFER: yiaddr={parsed['yiaddr']}, "
        f"router=DNS={rogue_ip}, from MAC {rogue_mac}",
        dry_run=dry_run,
    )
    return {"offer": rogue_offer, "parsed": parsed, "rogue_mac": rogue_mac}


# ---------------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------------

def demo() -> None:
    print("[dhcp] Fixture discover parse ...")
    p = parse_dhcp(DHCP_DISCOVER)
    assert p["msg_type_str"] == "DISCOVER" and p["chaddr"] == "00:11:22:33:44:55"
    print(f"  OK — xid=0x{p['xid']:08x}, chaddr={p['chaddr']}")

    print("[dhcp] Fixture offer parse ...")
    p2 = parse_dhcp(DHCP_OFFER)
    assert p2["msg_type_str"] == "OFFER" and p2["yiaddr"] == "192.0.2.100"
    print(f"  OK — yiaddr={p2['yiaddr']}")

    print("[dhcp] Fixture request parse ...")
    p3 = parse_dhcp(DHCP_REQUEST)
    assert p3["msg_type_str"] == "REQUEST"
    print(f"  OK — xid=0x{p3['xid']:08x}")

    print("[dhcp] Fixture ACK parse ...")
    p4 = parse_dhcp(DHCP_ACK)
    assert p4["msg_type_str"] == "ACK"
    print(f"  OK — yiaddr={p4['yiaddr']}")

    print("[dhcp] Build + parse roundtrip ...")
    built = build_dhcp(xid=0xBEEF0001, chaddr="aa:bb:cc:dd:ee:ff", msg_type=1)
    bp = parse_dhcp(built)
    assert bp["xid"] == 0xBEEF0001 and bp["chaddr"] == "aa:bb:cc:dd:ee:ff"
    print(f"  OK — xid=0x{bp['xid']:08x}")

    print("[dhcp] Starvation sim (10 fake MACs) ...")
    starved = starvation_sim(10)
    assert len(starved) == 10
    macs = [s["mac"] for s in starved]
    assert len(set(macs)) == 10, "MACs not unique"
    print(f"  OK — {len(macs)} unique MACs starved")

    print("[dhcp] Rogue DHCP demo (dry-run) ...")
    r = rogue_dhcp_demo(dry_run=True)
    assert r["parsed"]["msg_type_str"] == "OFFER"
    print(f"  OK — rogue offer to {r['parsed']['yiaddr']}")

    print("[dhcp] All demos passed.")
