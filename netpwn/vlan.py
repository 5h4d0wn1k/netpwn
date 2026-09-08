"""VLAN hopping module — 802.1Q single/double tag builder/parser, anomaly detection."""

from __future__ import annotations

import struct

from .fixtures import VLAN_SINGLE_TAGGED, VLAN_DOUBLE_TAGGED

# 802.1Q TPID
TPID_8021Q = 0x8100

# ---------------------------------------------------------------------------
# Frame builder
# ---------------------------------------------------------------------------

def build_vlan_frame(
    eth_dst: str = "ff:ff:ff:ff:ff:ff",
    eth_src: str = "00:11:22:33:44:55",
    vid: int = 100,
    inner_vid: int | None = None,
    inner_ether_type: int = 0x0800,
    payload: bytes = b"",
    pcp: int = 0,
    dei: int = 0,
) -> bytes:
    """Build a single- or double-tagged 802.1Q Ethernet frame.

    If *inner_vid* is provided, a QinQ double-tagged frame is built.
    """
    dst = bytes(int(b, 16) for b in eth_dst.split(":"))
    src = bytes(int(b, 16) for b in eth_src.split(":"))
    frame = dst + src

    if inner_vid is not None:
        # Outer tag
        outer_tci = ((pcp << 13) | (dei << 12) | (inner_vid & 0x0FFF))
        frame += struct.pack("!HH", TPID_8021Q, outer_tci)
        # Inner tag
        inner_tci = ((pcp << 13) | (dei << 12) | (vid & 0x0FFF))
        frame += struct.pack("!HH", TPID_8021Q, inner_tci)
    else:
        tci = ((pcp << 13) | (dei << 12) | (vid & 0x0FFF))
        frame += struct.pack("!HH", TPID_8021Q, tci)

    frame += struct.pack("!H", inner_ether_type)
    frame += payload
    return frame


# ---------------------------------------------------------------------------
# Frame parser
# ---------------------------------------------------------------------------

def parse_vlan_frame(frame: bytes) -> dict:
    """Parse a single- or double-tagged 802.1Q frame."""
    if len(frame) < 14:
        raise ValueError(f"Frame too short: {len(frame)}")

    eth_dst = ":".join(f"{b:02x}" for b in frame[0:6])
    eth_src = ":".join(f"{b:02x}" for b in frame[6:12])
    ethertype = struct.unpack("!H", frame[12:14])[0]

    tags = []
    offset = 14
    double_tagged = False

    if ethertype == TPID_8021Q:
        tci = struct.unpack("!H", frame[14:16])[0]
        vid = tci & 0x0FFF
        pcp = (tci >> 13) & 0x07
        dei = (tci >> 12) & 0x01
        tags.append({"vid": vid, "pcp": pcp, "dei": dei})
        inner_ethtype = struct.unpack("!H", frame[16:18])[0]
        offset = 18

        if inner_ethtype == TPID_8021Q:
            # Double-tagged
            double_tagged = True
            tci2 = struct.unpack("!H", frame[18:20])[0]
            vid2 = tci2 & 0x0FFF
            pcp2 = (tci2 >> 13) & 0x07
            dei2 = (tci2 >> 12) & 0x01
            tags.append({"vid": vid2, "pcp": pcp2, "dei": dei2})
            final_ethertype = struct.unpack("!H", frame[20:22])[0]
            offset = 22
        else:
            final_ethertype = inner_ethtype
    else:
        final_ethertype = ethertype

    return {
        "eth_dst": eth_dst,
        "eth_src": eth_src,
        "tags": tags,
        "double_tagged": double_tagged,
        "ether_type": final_ethertype,
        "payload_offset": offset,
        "payload": frame[offset:],
        "total_tags": len(tags),
    }


# ---------------------------------------------------------------------------
# Anomaly detection
# ---------------------------------------------------------------------------

def detect_tag_anomalies(frame: bytes) -> list[str]:
    """Return a list of anomaly descriptions for the given VLAN frame."""
    anomalies = []
    parsed = parse_vlan_frame(frame)

    if parsed["double_tagged"]:
        if len(parsed["tags"]) >= 2:
            outer_vid = parsed["tags"][0]["vid"]
            inner_vid = parsed["tags"][1]["vid"]
            if outer_vid == inner_vid:
                anomalies.append(f"Double-tagged with same VID {outer_vid} on both tags")
            if outer_vid == 0:
                anomalies.append("Outer tag VID 0 (reserved)")
            if inner_vid == 0:
                anomalies.append("Inner tag VID 0 (reserved)")
        if len(parsed["tags"]) >= 3:
            anomalies.append("Triple-tagged frame (unexpected)")

    if parsed["total_tags"] == 1:
        vid = parsed["tags"][0]["vid"]
        if vid == 0:
            anomalies.append("Tag VID 0 (priority tagging, not VLAN)")
        if vid == 4095:
            anomalies.append("Tag VID 4095 (reserved)")

    return anomalies


# ---------------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------------

def demo() -> None:
    print("[vlan] Build single-tagged frame ...")
    f1 = build_vlan_frame(vid=100)
    p1 = parse_vlan_frame(f1)
    assert p1["tags"][0]["vid"] == 100
    assert not p1["double_tagged"]
    print(f"  OK — single tag VID={p1['tags'][0]['vid']}, {len(f1)} bytes")

    print("[vlan] Build double-tagged (QinQ) frame ...")
    f2 = build_vlan_frame(vid=100, inner_vid=200)
    p2 = parse_vlan_frame(f2)
    assert p2["double_tagged"]
    assert p2["tags"][0]["vid"] == 200  # outer
    assert p2["tags"][1]["vid"] == 100  # inner
    print(f"  OK — double tag outer={p2['tags'][0]['vid']} inner={p2['tags'][1]['vid']}")

    print("[vlan] Fixture single-tagged parse ...")
    fp1 = parse_vlan_frame(VLAN_SINGLE_TAGGED)
    assert fp1["tags"][0]["vid"] == 100
    print(f"  OK — fixture VID={fp1['tags'][0]['vid']}")

    print("[vlan] Fixture double-tagged parse ...")
    fp2 = parse_vlan_frame(VLAN_DOUBLE_TAGGED)
    assert fp2["double_tagged"] and fp2["tags"][0]["vid"] == 200
    print(f"  OK — fixture outer={fp2['tags'][0]['vid']} inner={fp2['tags'][1]['vid']}")

    print("[vlan] Anomaly detection ...")
    same_vid = build_vlan_frame(vid=100, inner_vid=100)
    anom = detect_tag_anomalies(same_vid)
    assert any("same VID" in a for a in anom)
    print(f"  OK — detected {len(anom)} anomalies in same-VID double tag")

    clean_anom = detect_tag_anomalies(f1)
    print(f"  OK — clean frame: {len(clean_anom)} anomalies")

    print("[vlan] All demos passed.")
