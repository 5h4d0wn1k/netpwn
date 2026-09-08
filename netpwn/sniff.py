"""Sniff module — minimal pcap reader, ARP/DHCP/DNS flow extraction, anomaly report."""

from __future__ import annotations

import os
import struct
import time

from .fixtures import (
    ARP_REQUEST, ARP_REPLY, ARP_GRATUITOUS,
    DHCP_DISCOVER, DHCP_OFFER, DHCP_REQUEST, DHCP_ACK,
    DNS_QUERY_A, DNS_RESPONSE_A, DNS_RESPONSE_MISMATCH,
    PCAP_GLOBAL_HEADER,
)

# ---------------------------------------------------------------------------
# Minimal pcap reader (native pcap, little-endian, Ethernet link-type)
# ---------------------------------------------------------------------------

class PcapReader:
    """Read a pcap file and yield individual packets."""

    def __init__(self, path: str):
        self.path = path
        self.file = open(path, "rb")
        self._read_global_header()

    def _read_global_header(self) -> None:
        data = self.file.read(24)
        if len(data) < 24:
            raise ValueError("Truncated pcap global header")
        magic, ver_maj, ver_min, _, _, snaplen, linktype = struct.unpack(
            "<IHHiIII", data
        )
        if magic != 0xA1B2C3D4:
            raise ValueError(f"Bad pcap magic: 0x{magic:08x}")
        self.linktype = linktype
        self.snaplen = snaplen

    def __iter__(self):
        return self

    def __next__(self) -> dict:
        rec_hdr = self.file.read(16)
        if len(rec_hdr) < 16:
            raise StopIteration
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack("<IIII", rec_hdr)
        data = self.file.read(incl_len)
        if len(data) < incl_len:
            raise StopIteration
        return {
            "timestamp": ts_sec + ts_usec / 1e6,
            "captured_len": incl_len,
            "original_len": orig_len,
            "data": data,
        }

    def close(self) -> None:
        self.file.close()


def create_pcap(packets: list[bytes], path: str) -> str:
    """Write packets to a pcap file. Returns the path."""
    with open(path, "wb") as f:
        f.write(PCAP_GLOBAL_HEADER)
        for pkt in packets:
            now = int(time.time())
            rec = struct.pack("<IIII", now, 0, len(pkt), len(pkt))
            f.write(rec + pkt)
    return path


# ---------------------------------------------------------------------------
# Flow extraction
# ---------------------------------------------------------------------------

def wrap_udp(payload: bytes, src_port: int, dst_port: int, *,
             src_ip: str = "192.0.2.1", dst_ip: str = "192.0.2.2") -> bytes:
    """Wrap a UDP payload in Ethernet+IPv4+UDP headers (for pcap fixtures)."""
    src_mac = "001122334455"
    dst_mac = "aabbccddeeff"
    eth = bytes.fromhex(dst_mac + src_mac + "0800")
    udp_len = 8 + len(payload)
    udp = struct.pack("!HHHH", src_port, dst_port, udp_len, 0) + payload
    ip_tot_len = 20 + udp_len
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, ip_tot_len, 0, 0x4000, 64, 17, 0,
        __import__("socket").inet_aton(src_ip),
        __import__("socket").inet_aton(dst_ip),
    )
    # IP checksum
    if len(ip) % 2:
        ip += b"\x00"
    s = 0
    for i in range(0, len(ip), 2):
        s += (ip[i] << 8) | ip[i + 1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    checksum = ~s & 0xFFFF
    ip = ip[:10] + struct.pack("!H", checksum) + ip[12:]
    return eth + ip + udp


def extract_flows(packets: list[bytes]) -> dict:
    """Extract ARP, DHCP, and DNS flows from raw Ethernet frames."""
    flows = {"arp": [], "dhcp": [], "dns": []}

    for pkt in packets:
        if len(pkt) < 14:
            continue

        # Raw BOOTP/DHCP (no Ethernet header) detection via magic cookie
        if len(pkt) >= 240 and pkt[236:240] == bytes.fromhex("63825363"):
            from .dhcp import parse_dhcp
            try:
                flows["dhcp"].append(parse_dhcp(pkt))
            except Exception:
                pass
            continue

        ethertype = struct.unpack("!H", pkt[12:14])[0]

        if ethertype == 0x0806:
            # ARP
            from .arp import parse_arp
            try:
                parsed = parse_arp(pkt)
                flows["arp"].append(parsed)
            except Exception:
                pass

        elif ethertype == 0x0800:
            # IPv4 — check for UDP (DHCP/DNS)
            if len(pkt) < 34:
                continue
            ip_hdr = pkt[14:]
            proto = ip_hdr[9]
            if proto == 17:  # UDP
                udp_src = struct.unpack("!H", ip_hdr[20:22])[0]
                udp_dst = struct.unpack("!H", ip_hdr[22:24])[0]
                payload = ip_hdr[28:]

                if udp_src in (67, 68) or udp_dst in (67, 68):
                    # DHCP
                    from .dhcp import parse_dhcp
                    try:
                        parsed = parse_dhcp(payload)
                        flows["dhcp"].append(parsed)
                    except Exception:
                        pass

                if udp_src == 53 or udp_dst == 53:
                    # DNS
                    from .dns import parse_dns
                    try:
                        parsed = parse_dns(payload)
                        flows["dns"].append(parsed)
                    except Exception:
                        pass

    return flows


# ---------------------------------------------------------------------------
# Anomaly detection across flows
# ---------------------------------------------------------------------------

def detect_anomalies(flows: dict) -> list[dict]:
    """Detect ARP conflicts, DHCP starvation, DNS ID mismatches."""
    anomalies = []

    # ARP: check for multiple senders claiming same IP
    arp_ips: dict[str, list[str]] = {}
    for a in flows.get("arp", []):
        ip = a.get("sender_ip", "")
        mac = a.get("sender_mac", "")
        arp_ips.setdefault(ip, []).append(mac)
    for ip, macs in arp_ips.items():
        if len(set(macs)) > 1:
            anomalies.append({
                "type": "ARP_CONFLICT",
                "severity": "HIGH",
                "detail": f"IP {ip} claimed by {len(set(macs))} MACs: {set(macs)}",
            })

    # ARP: gratuitous ARP
    gratuitous = [a for a in flows.get("arp", []) if a.get("target_ip") == a.get("sender_ip") and a.get("opcode") == 1]
    if gratuitous:
        anomalies.append({
            "type": "ARP_GRATUITOUS",
            "severity": "MEDIUM",
            "detail": f"{len(gratuitous)} gratuitous ARP(s) detected",
        })

    # DHCP: starvation (many unique MACs, same xid pattern)
    dhcp_discovers = [d for d in flows.get("dhcp", []) if d.get("msg_type_str") == "DISCOVER"]
    if len(dhcp_discovers) > 5:
        unique_macs = set(d["chaddr"] for d in dhcp_discovers)
        anomalies.append({
            "type": "DHCP_STARVATION",
            "severity": "HIGH",
            "detail": f"{len(dhcp_discovers)} DISCOVERs from {len(unique_macs)} MACs",
        })

    # DNS: ID mismatches
    dns_ids: dict[int, list[dict]] = {}
    for d in flows.get("dns", []):
        if d.get("is_response"):
            dns_ids.setdefault(d["tx_id"], []).append(d)
    for tx_id, responses in dns_ids.items():
        if len(responses) > 1:
            # Check if all answers are the same
            answer_ips = [r["answers"][0]["rdata"] for r in responses if r["answers"]]
            if len(set(answer_ips)) > 1:
                anomalies.append({
                    "type": "DNS_ID_REUSE",
                    "severity": "HIGH",
                    "detail": f"DNS ID 0x{tx_id:04x} has {len(answer_ips)} different answers: {answer_ips}",
                })

    # DNS: off-by-one ID (spoof indicator)
    dns_responses = [d for d in flows.get("dns", []) if d.get("is_response")]
    ids = set(d["tx_id"] for d in dns_responses)
    for id1 in ids:
        for id2 in ids:
            if id1 != id2 and abs(id1 - id2) == 1:
                anomalies.append({
                    "type": "DNS_SPOOF_SUSPECTED",
                    "severity": "CRITICAL",
                    "detail": f"DNS IDs 0x{id1:04x} and 0x{id2:04x} differ by 1 (off-by-one spoof pattern)",
                })

    return anomalies


# ---------------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------------

def demo() -> None:
    import tempfile

    print("[sniff] Create test pcap with ARP+DHCP+DNS fixtures ...")
    pcap_path = os.path.join(tempfile.gettempdir(), "netpwn_test.pcap")
    create_pcap([
        ARP_REQUEST, ARP_REPLY,
        wrap_udp(DHCP_DISCOVER, 68, 67),
        wrap_udp(DHCP_OFFER, 67, 68),
        wrap_udp(DNS_QUERY_A, 53000, 53),
        wrap_udp(DNS_RESPONSE_A, 53, 53000),
    ], pcap_path)

    print("[sniff] Read pcap file ...")
    reader = PcapReader(pcap_path)
    pkts = list(reader)
    reader.close()
    assert len(pkts) == 6, f"Expected 6 packets, got {len(pkts)}"
    print(f"  OK — {len(pkts)} packets read")

    print("[sniff] Extract flows ...")
    raw_packets = [p["data"] for p in pkts]
    flows = extract_flows(raw_packets)
    assert len(flows["arp"]) == 2, f"Expected 2 ARP, got {len(flows['arp'])}"
    assert len(flows["dhcp"]) == 2, f"Expected 2 DHCP, got {len(flows['dhcp'])}"
    assert len(flows["dns"]) == 2, f"Expected 2 DNS, got {len(flows['dns'])}"
    print(f"  OK — ARP={len(flows['arp'])}, DHCP={len(flows['dhcp'])}, DNS={len(flows['dns'])}")

    print("[sniff] Anomaly detection on clean fixtures ...")
    anomalies = detect_anomalies(flows)
    # Clean fixtures should have no anomalies (each ID used once, unique IPs)
    print(f"  OK — {len(anomalies)} anomalies detected")

    print("[sniff] Anomaly detection with spoof pattern ...")
    dirty_flows = {
        "arp": [flows["arp"][0], flows["arp"][0]],  # duplicate IP claim
        "dhcp": flows["dhcp"],
        "dns": flows["dns"] + [{"tx_id": 0xABCE, "is_response": True,  # off-by-one from 0xABCD
                                 "answers": [{"rdata": "10.0.0.1"}]}],
    }
    dirty_anom = detect_anomalies(dirty_flows)
    assert len(dirty_anom) > 0
    print(f"  OK — {len(dirty_anom)} anomalies detected in dirty flow set")

    os.unlink(pcap_path)
    print("[sniff] All demos passed.")
