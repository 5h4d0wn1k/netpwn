"""DNS module — build/parse queries/responses, spoof detection, rebinding demo."""

from __future__ import annotations

import socket
import struct
from typing import Optional

from .fixtures import (
    DNS_QUERY_A, DNS_RESPONSE_A, DNS_RESPONSE_MISMATCH, DNS_RESPONSE_REBIND,
)
from . import safety

# ---------------------------------------------------------------------------
# DNS header parser/builder
# ---------------------------------------------------------------------------

def _dns_name_decode(data: bytes, offset: int) -> tuple[str, int]:
    """Decode a DNS name from *data* starting at *offset*."""
    labels = []
    jumped = False
    orig_offset = offset
    while offset < len(data):
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if (length & 0xC0) == 0xC0:
            if not jumped:
                orig_offset = offset + 2
            pointer = struct.unpack("!H", data[offset : offset + 2])[0] & 0x3FFF
            offset = pointer
            jumped = True
            continue
        offset += 1
        labels.append(data[offset : offset + length].decode("ascii", errors="replace"))
        offset += length
    return ".".join(labels), orig_offset if jumped else offset


def _dns_name_encode(name: str) -> bytes:
    """Encode a domain name into DNS wire format."""
    parts = name.rstrip(".").split(".")
    result = b""
    for label in parts:
        result += bytes([len(label)]) + label.encode("ascii")
    result += b"\x00"
    return result


def parse_dns(data: bytes) -> dict:
    """Parse a DNS message (query or response)."""
    if len(data) < 12:
        raise ValueError(f"DNS message too short: {len(data)}")
    tx_id = struct.unpack("!H", data[0:2])[0]
    flags = struct.unpack("!H", data[2:4])[0]
    qdcount = struct.unpack("!H", data[4:6])[0]
    ancount = struct.unpack("!H", data[6:8])[0]
    nscount = struct.unpack("!H", data[8:10])[0]
    arcount = struct.unpack("!H", data[10:12])[0]

    is_response = bool(flags & 0x8000)
    rcode = flags & 0x0F
    opcode = (flags >> 11) & 0xF

    # Parse questions
    offset = 12
    questions = []
    for _ in range(qdcount):
        qname, offset = _dns_name_decode(data, offset)
        if offset + 4 > len(data):
            break
        qtype, qclass = struct.unpack("!HH", data[offset : offset + 4])
        offset += 4
        questions.append({"name": qname, "type": qtype, "class": qclass})

    # Parse answers
    answers = []
    for _ in range(ancount):
        name, offset = _dns_name_decode(data, offset)
        if offset + 10 > len(data):
            break
        rtype, rclass, ttl, rdlength = struct.unpack(
            "!HHIH", data[offset : offset + 10]
        )
        offset += 10
        rdata_raw = data[offset : offset + rdlength]
        offset += rdlength

        rdata_str = ""
        if rtype == 1 and rdlength == 4:  # A record
            rdata_str = socket.inet_ntoa(rdata_raw)
        elif rtype == 28 and rdlength == 16:  # AAAA
            rdata_str = socket.inet_ntop(socket.AF_INET6, rdata_raw)
        elif rtype == 5:  # CNAME
            cname, _ = _dns_name_decode(data, offset - rdlength)
            rdata_str = cname

        answers.append({
            "name": name,
            "type": rtype,
            "class": rclass,
            "ttl": ttl,
            "rdlength": rdlength,
            "rdata": rdata_str,
        })

    return {
        "tx_id": tx_id,
        "flags": flags,
        "is_response": is_response,
        "opcode": opcode,
        "rcode": rcode,
        "qdcount": qdcount,
        "ancount": ancount,
        "questions": questions,
        "answers": answers,
    }


def build_dns_query(name: str, qtype: int = 1, tx_id: int = 0x1234) -> bytes:
    """Build a DNS A-record query."""
    header = struct.pack("!HHHHHH", tx_id, 0x0100, 1, 0, 0, 0)
    qname = _dns_name_encode(name)
    question = struct.pack("!HH", qtype, 1)  # type A, class IN
    return header + qname + question


def build_dns_response(
    name: str,
    answers: list[tuple[str, int, int, bytes]],
    tx_id: int = 0x1234,
    flags: int = 0x8180,
) -> bytes:
    """Build a DNS response. *answers* = [(ip_str, ttl, rdlength, rdata_raw), ...]."""
    header = struct.pack("!HHHHHH", tx_id, flags, 1, len(answers), 0, 0)
    qname = _dns_name_encode(name)
    question = struct.pack("!HH", 1, 1)  # type A, class IN
    resp = header + qname + question
    for ip_str, ttl, rdl, rdata in answers:
        resp += b"\xc0\x0c"  # pointer to name
        resp += struct.pack("!HHIH", 1, 1, ttl, rdl)
        resp += rdata
    return resp


# ---------------------------------------------------------------------------
# Spoof detection
# ---------------------------------------------------------------------------

def detect_dns_spoof(
    expected_id: int,
    responses: list[bytes],
) -> list[dict]:
    """Check a list of DNS responses for spoof indicators.

    Returns a list of dicts with 'valid', 'reason' fields.
    """
    results = []
    for raw in responses:
        parsed = parse_dns(raw)
        if parsed["tx_id"] != expected_id:
            results.append({
                "valid": False,
                "reason": f"ID mismatch: got {parsed['tx_id']:#06x}, expected {expected_id:#06x}",
                "tx_id": parsed["tx_id"],
            })
        elif not parsed["is_response"]:
            results.append({"valid": False, "reason": "Not a response packet", "tx_id": parsed["tx_id"]})
        else:
            results.append({"valid": True, "reason": "OK", "tx_id": parsed["tx_id"]})
    return results


# ---------------------------------------------------------------------------
# Rebinding demo
# ---------------------------------------------------------------------------

def rebinding_demo() -> dict:
    """Demonstrate DNS rebinding: same ID, different answer IPs."""
    # First legitimate response
    r1 = parse_dns(DNS_RESPONSE_A)
    # Second response with same ID but different IP
    r2 = parse_dns(DNS_RESPONSE_REBIND)

    assert r1["tx_id"] == r2["tx_id"], "Rebind responses must share tx_id"
    ip1 = r1["answers"][0]["rdata"] if r1["answers"] else None
    ip2 = r2["answers"][0]["rdata"] if r2["answers"] else None
    rebound = ip1 != ip2

    return {
        "tx_id": r1["tx_id"],
        "first_ip": ip1,
        "second_ip": ip2,
        "rebound": rebound,
    }


# ---------------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------------

def demo() -> None:
    print("[dns] Build + parse query roundtrip ...")
    q = build_dns_query("www.example.com", tx_id=0xABCD)
    pq = parse_dns(q)
    assert pq["tx_id"] == 0xABCD
    assert pq["questions"][0]["name"] == "www.example.com"
    print(f"  OK — query id=0x{pq['tx_id']:04x}, qname={pq['questions'][0]['name']}")

    print("[dns] Fixture query parse ...")
    fq = parse_dns(DNS_QUERY_A)
    assert fq["tx_id"] == 0xABCD
    assert fq["questions"][0]["name"] == "www.google.com"
    print(f"  OK — {fq['questions'][0]['name']}")

    print("[dns] Fixture response parse ...")
    fr = parse_dns(DNS_RESPONSE_A)
    assert fr["tx_id"] == 0xABCD and fr["answers"][0]["rdata"] == "142.250.46.17"
    print(f"  OK — answer={fr['answers'][0]['rdata']}, ttl={fr['answers'][0]['ttl']}")

    print("[dns] Spoof detection: ID mismatch ...")
    results = detect_dns_spoof(0xABCD, [DNS_RESPONSE_A, DNS_RESPONSE_MISMATCH])
    assert results[0]["valid"] is True
    assert results[1]["valid"] is False and "mismatch" in results[1]["reason"]
    print(f"  OK — {sum(1 for r in results if r['valid'])}/{len(results)} valid, "
          f"{sum(1 for r in results if not r['valid'])} flagged")

    print("[dns] Rebinding demo ...")
    rb = rebinding_demo()
    assert rb["rebound"], "Expected rebinding"
    print(f"  OK — {rb['first_ip']} -> {rb['second_ip']} (rebound={rb['rebound']})")

    print("[dns] All demos passed.")
