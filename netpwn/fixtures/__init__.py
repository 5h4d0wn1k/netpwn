"""Byte-exact fixture packets for offline testing and demos."""

from __future__ import annotations

import struct

# ---------------------------------------------------------------------------
# ARP fixtures
# ---------------------------------------------------------------------------

# ARP request: who-has 192.0.2.10 tell 192.0.2.1
ARP_REQUEST = bytes.fromhex(
    "ffffffffffff"          # dst broadcast
    "001122334455"          # src MAC 00:11:22:33:44:55
    "0806"                  # EtherType ARP
    "0001"                  # hw type Ethernet
    "0800"                  # proto IPv4
    "06"                    # hw size
    "04"                    # proto size
    "0001"                  # opcode request
    "001122334455"          # sender MAC
    "c000020a"              # sender IP 192.0.2.10
    "000000000000"          # target MAC (unknown)
    "c0000201"              # target IP 192.0.2.1
)

ARP_REPLY = bytes.fromhex(
    "001122334455"          # dst = original src
    "aabbccddeeff"          # src MAC aa:bb:cc:dd:ee:ff
    "0806"
    "0001" "0800" "06" "04"
    "0002"                  # opcode reply
    "aabbccddeeff"          # sender MAC
    "c0000201"              # sender IP 192.0.2.1
    "001122334455"          # target MAC
    "c000020a"              # target IP 192.0.2.10
)

# Gratuitous ARP (announcement)
ARP_GRATUITOUS = bytes.fromhex(
    "ffffffffffff"
    "aabbccddeeff"
    "0806"
    "0001" "0800" "06" "04"
    "0001"                  # opcode request
    "aabbccddeeff"
    "c0000201"
    "aabbccddeeff"          # target = self (gratuitous)
    "c0000201"
)

# ---------------------------------------------------------------------------
# DHCP fixtures  (BOOTP wire format, options after cookie)
# ---------------------------------------------------------------------------

def _dhcp_pkt(op: int, yiaddr: str, options_hex: str,
              chaddr: str = "001122334455") -> bytes:
    """Build a 300-byte DHCP packet from fields.

    Layout: 28B header + 16B (chaddr+pad) + 64B sname + 128B file = 236B,
    then cookie + options, padded to 300B.
    """
    import socket as _socket
    hdr = bytes.fromhex(
        f"{op:02x}016300"                     # op, htype, hlen, hops
        "12345678"                             # xid
        "00008000"                             # secs, flags
        "00000000"                             # ciaddr
        + _socket.inet_aton(yiaddr).hex()      # yiaddr
        + "0000000000000000"                   # siaddr, giaddr
        + chaddr                               # chaddr
        + "00000000000000000000"               # pad (10B)
    )
    pkt = hdr + b"\x00" * 64 + b"\x00" * 128   # sname + file
    pkt += bytes.fromhex("63825363" + options_hex)
    if len(pkt) < 300:
        pkt += b"\x00" * (300 - len(pkt))
    return pkt


DHCP_DISCOVER = _dhcp_pkt(1, "0.0.0.0", "350101" "ff")
DHCP_OFFER = _dhcp_pkt(2, "192.0.2.100",
                       "350102" "0104ffffff00" "3604c0000201" "ff")
DHCP_REQUEST = _dhcp_pkt(1, "0.0.0.0",
                         "350103" "3204c0000264" "3604c0000201" "ff")
DHCP_ACK = _dhcp_pkt(2, "192.0.2.100",
                     "350105" "0104ffffff00" "0304c0000201" "0604c0000201" "ff")


# ---------------------------------------------------------------------------
# DNS fixtures  (ID preserved for round-trip)
# ---------------------------------------------------------------------------

DNS_QUERY_A = bytes.fromhex(
    "abcd"                  # Transaction ID
    "0100"                  # Flags: standard query
    "0001"                  # Questions: 1
    "0000" "0000" "0000"    # Answer/Auth/Additional
    "03" "77" "77" "77"     # www
    "06" "67" "6f" "6f"     # goo
    "67" "6c" "65"          # gle
    "03" "63" "6f" "6d"     # com
    "00"                    # root
    "0001"                  # type A
    "0001"                  # class IN
)

DNS_RESPONSE_A = bytes.fromhex(
    "abcd"                  # Transaction ID (matches query)
    "8180"                  # Flags: response, no error
    "0001"                  # Questions: 1
    "0001"                  # Answers: 1
    "0000" "0000"
    "03" "77" "77" "77"
    "06" "67" "6f" "6f"
    "67" "6c" "65"
    "03" "63" "6f" "6d"
    "00"
    "0001" "0001"
    # Answer
    "c00c"                  # pointer to name
    "0001"                  # type A
    "0001"                  # class IN
    "000000ff"              # TTL 255
    "0004"                  # rdlength 4
    "8efa2e11"              # 142.250.46.17
)

# Off-by-one ID mismatch: tx_id 0xABCD -> 0xABCE (differs by 1, spoof indicator)
DNS_RESPONSE_MISMATCH = bytearray(DNS_RESPONSE_A)
DNS_RESPONSE_MISMATCH[1] = (DNS_RESPONSE_MISMATCH[1] + 1) & 0xFF  # low byte +1
DNS_RESPONSE_MISMATCH = bytes(DNS_RESPONSE_MISMATCH)

# Second valid response with same ID (rebind test)
DNS_RESPONSE_REBIND = bytearray(DNS_RESPONSE_A)
DNS_RESPONSE_REBIND[44:48] = bytes.fromhex("0a000001")  # answer: 10.0.0.1
DNS_RESPONSE_REBIND = bytes(DNS_RESPONSE_REBIND)

# ---------------------------------------------------------------------------
# 802.1Q VLAN fixtures
# ---------------------------------------------------------------------------

# Single-tagged frame
VLAN_SINGLE_TAGGED = bytes.fromhex(
    "ffffffffffff"          # dst broadcast
    "001122334455"          # src
    "8100"                  # 802.1Q TPID
    "0064"                  # VID 100, PCP 0, DEI 0
    "0800"                  # inner EtherType IPv4
    "45000028"              # IPv4 header start...
    "00004000"
    "4006"
    "0000"                  # checksum placeholder
    "c0000201"              # src 192.0.2.1
    "c0000202"              # dst 192.0.2.2
    "0000000000000000000000000000000000000000"  # TCP header placeholder (20 bytes)
)

# Double-tagged (QinQ) frame
VLAN_DOUBLE_TAGGED = bytes.fromhex(
    "ffffffffffff"
    "001122334455"
    "8100"                  # outer tag: VLAN 200
    "00c8"
    "8100"                  # inner tag: VLAN 100
    "0064"
    "0800"
    "45000028"
    "00004000"
    "4006"
    "0000"
    "c0000201"
    "c0000202"
    "0000000000000000000000000000000000000000"  # TCP header placeholder (20 bytes)
)

# ---------------------------------------------------------------------------
# IP spoofed ICMP echo (forged src)
# ---------------------------------------------------------------------------
IP_SPOOFED_ICMP = bytes.fromhex(
    "ffffffffffff"          # broadcast dst
    "001122334455"          # src
    "0800"                  # IPv4
    "4500001c"              # ver=4, ihl=5, len=28
    "00004000"
    "4001"                  # TTL=64, proto ICMP
    "0000"                  # checksum (fill in)
    "c00002ff"              # forged src 192.0.2.255
    "7f000001"              # dst 127.0.0.1
    "0800"                  # ICMP echo request
    "0000"
    "0001" "0001"           # id, seq
)

# ---------------------------------------------------------------------------
# Port-knock fixture sequence
# ---------------------------------------------------------------------------
KNOCK_PORTS = [7000, 8000, 9000]
SECRET_PORT = 9999
KNOCK_SECRET = b"SECRET-UNLOCKED"

# ---------------------------------------------------------------------------
# Minimal pcap header (little-endian, link-type Ethernet = 1)
# ---------------------------------------------------------------------------
PCAP_GLOBAL_HEADER = struct.pack(
    "<IHHiIII",
    0xa1b2c3d4,  # magic
    2, 4,         # version
    0,            # timezone
    0,            # sigfigs
    65535,        # snaplen
    1,            # link-layer: Ethernet
)
