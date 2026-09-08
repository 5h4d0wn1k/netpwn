"""Safety gating — lab allowlist, dry-run enforcement, interface checks."""

from __future__ import annotations

import ipaddress
import os
import socket
import struct
import fcntl

# ---------------------------------------------------------------------------
# RFC 5737 documentation-only networks (never real)
# ---------------------------------------------------------------------------
DOC_NETS = [
    ipaddress.ip_network("192.0.2.0/24"),   # TEST-NET-1
    ipaddress.ip_network("198.51.100.0/24"), # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),  # TEST-NET-3
]

LOOPBACK_ADDRS = {
    "127.0.0.0/8",
    "::1/128",
}

# ---------------------------------------------------------------------------
# Lab allowlist loading
# ---------------------------------------------------------------------------

def _default_allowlist_path() -> str:
    return os.path.join(os.path.dirname(__file__), "lab_allowlist.conf")


def load_allowlist(path: str | None = None) -> set[str]:
    """Return the set of permitted interface names / CIDRs."""
    path = path or _default_allowlist_path()
    allowed: set[str] = set()
    if os.path.isfile(path):
        with open(path) as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#"):
                    allowed.add(line)
    return allowed


def iface_allowed(iface: str, allowlist: set[str]) -> bool:
    if iface in allowlist:
        return True
    for entry in allowlist:
        try:
            net = ipaddress.ip_network(entry, strict=False)
            try:
                if ipaddress.ip_address(iface) in net:
                    return True
            except ValueError:
                pass
        except ValueError:
            pass
    return False


# ---------------------------------------------------------------------------
# Guard: raise if live action attempted without gates
# ---------------------------------------------------------------------------

class LiveActionBlocked(Exception):
    """Raised when a live-network action is attempted without proper gating."""


def require_live_gate(iface: str | None, yes: bool,
                      allowlist: set[str] | None = None,
                      dry_run: bool = True) -> str:
    """Validate all gates for a live action.

    Returns the interface name on success, raises LiveActionBlocked otherwise.
    """
    if dry_run:
        raise LiveActionBlocked(
            "DRY-RUN: would perform live action. "
            "Remove --dry-run and supply --iface + --yes + --lab-allowlist."
        )
    if not iface:
        raise LiveActionBlocked("--iface is required for live actions.")
    if not yes:
        raise LiveActionBlocked("--yes confirmation flag is required.")
    if allowlist is None:
        allowlist = load_allowlist()
    if not allowlist:
        raise LiveActionBlocked(
            "--lab-allowlist path must contain at least one entry."
        )
    if not iface_allowed(iface, allowlist):
        raise LiveActionBlocked(
            f"Interface '{iface}' is not in the lab allowlist."
        )
    return iface


# ---------------------------------------------------------------------------
# Localhost / loopback helpers
# ---------------------------------------------------------------------------

def is_loopback(iface: str) -> bool:
    """Best-effort check if *iface* or *iface* looks loopback."""
    if iface in ("lo", "lo0", "loopback"):
        return True
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)
        try:
            info = fcntl.ioctl(
                s.fileno(),
                0x8915,  # SIOCGIFADDR
                struct.pack("256s", iface[:15].encode("utf-8")),
            )
            addr = socket.inet_ntoa(info[20:24])
            return ipaddress.ip_address(addr).is_loopback
        except OSError:
            return False
        finally:
            s.close()
    except Exception:
        return False


# ---------------------------------------------------------------------------
# MAC utilities
# ---------------------------------------------------------------------------

def mac_bytes(mac_str: str) -> bytes:
    """Convert 'AA:BB:CC:DD:EE:FF' -> 6 raw bytes."""
    return bytes(int(b, 16) for b in mac_str.split(":"))


def mac_str(data: bytes) -> str:
    """6 raw bytes -> 'AA:BB:CC:DD:EE:FF'."""
    return ":".join(f"{b:02x}" for b in data[:6])


def random_mac(seed: int | None = None) -> str:
    """Deterministic random MAC for offline testing."""
    import hashlib
    h = hashlib.sha256(struct.pack("<Q", seed if seed is not None else 0)).digest()
    b = bytearray(h[:6])
    b[0] = (b[0] & 0xFE) | 0x02  # locally-administered, unicast
    return mac_str(bytes(b))


# ---------------------------------------------------------------------------
# Dry-run printer
# ---------------------------------------------------------------------------

def dry_action(msg: str, dry_run: bool = True) -> None:
    """Print what *would* happen in dry-run mode."""
    if dry_run:
        print(f"[DRY-RUN] {msg}")
