"""Port knock engine — SYN knock sequence opens secret port on localhost."""

from __future__ import annotations

import socket
import struct
import threading
import time

from .fixtures import KNOCK_PORTS, SECRET_PORT, KNOCK_SECRET
from . import safety

# ---------------------------------------------------------------------------
# TCP SYN packet builder
# ---------------------------------------------------------------------------

def build_syn(dst_ip: str, dst_port: int, src_port: int = 0, seq: int = 1000) -> bytes:
    """Build a minimal TCP SYN packet (IP + TCP only, no Ethernet header)."""
    if src_port == 0:
        src_port = 40000 + (dst_port % 1000)
    # Pseudo-header + TCP
    tcp_hdr_len = 20
    flags = 0x02  # SYN
    tcp = struct.pack(
        "!HHIIBBHHH",
        src_port,
        dst_port,
        seq,
        0,              # ack
        (5 << 4),       # data offset (5 * 4 = 20)
        flags,
        65535,          # window
        0,              # checksum (placeholder)
        0,              # urgent
    )
    # Compute TCP checksum
    src = socket.inet_aton(dst_ip)
    dst = socket.inet_aton("127.0.0.1")
    pseudo = struct.pack("!4s4sBBH", src, dst, 0, 6, tcp_hdr_len)
    csum = _tcp_checksum(pseudo + tcp)
    tcp = tcp[:16] + struct.pack("!H", csum) + tcp[18:]
    return tcp


def _tcp_checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) | data[i + 1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


# ---------------------------------------------------------------------------
# Port-knock listener
# ---------------------------------------------------------------------------

class KnockListener:
    """TCP listener on *secret_port* that only accepts clients who knock correctly."""

    def __init__(
        self,
        knock_ports: list[int] | None = None,
        secret_port: int = SECRET_PORT,
        secret: bytes = KNOCK_SECRET,
        host: str = "127.0.0.1",
    ):
        self.knock_ports = knock_ports or list(KNOCK_PORTS)
        self.secret_port = secret_port
        self.secret = secret
        self.host = host
        self._knocked: dict[str, list[int]] = {}
        self._server_sock: socket.socket | None = None
        self._running = False
        self._accepted = False

    def _is_knocked(self, addr: str) -> bool:
        knocked = self._knocked.get(addr, [])
        return sorted(knocked) == sorted(self.knock_ports)

    def handle_syn_on_knock_port(self, port: int, src_addr: str) -> None:
        """Called when a SYN arrives on a knock port (simulated)."""
        self._knocked.setdefault(src_addr, [])
        if port not in self._knocked[src_addr]:
            self._knocked[src_addr].append(port)

    def start(self) -> None:
        """Start the secret-port listener in a background thread."""
        self._running = True
        self._server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_sock.settimeout(2.0)
        self._server_sock.bind((self.host, self.secret_port))
        self._server_sock.listen(1)

    def accept_once(self, timeout: float = 2.0) -> str | None:
        """Accept one connection and send the secret if knock sequence verified."""
        if not self._server_sock:
            return None
        try:
            conn, addr = self._server_sock.accept()
            if self._is_knocked(addr[0]):
                conn.sendall(self.secret)
                self._accepted = True
                conn.close()
                return f"ACCEPTED:{addr[0]}"
            else:
                conn.sendall(b"NOPE")
                conn.close()
                return f"REJECTED:{addr[0]}"
        except socket.timeout:
            return None

    def stop(self) -> None:
        self._running = False
        if self._server_sock:
            self._server_sock.close()
            self._server_sock = None


# ---------------------------------------------------------------------------
# Knock sender
# ---------------------------------------------------------------------------

def send_knock(
    target: str = "127.0.0.1",
    ports: list[int] | None = None,
    dry_run: bool = True,
) -> dict:
    """Send a SYN-knock sequence to *target*.

    In dry-run mode, just builds the packets and returns them.
    """
    ports = ports or list(KNOCK_PORTS)
    if dry_run:
        packets = []
        for p in ports:
            pkt = build_syn(target, p)
            packets.append({"port": p, "packet_len": len(pkt)})
        safety.dry_action(
            f"Knock sequence: SYN to {target} ports {ports}", dry_run=True
        )
        return {"mode": "dry-run", "knock_ports": ports, "packets": packets}

    # Real send via TCP connect (actual SYN)
    for p in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            s.connect_ex((target, p))
            s.close()
        except Exception:
            pass
    return {"mode": "live", "knock_ports": ports}


# ---------------------------------------------------------------------------
# End-to-end test over loopback
# ---------------------------------------------------------------------------

def knock_e2e_test(
    host: str = "127.0.0.1",
    ports: list[int] | None = None,
    secret_port: int = SECRET_PORT,
    secret: bytes = KNOCK_SECRET,
) -> dict:
    """Run full knock sequence on loopback using real TCP sockets.

    Starts a listener, knocks, verifies secret arrives.
    """
    ports = ports or list(KNOCK_PORTS)

    # Bind listener on the secret port
    listener = KnockListener(
        knock_ports=ports,
        secret_port=secret_port,
        secret=secret,
        host=host,
    )
    try:
        listener.start()
    except OSError as e:
        return {"ok": False, "error": f"Cannot bind: {e}"}

    # Send knock SYN packets via TCP connect-ex
    time.sleep(0.1)
    for p in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            s.connect_ex((host, p))
            # Register the knock in the listener
            listener.handle_syn_on_knock_port(p, host)
            s.close()
        except Exception:
            pass

    time.sleep(0.1)
    # Start a thread to accept the connection on the secret port.
    import threading as _threading
    result_holder = {}

    def _accept_worker():
        res = listener.accept_once(timeout=3.0)
        result_holder["result"] = res

    worker = _threading.Thread(target=_accept_worker, daemon=True)
    worker.start()

    # Connect to the secret port and read the response
    accepted = False
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3.0)
        s.connect((host, secret_port))
        data = s.recv(1024)
        s.close()
        accepted = (data == secret)
    except (socket.timeout, ConnectionRefusedError, OSError):
        accepted = False

    worker.join(timeout=4.0)
    listener.stop()

    return {
        "ok": accepted,
        "result": result_holder.get("result"),
        "secret_matched": accepted,
    }


# ---------------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------------

def demo() -> None:
    print("[knock] Build knock sequence (dry-run) ...")
    r = send_knock(dry_run=True)
    assert r["mode"] == "dry-run" and len(r["packets"]) == 3
    print(f"  OK — {len(r['packets'])} packets built for ports {r['knock_ports']}")

    print("[knock] TCP SYN builder ...")
    syn = build_syn("127.0.0.1", 7000)
    assert len(syn) == 20  # 20-byte TCP header
    print(f"  OK — {len(syn)}-byte TCP SYN to port 7000")

    print("[knock] End-to-end knock test on loopback ...")
    e2e = knock_e2e_test()
    assert e2e["ok"], f"E2E knock failed: {e2e}"
    print(f"  OK — secret port accepted: {e2e['result']}")

    print("[knock] All demos passed.")
