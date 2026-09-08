"""MITM core — interception pipeline over loopback, capture store, dry-run gate."""

from __future__ import annotations

import json
import os
import socket
import sqlite3
import struct
import time
from typing import Optional

from . import safety

# ---------------------------------------------------------------------------
# Capture store (SQLite)
# ---------------------------------------------------------------------------

class CaptureStore:
    """Simple SQLite store for captured packets."""

    def __init__(self, db_path: str = ":memory:"):
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self._init_db()

    def _init_db(self) -> None:
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS captures (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL,
                src_mac TEXT,
                dst_mac TEXT,
                ethertype INTEGER,
                length INTEGER,
                data BLOB,
                description TEXT
            )
        """)
        self.conn.commit()

    def insert(self, *, src_mac: str = "", dst_mac: str = "",
               ethertype: int = 0, length: int = 0,
               data: bytes = b"", description: str = "") -> int:
        cur = self.conn.execute(
            "INSERT INTO captures (timestamp, src_mac, dst_mac, ethertype, length, data, description) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (time.time(), src_mac, dst_mac, ethertype, length, data, description),
        )
        self.conn.commit()
        return cur.lastrowid

    def count(self) -> int:
        return self.conn.execute("SELECT COUNT(*) FROM captures").fetchone()[0]

    def all_rows(self) -> list[dict]:
        rows = self.conn.execute(
            "SELECT id, timestamp, src_mac, dst_mac, ethertype, length, description "
            "FROM captures ORDER BY id"
        ).fetchall()
        return [
            {"id": r[0], "ts": r[1], "src": r[2], "dst": r[3],
             "etype": r[4], "len": r[5], "desc": r[6]}
            for r in rows
        ]

    def close(self) -> None:
        self.conn.close()


# ---------------------------------------------------------------------------
# MITM interceptor (userspace loopback simulation)
# ---------------------------------------------------------------------------

class MITMInterceptor:
    """Userspace MITM simulation on loopback.

    Uses SO_REUSEPORT test sockets to demonstrate packet capture pipeline
    without touching iptables or kernel networking.
    """

    def __init__(self, store: CaptureStore | None = None,
                 host: str = "127.0.0.1", port: int = 19876,
                 dry_run: bool = True):
        self.store = store or CaptureStore()
        self.host = host
        self.port = port
        self.dry_run = dry_run
        self._running = False
        self._server_sock: socket.socket | None = None
        self._capture_thread: threading.Thread | None = None

    def start(self) -> dict:
        """Start the MITM interceptor."""
        import threading

        if self.dry_run:
            safety.dry_action(
                f"MITM interceptor would listen on {self.host}:{self.port}, "
                "intercept and log all traffic", dry_run=True
            )
            return {"mode": "dry-run", "host": self.host, "port": self.port}

        import socket as _socket
        self._server_sock = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        self._server_sock.setsockopt(_socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1)
        self._server_sock.settimeout(2.0)
        self._server_sock.bind((self.host, self.port))
        self._server_sock.listen(5)
        self._running = True

        self._capture_thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._capture_thread.start()

        return {"mode": "live", "host": self.host, "port": self.port}

    def _accept_loop(self) -> None:
        """Accept connections and log them."""
        while self._running:
            try:
                conn, addr = self._server_sock.accept()
                data = conn.recv(65535)
                if data:
                    self.store.insert(
                        src_mac="", dst_mac="",
                        ethertype=0, length=len(data),
                        data=data,
                        description=f"MITM capture from {addr}",
                    )
                conn.close()
            except socket.timeout:
                continue
            except Exception:
                break

    def stop(self) -> dict:
        """Stop the interceptor."""
        self._running = False
        if self._capture_thread:
            self._capture_thread.join(timeout=2)
        if self._server_sock:
            self._server_sock.close()
            self._server_sock = None
        count = self.store.count()
        return {"captured": count, "mode": "stopped"}


# ---------------------------------------------------------------------------
# Dry-run print "would do X"
# ---------------------------------------------------------------------------

def dry_mitm_plan(iface: str = "lo") -> dict:
    """Print what the MITM pipeline would do."""
    steps = [
        f"1. Open raw socket on {iface} (AF_PACKET, ETH_P_ALL)",
        "2. Set promiscuous mode via ioctl SIOCGIFFLAGS / SIOCSIFFLAGS",
        "3. Fork capture thread to read frames in a loop",
        "4. Parse each frame: extract Ethernet header, identify protocol",
        "5. Log to SQLite capture store with timestamp",
        "6. On SIGINT/SIGTERM: restore interface flags, close socket, emit report",
    ]
    for step in steps:
        safety.dry_action(step, dry_run=True)
    return {"iface": iface, "steps": len(steps)}


# ---------------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------------

import socket as _socket_mod
import threading

def demo() -> None:
    print("[mitm] Dry-run MITM plan ...")
    plan = dry_mitm_plan("lo")
    assert plan["steps"] == 6
    print(f"  OK — {plan['steps']} steps described")

    print("[mitm] Capture store test ...")
    store = CaptureStore(":memory:")
    store.insert(src_mac="aa:bb:cc:dd:ee:ff", dst_mac="11:22:33:44:55:66",
                 ethertype=0x0806, length=42, description="ARP test")
    store.insert(src_mac="ff:ff:ff:ff:ff:ff", ethertype=0x0800,
                 length=100, description="IP test")
    assert store.count() == 2
    rows = store.all_rows()
    assert rows[0]["desc"] == "ARP test"
    store.close()
    print(f"  OK — {len(rows)} entries in store")

    print("[mitm] Dry-run interceptor ...")
    interceptor = MITMInterceptor(dry_run=True)
    r = interceptor.start()
    assert r["mode"] == "dry-run"
    print(f"  OK — {r['mode']} on {r['host']}:{r['port']}")

    print("[mitm] Live loopback interceptor test ...")
    store2 = CaptureStore(":memory:")
    live_interceptor = MITMInterceptor(store=store2, dry_run=False, port=19877)
    lr = live_interceptor.start()
    assert lr["mode"] == "live"

    # Send some data to the interceptor
    time.sleep(0.2)
    try:
        s = _socket_mod.socket(_socket_mod.AF_INET, _socket_mod.SOCK_STREAM)
        s.settimeout(1.0)
        s.connect(("127.0.0.1", 19877))
        s.sendall(b"MITM-CAPTURE-TEST")
        s.close()
    except Exception:
        pass

    time.sleep(0.5)
    sr = live_interceptor.stop()
    assert sr["captured"] >= 1, f"Expected >=1 capture, got {sr['captured']}"
    store2.close()
    print(f"  OK — {sr['captured']} packets captured on loopback")

    print("[mitm] All demos passed.")
