"""Low-level network helpers shared across modules.

Kept dependency-free and separate from `base` to avoid import cycles. The key
primitive is `tcp_open`, a single TCP connect probe; `PortCache` memoizes its
results so that when several modules ask about the same host:port in one run,
the network is only touched once.
"""
from __future__ import annotations

import socket
import threading
import time


def tcp_open(ip: str, port: int, timeout: float) -> bool:
    """Return True if a TCP connection to ip:port succeeds (IPv4/IPv6)."""
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


class PortCache:
    """Thread-safe memoizer for TCP-open probes within a single run."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._cache: dict[tuple[str, int], bool] = {}

    def is_open(self, ip: str, port: int, timeout: float) -> bool:
        key = (ip, port)
        with self._lock:
            if key in self._cache:
                return self._cache[key]
        result = tcp_open(ip, port, timeout)
        with self._lock:
            self._cache.setdefault(key, result)
            return self._cache[key]

    def stats(self) -> dict[str, int]:
        with self._lock:
            return {"probed": len(self._cache),
                    "open": sum(1 for v in self._cache.values() if v)}


class RateLimiter:
    """Optional minimum delay between outbound requests (politeness)."""

    def __init__(self, delay: float = 0.0) -> None:
        self.delay = max(0.0, delay)
        self._lock = threading.Lock()
        self._last = 0.0

    def wait(self) -> None:
        if self.delay <= 0:
            return
        with self._lock:
            now = time.monotonic()
            gap = self._last + self.delay - now
            if gap > 0:
                time.sleep(gap)
            self._last = time.monotonic()
