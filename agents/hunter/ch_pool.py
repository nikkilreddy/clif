"""
ClickHouse Connection Pool – thread-safe pool for the Hunter Agent.

Eliminates the overhead of creating 5+ TCP connections per investigation
(~7 concurrent CH clients × HUNTER_CONCURRENCY investigations).

Usage:
    pool = CHPool(size=32, host=..., port=..., ...)

    # Borrow / return
    client = pool.borrow()
    try:
        rows = client.query("SELECT ...").result_rows
    finally:
        pool.release(client)

    # Or via context manager
    with pool.client() as client:
        rows = client.query("SELECT ...").result_rows
"""
from __future__ import annotations

import logging
import queue
import threading
from contextlib import contextmanager
from typing import Any, Optional

import clickhouse_connect  # type: ignore
import urllib3

log = logging.getLogger("hunter.ch_pool")

_urllib3_pool = urllib3.PoolManager(num_pools=4, maxsize=120)


class CHPool:
    """
    Thread-safe ClickHouse connection pool.

    Pre-creates `size` connections at startup. When the pool is exhausted,
    creates temporary overflow connections (with a warning) rather than
    blocking callers.
    """

    def __init__(
        self,
        size: int,
        host: str,
        port: int,
        username: str,
        password: str,
        database: str,
    ) -> None:
        self._conn_kwargs = {
            "host": host,
            "port": port,
            "username": username,
            "password": password,
            "database": database,
        }
        self._size = size
        self._pool: queue.Queue = queue.Queue(maxsize=size)
        self._created = 0
        self._overflow = 0
        self._lock = threading.Lock()

        # Pre-fill pool
        for _ in range(size):
            self._pool.put(self._create_client())
        log.info("CHPool initialised: size=%d, host=%s:%d", size, host, port)

    def _create_client(self) -> Any:
        with self._lock:
            self._created += 1
        return clickhouse_connect.get_client(
            **self._conn_kwargs, pool_mgr=_urllib3_pool
        )

    def borrow(self, timeout: float = 0.0) -> Any:
        """
        Borrow a client from the pool.

        If the pool is empty and timeout <= 0, creates a temporary overflow
        client immediately (non-blocking). If timeout > 0, waits up to
        `timeout` seconds before creating an overflow.
        """
        try:
            return self._pool.get(block=(timeout > 0), timeout=timeout or None)
        except queue.Empty:
            with self._lock:
                self._overflow += 1
            if self._overflow % 50 == 1:
                log.warning(
                    "CHPool exhausted (size=%d), created overflow client #%d",
                    self._size, self._overflow,
                )
            return self._create_client()

    def release(self, client: Any) -> None:
        """Return a client to the pool. Discards if pool is full."""
        if client is None:
            return
        try:
            self._pool.put_nowait(client)
        except queue.Full:
            # Overflow client — close it
            try:
                client.close()
            except Exception:
                pass

    @contextmanager
    def client(self):
        """Context manager that borrows and auto-releases a client."""
        c = self.borrow()
        try:
            yield c
        finally:
            self.release(c)

    def close_all(self) -> None:
        """Drain the pool and close all connections."""
        closed = 0
        while not self._pool.empty():
            try:
                c = self._pool.get_nowait()
                c.close()
                closed += 1
            except (queue.Empty, Exception):
                break
        log.info("CHPool closed: %d connections", closed)

    def get_stats(self) -> dict:
        return {
            "pool_size": self._size,
            "available": self._pool.qsize(),
            "total_created": self._created,
            "overflow_created": self._overflow,
        }
