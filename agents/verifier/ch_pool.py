"""
ClickHouse Connection Pool – thread-safe pool for the Verifier Agent.

Eliminates the overhead of creating 4+ TCP connections per verification
(evidence, IOC, timeline, FP — each needs a dedicated CH client).

Ported from agents/hunter/ch_pool.py with identical API.
"""
from __future__ import annotations

import logging
import queue
import threading
from contextlib import contextmanager
from typing import Any

import clickhouse_connect  # type: ignore
import urllib3

log = logging.getLogger("verifier.ch_pool")

# Shared urllib3 PoolManager with generous limits to avoid
# "Connection pool is full, discarding connection" warnings
# when many concurrent CH clients hit the same ClickHouse host.
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
        if client is None:
            return
        try:
            self._pool.put_nowait(client)
        except queue.Full:
            try:
                client.close()
            except Exception:
                pass

    @contextmanager
    def client(self):
        c = self.borrow()
        try:
            yield c
        finally:
            self.release(c)

    def close_all(self) -> None:
        while not self._pool.empty():
            try:
                c = self._pool.get_nowait()
                c.close()
            except Exception:
                pass
