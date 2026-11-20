"""Keep one SSH port forward alive as a child process, only while it is useful.

Used to reach a service that listens only on another machine's loopback — LM
Studio on the gaming PC (``127.0.0.1:1234``) — as ``127.0.0.1:<local_port>``
here, through the same restricted key the PC agent uses (that key may open
exactly this one forward and nothing else).

* Started on demand (:meth:`TunnelKeeper.ensure`), when something asks for the
  service and the tunnel is down; re-used while the process lives.
* Bound to 127.0.0.1 only: nothing else on the network can use it.
* The PC is often off. Then ssh fails, and asking again a second later would
  only fail again — so failures back off (30 s, doubling, up to 15 min) and
  "not available" is simply the answer meanwhile. No loop runs in the
  background: nothing happens until the next time someone asks.
* Stopped on shutdown (:meth:`stop`).
"""

from __future__ import annotations

import logging
import socket
import subprocess  # nosec B404 - fixed argv (no shell), see TunnelKeeper.argv
import threading
import time
from typing import Any, Callable

log = logging.getLogger(__name__)

FIRST_BACKOFF_S = 30.0
MAX_BACKOFF_S = 900.0


def port_open(port: int, timeout: float = 0.5) -> bool:
    """Is something listening on 127.0.0.1:<port>?"""
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=timeout):
            return True
    except OSError:
        return False


class TunnelKeeper:
    def __init__(self, *, host: str, user: str, ssh_key: str, local_port: int,
                 remote_port: int = 1234, port: int = 22, connect_timeout: int = 8,
                 ssh_bin: str = "ssh",
                 spawn: Callable[..., Any] = subprocess.Popen,
                 probe: Callable[[int], bool] = port_open,
                 clock: Callable[[], float] = time.monotonic,
                 sleep: Callable[[float], None] = time.sleep) -> None:
        if not 1024 <= int(local_port) <= 65535:
            raise ValueError(f"local tunnel port must be 1024-65535, not {local_port}")
        if not 1 <= int(remote_port) <= 65535:
            raise ValueError(f"remote port out of range: {remote_port}")
        self.local_port = int(local_port)
        self.argv = [ssh_bin, "-i", ssh_key, "-p", str(int(port)),
                     "-o", "BatchMode=yes",
                     "-o", f"ConnectTimeout={max(2, int(connect_timeout))}",
                     "-o", "StrictHostKeyChecking=accept-new",
                     "-o", "ExitOnForwardFailure=yes",
                     "-o", "ServerAliveInterval=30", "-o", "ServerAliveCountMax=3",
                     "-o", "IdentitiesOnly=yes",
                     "-N", "-L", f"127.0.0.1:{self.local_port}:127.0.0.1:{int(remote_port)}",
                     f"{user}@{host}"]
        self._wait_s = max(2, int(connect_timeout)) + 4.0
        self._spawn, self._probe, self._clock, self._sleep = spawn, probe, clock, sleep
        self._proc: Any = None
        self._lock = threading.Lock()
        self._backoff = 0.0
        self._next_try = 0.0
        self.starts = 0                       # how many ssh processes were started

    def alive(self) -> bool:
        return self._proc is not None and self._proc.poll() is None

    def ensure(self) -> bool:
        """True when the forward is up (started now if needed and allowed)."""
        with self._lock:
            if self.alive() and self._probe(self.local_port):
                return True
            self._kill()
            now = self._clock()
            if now < self._next_try:
                return False                   # backing off: the PC was not there
            if self._probe(self.local_port):
                # Something else already listens there: not ours, do not fight it.
                log.warning("Tunnel port %d is taken by another program", self.local_port)
                self._fail(now)
                return False
            return self._start(now)

    def stop(self) -> None:
        with self._lock:
            self._kill()

    # ─── inside ──────────────────────────────────────────────────

    def _start(self, now: float) -> bool:
        try:
            self._proc = self._spawn(self.argv, stdin=subprocess.DEVNULL,  # nosec B603 - fixed argv
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except OSError as e:
            log.error("Could not start the ssh tunnel: %s", e)
            self._fail(now)
            return False
        self.starts += 1
        deadline = now + self._wait_s
        while self._clock() < deadline:
            if self._proc.poll() is not None:
                break                           # ssh gave up: PC off or key refused
            if self._probe(self.local_port):
                self._backoff = 0.0
                self._next_try = 0.0
                log.info("Tunnel up on 127.0.0.1:%d", self.local_port)
                return True
            self._sleep(0.25)
        self._kill()
        self._fail(now)
        return False

    def _fail(self, now: float) -> None:
        self._backoff = min(MAX_BACKOFF_S, self._backoff * 2 or FIRST_BACKOFF_S)
        self._next_try = now + self._backoff
        log.info("Tunnel not available; next attempt in %d s", int(self._backoff))

    def _kill(self) -> None:
        proc, self._proc = self._proc, None
        if proc is None:
            return
        try:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
        except OSError:
            log.debug("tunnel process already gone")
