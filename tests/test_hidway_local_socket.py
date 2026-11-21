"""HIDway's local socket (relay v0.7.2+) in core/hidway.py, offline.

The contract is HIDway's ``docs/RELAY.md``, "Local socket": AF_UNIX
SOCK_SEQPACKET, one plain 51-byte input packet per message, a 25-byte status
reply per accepted packet or PROBE on the same connection, no sealed envelope
even when the relay has a key, closing releases. Most tests use a fake socket
and run everywhere; the ones at the end use real sockets and run only where
the platform has AF_UNIX + SOCK_SEQPACKET (the Linux CI).
"""

from __future__ import annotations

import logging
import os
import shutil
import socket
import struct
import tempfile
import threading
from pathlib import Path

import pytest
from test_hidway_protocol import Clock, FakeRelay, _decode_input

from netsentry.core import hidway
from netsentry.core.remote_input import Frame

KEY = bytes(range(32))
ON = "link=down\nserial=open\ntarget=on\ncrypto=on\nlocal_socket=on\n"


def _status(session: int, seq: int, flags: int = 0x0032) -> bytes:
    return struct.pack("<BBBBIIIIHHB", 0x48, 1, 0x81, 0, session, seq, 0, 1, 0, flags, 0)


class FakeConn:
    """A SOCK_SEQPACKET connection to a relay that answers like hidwayd."""

    def __init__(self) -> None:
        self.raw: list[bytes] = []
        self.inbox: list[bytes] = []
        self.connected_to = ""
        self.closed = False
        self.silent = False
        self.connect_error: OSError | None = None
        self.send_error: OSError | None = None
        self.reply_sealed = False

    def settimeout(self, t) -> None:
        pass

    def setblocking(self, flag: bool) -> None:
        pass

    def connect(self, path: str) -> None:
        if self.connect_error is not None:
            raise self.connect_error
        self.connected_to = path

    def send(self, data: bytes) -> int:
        if self.send_error is not None:
            raise self.send_error
        self.raw.append(data)
        pkt = _decode_input(data)               # asserts 51 plain bytes
        if not self.silent:
            reply = _status(pkt["session"], pkt["seq"])
            if self.reply_sealed:
                reply = hidway.seal(KEY, bytes(24), 1, reply)
            self.inbox.append(reply)
        return len(data)

    def recv(self, size: int) -> bytes:
        if not self.inbox:
            raise BlockingIOError
        return self.inbox.pop(0)

    def close(self) -> None:
        self.closed = True

    @property
    def packets(self) -> list[dict]:
        return [_decode_input(r) for r in self.raw]


class Conns:
    """unix_socket_factory: a new FakeConn per connect, all remembered."""

    def __init__(self) -> None:
        self.made: list[FakeConn] = []
        self.connect_error: OSError | None = None

    def __call__(self) -> FakeConn:
        conn = FakeConn()
        conn.connect_error = self.connect_error
        self.made.append(conn)
        return conn


def _no_udp():
    raise AssertionError("UDP must not be used")


def _relay(tmp_path: Path, *, state: str | None = ON, transport: str = "auto",
           host: str = "192.0.2.10", key: bytes | None = KEY, conns: Conns | None = None,
           udp=None, local_socket: str = "/run/hidway/inject.sock"):
    state_file = tmp_path / "state"
    if state is not None:
        state_file.write_text(state, encoding="utf-8")
    clock = Clock()
    counter = iter(range(1, 10_000))
    conns = conns or Conns()
    relay = hidway.HidwayRelay(
        host, 47800, key=key, state_file=str(state_file), transport=transport,
        local_socket=local_socket, unix_socket_factory=conns,
        socket_factory=udp or _no_udp, sleep=clock.sleep, clock=clock,
        wall_us=lambda: 1_800_000_000_000_000,
        random_bytes=lambda n: bytes([next(counter) & 0xFF]) * n)
    return relay, clock, conns


# ─── choosing the transport (pure) ───────────────────────────────

@pytest.mark.parametrize("mode, local, udp, state, exists, want", [
    ("udp", "/s", True, {"local_socket": "on"}, True, "udp"),
    ("local", "/s", True, {"local_socket": "off"}, False, "local"),
    ("auto", "", True, {"local_socket": "on"}, True, "udp"),        # socket switched off here
    ("auto", "/s", False, {"local_socket": "off"}, False, "local"),  # no UDP to fall back to
    ("auto", "/s", True, {"local_socket": "on"}, False, "local"),
    ("auto", "/s", True, {"local_socket": "off"}, True, "udp"),     # the relay's word wins
    ("auto", "/s", True, {}, True, "local"),                        # older relay: socket exists
    ("auto", "/s", True, {}, False, "udp"),
    ("auto", "/s", True, None, False, "udp"),                       # relay not running
])
def test_choose_transport(mode, local, udp, state, exists, want) -> None:
    got, why = hidway.choose_transport(mode, local, udp, state, exists)
    assert got == want and why


def test_auto_without_a_socket_path_stays_udp_byte_for_byte(tmp_path: Path) -> None:
    fake = FakeRelay()
    relay, _, conns = _relay(tmp_path, key=None, local_socket="", udp=lambda: fake,
                             state="link=down\ncrypto=off\nlocal_socket=on\n")
    relay.start()
    assert relay.probe() and conns.made == []
    assert relay.view().transport == "udp"


# ─── the socket path ─────────────────────────────────────────────

def test_packets_are_plain_on_the_socket_even_with_a_key(tmp_path: Path, caplog) -> None:
    relay, _, conns = _relay(tmp_path)
    with caplog.at_level(logging.INFO):
        relay.start()
    conn = conns.made[0]
    assert conn.connected_to == "/run/hidway/inject.sock"
    assert "local socket" in caplog.text and "local_socket=on" in caplog.text
    assert relay.probe() is True
    assert relay.send([Frame(), Frame(keys=frozenset({0x04})), Frame()], threading.Event()) == ""
    relay.release()
    assert all(len(r) == hidway.INPUT_LEN and not hidway.is_sealed(r) for r in conn.raw)
    assert [p["type"] for p in conn.packets] == [3, 1, 1, 1, 1, 2]   # PROBE, states, RELEASE
    view = relay.view()
    assert view.transport == "local" and view.encrypted is None and view.problem == ""
    relay.stop()
    assert conn.closed                       # closing the connection releases


def test_the_choice_is_logged_once(tmp_path: Path, caplog) -> None:
    relay, _, _ = _relay(tmp_path)
    with caplog.at_level(logging.INFO):
        relay.start()
        relay.stop()
        relay.start()
    assert caplog.text.count("sending over") == 1


def test_a_sealed_reply_is_ignored_on_the_socket(tmp_path: Path) -> None:
    relay, _, conns = _relay(tmp_path)
    relay.start()
    conns.made[0].reply_sealed = True
    assert relay.probe() is False


def test_no_reply_never_blocks(tmp_path: Path) -> None:
    relay, clock, conns = _relay(tmp_path)
    relay.start()
    conns.made[0].silent = True
    assert relay.probe() is False
    assert relay.reply_timeout_s <= clock.t - 1000.0 < relay.reply_timeout_s + 0.1
    assert relay.send([Frame()], threading.Event()) == "no_answer"


def test_auto_falls_back_to_udp_when_the_socket_does_not_connect(tmp_path: Path, caplog) -> None:
    fake = FakeRelay(KEY)
    conns = Conns()
    conns.connect_error = FileNotFoundError(2, "missing")
    relay, _, _ = _relay(tmp_path, conns=conns, udp=lambda: fake)
    with caplog.at_level(logging.INFO):
        relay.start()
    assert "UDP" in caplog.text and "FileNotFoundError" in caplog.text
    assert relay.probe() is True and all(hidway.is_sealed(r) for r in fake.raw)
    assert relay.view().transport == "udp"


def test_local_never_falls_back_to_udp(tmp_path: Path) -> None:
    conns = Conns()
    conns.connect_error = ConnectionRefusedError(111, "refused")
    relay, _, _ = _relay(tmp_path, transport="local", conns=conns)   # UDP would raise
    with pytest.raises(OSError):
        relay.start()
    assert relay.probe() is False and relay.send([Frame()], threading.Event()) == "no_answer"
    relay.release()
    relay.stop()


def test_auto_without_relay_host_is_socket_only(tmp_path: Path) -> None:
    conns = Conns()
    conns.connect_error = FileNotFoundError(2, "missing")
    relay, _, _ = _relay(tmp_path, host="", key=None, conns=conns, state="crypto=off\n")
    with pytest.raises(OSError):
        relay.start()


def test_a_switched_off_socket_is_a_problem_only_without_udp(tmp_path: Path) -> None:
    off = "link=down\nserial=open\ncrypto=on\nlocal_socket=off\n"
    relay, _, _ = _relay(tmp_path, transport="local", state=off)
    assert "local socket is off" in relay.view().problem
    relay, _, _ = _relay(tmp_path, state=off)
    view = relay.view()
    assert view.transport == "udp" and view.problem == "" and view.encrypted is True


def test_local_mode_ignores_the_encryption_mismatch(tmp_path: Path) -> None:
    relay, _, _ = _relay(tmp_path, transport="local", host="", key=None)
    assert relay.view().problem == ""         # crypto=on, no key: fine on the socket


def test_a_lost_connection_is_closed_and_the_next_operation_reconnects(tmp_path: Path,
                                                                       caplog) -> None:
    relay, _, conns = _relay(tmp_path)
    relay.start()
    first = conns.made[0]
    first.send_error = BrokenPipeError(32, "broken")
    with caplog.at_level(logging.WARNING):
        assert relay.send([Frame(), Frame()], threading.Event()) == "no_answer"
    assert first.closed and "BrokenPipeError" in caplog.text
    session = relay._session
    assert relay.send([Frame()], threading.Event()) == ""
    second = conns.made[1]
    assert second.packets[0]["session"] == session


def test_end_of_file_from_the_relay_closes_the_connection(tmp_path: Path) -> None:
    relay, _, conns = _relay(tmp_path)
    relay.start()
    conn = conns.made[0]
    conn.silent = True
    conn.inbox.append(b"")
    assert relay.probe() is False and conn.closed


def test_bad_transport_settings_are_refused() -> None:
    with pytest.raises(hidway.HidwayError):
        hidway.HidwayRelay("192.0.2.10", transport="carrier-pigeon")
    with pytest.raises(hidway.HidwayError):
        hidway.HidwayRelay(transport="local")                     # no socket path
    with pytest.raises(hidway.HidwayError):
        hidway.HidwayRelay(transport="local", local_socket="run/inject.sock")
    with pytest.raises(hidway.HidwayError):
        hidway.HidwayRelay(local_socket="")                       # auto: neither way
    with pytest.raises(hidway.HidwayError):
        hidway.HidwayRelay(transport="udp", local_socket="/run/hidway/inject.sock")
    relay = hidway.HidwayRelay(transport="local", local_socket="/run/hidway/inject.sock")
    assert not relay.udp_configured


# ─── real sockets (Linux) ────────────────────────────────────────

needs_seqpacket = pytest.mark.skipif(
    not hasattr(socket, "AF_UNIX") or not hasattr(socket, "SOCK_SEQPACKET"),
    reason="needs AF_UNIX + SOCK_SEQPACKET (runs on the Linux CI)")


class SocketRelay:
    """A listening SOCK_SEQPACKET socket that answers like hidwayd."""

    def __init__(self, path: str, *, silent: bool = False) -> None:
        self.path = path
        self.silent = silent
        self.raw: list[bytes] = []
        self.eof = threading.Event()
        self.server = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self.server.bind(path)
        self.server.listen(4)
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self) -> None:
        conn, _ = self.server.accept()
        with conn:
            conn.settimeout(5)
            while True:
                data = conn.recv(256)
                if not data:
                    self.eof.set()
                    return
                self.raw.append(data)
                pkt = _decode_input(data)
                if not self.silent and pkt["type"] in (1, 3):
                    conn.send(_status(pkt["session"], pkt["seq"]))

    def close(self) -> None:
        self.server.close()


@pytest.fixture()
def short_dir():
    path = tempfile.mkdtemp(prefix="hw")       # sun_path is short: keep it under /tmp
    yield path
    shutil.rmtree(path, ignore_errors=True)


@needs_seqpacket
def test_real_socket_round_trip(short_dir: str, tmp_path: Path) -> None:
    sock_path = os.path.join(short_dir, "inject.sock")
    server = SocketRelay(sock_path)
    state = tmp_path / "state"
    state.write_text(ON, encoding="utf-8")
    relay = hidway.HidwayRelay("192.0.2.10", key=KEY, state_file=str(state),
                               local_socket=sock_path, socket_factory=_no_udp)
    try:
        relay.start()
        assert relay.probe() is True
        assert relay.send([Frame(), Frame(keys=frozenset({0x04})), Frame()],
                          threading.Event()) == ""
        relay.release()
        relay.stop()
        assert server.eof.wait(5)
        assert all(len(r) == 51 and r[0] == 0x48 and r[1] == 1 for r in server.raw)
        assert [r[2] for r in server.raw] == [3, 1, 1, 1, 1, 2]
    finally:
        relay.stop()
        server.close()


@needs_seqpacket
def test_real_socket_without_replies_does_not_block(short_dir: str, tmp_path: Path) -> None:
    sock_path = os.path.join(short_dir, "inject.sock")
    server = SocketRelay(sock_path, silent=True)
    state = tmp_path / "state"
    state.write_text(ON, encoding="utf-8")
    relay = hidway.HidwayRelay(transport="local", local_socket=sock_path,
                               state_file=str(state), reply_timeout_s=0.05)
    try:
        relay.start()
        assert relay.probe() is False
        assert relay.send([Frame()], threading.Event()) == "no_answer"
    finally:
        relay.stop()
        server.close()


@needs_seqpacket
def test_real_socket_missing_file_is_refused_in_local_mode(short_dir: str,
                                                          tmp_path: Path) -> None:
    relay = hidway.HidwayRelay(transport="local", local_socket=os.path.join(short_dir, "none"),
                               state_file=str(tmp_path / "state"))
    with pytest.raises(OSError):
        relay.start()
