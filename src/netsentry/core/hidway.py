"""
HIDway's relay protocol, spoken from the relay's own host.

HIDway (a separate project) turns UDP packets into real USB keyboard/mouse
input: a Windows client sends them to the relay ``hidwayd``, which forwards
them over a serial line to a Raspberry Pi Pico plugged into the PC as a USB
keyboard and mouse. NetSentry runs on the same host as the relay, so it can
be one more sender. This module is a byte-exact Python copy of the parts of
the C sources it needs (HIDway repository):

  * ``common/protocol.h`` — the 51-byte input packet (full keyboard/mouse
    state, never events) and the 25-byte status reply, little-endian;
  * ``common/hidway_crypto.c`` — the optional sealed envelope:
    ``'H' | 2 | 0x10 | nonce[24] | XChaCha20-Poly1305(ts_us[8] || packet) | tag[16]``
    with the 3 header bytes as associated data and a pre-shared 32-byte key;
  * ``relay/hidwayd.c`` — how the relay treats senders: a source-address
    allow-list, one input session at a time (a new session id takes over and
    the previous one is ignored from then on), a 250 ms silence timeout that
    releases everything, and a state file (``/run/hidway/state``) that says
    whether a session is live and whose it is.

``HidwayRelay`` implements ``core.remote_input.InputTransport``. It never
holds a key between calls: every burst ends with everything up, followed by a
RELEASE packet.
"""

from __future__ import annotations

import logging
import os
import socket
import struct
import threading
import time
from pathlib import Path
from typing import Any, Callable, Sequence

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from .remote_input import Frame, RelayView

# ─── protocol.h ──────────────────────────────────────────────────

MAGIC = 0x48                 # 'H'
VERSION = 1
MSG_STATE = 1
MSG_RELEASE = 2
MSG_PROBE = 3
MSG_STATUS = 0x81
INPUT_LEN = 51
STATUS_LEN = 25
KEY_BITMAP_BYTES = 21        # usages 0x00..0xA7
USAGE_MAX = 0xA7

STATUS_SERIAL_OPEN = 0x0002
STATUS_ENCRYPTED = 0x0004
STATUS_TARGET_SHIFT = 4
STATUS_TARGET_MASK = 0x0030
STATUS_INPUT_FAULT = 0x0040
TARGETS = {0: "unknown", 1: "off", 2: "asleep", 3: "on"}

# ─── hidway_crypto.h ─────────────────────────────────────────────

KEY_LEN = 32
NONCE_LEN = 24
SEALED_VERSION = 2
MSG_SEALED = 0x10
SEAL_HDR = bytes((MAGIC, SEALED_VERSION, MSG_SEALED))
SEAL_OVERHEAD = 3 + NONCE_LEN + 8 + 16

_IN = struct.Struct("<BBBBIII")        # magic, ver, type, flags, session, seq, time
_TAIL = struct.Struct("<Biihh")        # buttons, x, y, wheel, pan
_STATUS = struct.Struct("<BBBBIIIIHHB")


class HidwayError(ValueError):
    """Bad configuration or key material (the message never holds the key)."""


def encode_input(msg_type: int, session: int, seq: int, time_us: int, *, mods: int = 0,
                 keys: frozenset[int] | set[int] = frozenset(), buttons: int = 0,
                 x: int = 0, y: int = 0, wheel: int = 0, pan: int = 0) -> bytes:
    """``hidway_input_encode``: the 51-byte input packet."""
    bitmap = bytearray(KEY_BITMAP_BYTES)
    for usage in keys:
        if not 0 <= usage <= USAGE_MAX:
            raise HidwayError("key usage out of range")
        bitmap[usage >> 3] |= 1 << (usage & 7)
    return (_IN.pack(MAGIC, VERSION, msg_type, 0, session & 0xFFFFFFFF,
                     seq & 0xFFFFFFFF, time_us & 0xFFFFFFFF)
            + bytes((mods & 0xFF,)) + bytes(bitmap)
            + _TAIL.pack(buttons & 0xFF, _s32(x), _s32(y), _s16(wheel), _s16(pan)))


def decode_status(data: bytes) -> dict[str, int] | None:
    """``hidway_status_decode``: the relay's 25-byte reply, or None."""
    if len(data) != STATUS_LEN:
        return None
    magic, ver, kind, _, session, seq, ctime, frames, gaps, flags, leds = _STATUS.unpack(data)
    if magic != MAGIC or ver != VERSION or kind != MSG_STATUS:
        return None
    return {"session": session, "seq": seq, "client_time_us": ctime, "frames_ok": frames,
            "seq_gaps": gaps, "flags": flags, "leds": leds}


def _s32(v: int) -> int:
    v &= 0xFFFFFFFF
    return v - (1 << 32) if v & 0x80000000 else v


def _s16(v: int) -> int:
    v &= 0xFFFF
    return v - (1 << 16) if v & 0x8000 else v


# ─── XChaCha20-Poly1305 (= Monocypher 4 crypto_aead_lock) ────────

def _rotl(v: int, n: int) -> int:
    return ((v << n) & 0xFFFFFFFF) | (v >> (32 - n))


def _quarter(s: list[int], a: int, b: int, c: int, d: int) -> None:
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF
    s[d] = _rotl(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF
    s[b] = _rotl(s[b] ^ s[c], 12)
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF
    s[d] = _rotl(s[d] ^ s[a], 8)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF
    s[b] = _rotl(s[b] ^ s[c], 7)


def hchacha20(key: bytes, nonce16: bytes) -> bytes:
    """HChaCha20 (draft-irtf-cfrg-xchacha §2.2): the per-nonce subkey."""
    if len(key) != KEY_LEN or len(nonce16) != 16:
        raise HidwayError("hchacha20 needs a 32-byte key and a 16-byte nonce")
    s = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574,
         *struct.unpack("<8I", key), *struct.unpack("<4I", nonce16)]
    for _ in range(10):
        _quarter(s, 0, 4, 8, 12)
        _quarter(s, 1, 5, 9, 13)
        _quarter(s, 2, 6, 10, 14)
        _quarter(s, 3, 7, 11, 15)
        _quarter(s, 0, 5, 10, 15)
        _quarter(s, 1, 6, 11, 12)
        _quarter(s, 2, 7, 8, 13)
        _quarter(s, 3, 4, 9, 14)
    return struct.pack("<8I", *s[0:4], *s[12:16])


def _aead(key: bytes, nonce: bytes) -> tuple[ChaCha20Poly1305, bytes]:
    """XChaCha20-Poly1305 = ChaCha20-Poly1305 (RFC 8439) under the HChaCha20
    subkey, with nonce 0x00000000 || nonce[16:24]."""
    return ChaCha20Poly1305(hchacha20(key, nonce[:16])), b"\0\0\0\0" + nonce[16:]


def xchacha_seal(key: bytes, nonce: bytes, plain: bytes, aad: bytes) -> bytes:
    aead, n12 = _aead(key, nonce)
    return aead.encrypt(n12, plain, aad)          # ciphertext || tag


def xchacha_open(key: bytes, nonce: bytes, sealed: bytes, aad: bytes) -> bytes | None:
    aead, n12 = _aead(key, nonce)
    try:
        return aead.decrypt(n12, sealed, aad)
    except Exception:                             # InvalidTag: forged, tampered, wrong key
        return None


def seal(key: bytes, nonce: bytes, ts_us: int, inner: bytes) -> bytes:
    """``hidway_seal``: the envelope the relay accepts when it has a key."""
    if len(nonce) != NONCE_LEN or len(inner) > 64:
        raise HidwayError("bad nonce or packet length")
    plain = struct.pack("<Q", ts_us & 0xFFFFFFFFFFFFFFFF) + inner
    return SEAL_HDR + nonce + xchacha_seal(key, nonce, plain, SEAL_HDR)


def is_sealed(data: bytes) -> bool:
    return len(data) >= SEAL_OVERHEAD and data[:3] == SEAL_HDR


def open_sealed(key: bytes, data: bytes) -> tuple[int, bytes] | None:
    """``hidway_open``: (timestamp, inner packet), or None."""
    if not is_sealed(data) or len(data) - SEAL_OVERHEAD > 64:
        return None
    nonce = data[3:3 + NONCE_LEN]
    plain = xchacha_open(key, nonce, data[3 + NONCE_LEN:], SEAL_HDR)
    if plain is None:
        return None
    return struct.unpack("<Q", plain[:8])[0], plain[8:]


def parse_key(text: Any) -> bytes:
    """``hidway_key_parse``: exactly 64 hex characters (surrounding spaces
    ignored). The error never quotes the value."""
    raw = str(text or "").strip()
    if len(raw) != 2 * KEY_LEN:
        raise HidwayError("the key must be exactly 64 hex characters")
    try:
        return bytes.fromhex(raw)
    except ValueError:
        raise HidwayError("the key must be exactly 64 hex characters") from None


# ─── /run/hidway/state ───────────────────────────────────────────

def read_state_file(path: str | Path) -> dict[str, str] | None:
    """The relay's published state (``key=value`` lines), or None when the
    relay does not run (it removes the file on exit) or it cannot be read."""
    try:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    out: dict[str, str] = {}
    for line in text.splitlines()[:64]:
        key, sep, value = line.partition("=")
        if sep and key.strip():
            out[key.strip()] = value.strip()[:64]
    return out


# ─── the transport ───────────────────────────────────────────────

class HidwayRelay:
    """``InputTransport`` over HIDway's UDP protocol to the relay on this host.

    The socket is bound to ``source_host`` (default: the relay address itself),
    so the relay sees a fixed source address that its allow-list can name.
    """

    def __init__(self, host: str, port: int = 47800, *, source_host: str = "",
                 key: bytes | None = None, state_file: str = "/run/hidway/state",
                 frame_gap_s: float = 0.010, reply_timeout_s: float = 0.3,
                 logger: logging.Logger | None = None,
                 socket_factory: Callable[[], Any] | None = None,
                 sleep: Callable[[float], None] = time.sleep,
                 clock: Callable[[], float] = time.monotonic,
                 wall_us: Callable[[], int] = lambda: time.time_ns() // 1000,
                 random_bytes: Callable[[int], bytes] = os.urandom) -> None:
        try:
            socket.inet_aton(host)
            if source_host:
                socket.inet_aton(source_host)
        except OSError:
            raise HidwayError("relay_host and source_host must be IPv4 addresses") from None
        if not 0 < int(port) < 65536:
            raise HidwayError("relay_port must be 1-65535")
        if key is not None and len(key) != KEY_LEN:
            raise HidwayError("the key must be 32 bytes")
        self.addr = (host, int(port))
        self.source = source_host or host
        self._key = key
        self.state_file = state_file
        self.frame_gap_s = max(0.004, min(float(frame_gap_s), 0.05))
        self.reply_timeout_s = max(0.05, min(float(reply_timeout_s), 2.0))
        self.log = logger or logging.getLogger(__name__)
        self._socket_factory = socket_factory or (
            lambda: socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
        self._sleep, self._clock, self._wall_us, self._random = sleep, clock, wall_us, random_bytes
        self._lock = threading.Lock()
        self._sock: Any = None
        self._session: int | None = None
        self._seq = 0
        self._last_ts = 0
        self._last_frame: Frame | None = None
        self._last_sent = -1e9
        self._flags = 0

    @property
    def encrypted(self) -> bool:
        return self._key is not None

    # ─── InputTransport ──────────────────────────────────────────

    def view(self) -> RelayView:
        st = read_state_file(self.state_file)
        if st is None:
            return RelayView(running=False, problem="The HIDway relay is not running on "
                             "this host (no state file).")
        crypto_on = st.get("crypto") == "on" if "crypto" in st else None
        problem = ""
        if crypto_on is True and not self.encrypted:
            problem = "The relay requires encryption, but NetSentry has no key for it."
        elif crypto_on is False and self.encrypted:
            problem = "NetSentry has a key, but the relay runs without encryption."
        control = "none"
        if st.get("link") == "up":
            session = st.get("session", "")
            mine = self._session is not None and session == f"{self._session:08x}"
            control = "you" if mine else "other"
        serial = st.get("serial")
        return RelayView(
            running=True,
            serial_open=True if serial == "open" else False if serial in ("closed", "none") else None,
            target=st.get("target", "unknown") if st.get("target") in TARGETS.values() else "unknown",
            encrypted=crypto_on, control=control, problem=problem)

    def start(self) -> None:
        with self._lock:
            self._close()
            sock = self._socket_factory()
            try:
                sock.bind((self.source, 0))
                sock.setblocking(False)
            except OSError:
                sock.close()
                raise
            self._sock = sock
            session = 0
            while session == 0:
                session = int.from_bytes(self._random(4), "little")
            self._session = session
            self._seq = 0
            self._last_frame = None
            self._last_sent = -1e9
            self._flags = 0

    def probe(self) -> bool:
        with self._lock:
            if self._sock is None:
                return False
            sent_at = self._clock()
            self._send(MSG_PROBE, Frame())
            return self._await_reply(sent_at)

    def send(self, frames: Sequence[Frame], cancel: threading.Event) -> str:
        with self._lock:
            if self._sock is None:
                return "no_answer"
            # The Pico applies mouse movement only between two states less than
            # 100 ms apart, so every burst starts with "nothing held, counters
            # where they stand" (RemoteInput puts it first) and goes out paced.
            replies = 0
            for i, frame in enumerate(frames):
                if cancel.is_set():
                    return "cancelled"
                if i:
                    self._sleep(self.frame_gap_s)
                self._send(MSG_STATE, frame)
                replies += self._drain()
            if not replies and not self._await_reply(self._clock()):
                return "no_answer"
            if self._flags & STATUS_INPUT_FAULT:
                return "input_fault"
            return ""

    def release(self) -> None:
        with self._lock:
            if self._sock is None or self._session is None:
                return
            # Let the last states reach the Pico first: a RELEASE makes the
            # relay drop anything still queued for the serial line.
            wait = 0.05 - (self._clock() - self._last_sent)
            if wait > 0:
                self._sleep(wait)
            last = self._last_frame or Frame()
            self._send(MSG_STATE, Frame(x=last.x, y=last.y, wheel=last.wheel))
            self._sleep(self.frame_gap_s)
            self._send(MSG_RELEASE, Frame())
            self._drain()

    def stop(self) -> None:
        with self._lock:
            self._close()
            self._session = None

    # ─── internals (called with the lock held) ───────────────────

    def _close(self) -> None:
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
        self._sock = None

    def _send(self, msg_type: int, frame: Frame) -> None:
        self._seq = (self._seq + 1) & 0xFFFFFFFF
        packet = encode_input(msg_type, self._session or 0, self._seq,
                              int(self._clock() * 1_000_000), mods=frame.mods,
                              keys=frame.keys, buttons=frame.buttons,
                              x=frame.x, y=frame.y, wheel=frame.wheel)
        if self._key is not None:
            # Strictly increasing: the relay refuses a timestamp it has seen.
            ts = max(self._wall_us(), self._last_ts + 1)
            self._last_ts = ts
            packet = seal(self._key, self._random(NONCE_LEN), ts, packet)
        try:
            self._sock.sendto(packet, self.addr)
        except OSError as exc:
            self.log.warning("remote keyboard: cannot send to the relay (%s)",
                             type(exc).__name__)
        if msg_type == MSG_STATE:
            self._last_frame = frame
            self._last_sent = self._clock()

    def _drain(self) -> int:
        """Read every reply waiting; count the ones for this session."""
        count = 0
        while True:
            try:
                data, _ = self._sock.recvfrom(256)
            except (BlockingIOError, InterruptedError, socket.timeout):
                return count
            except OSError:
                return count             # e.g. ICMP port unreachable: nobody listens
            if self._accept_reply(data):
                count += 1

    def _await_reply(self, since: float) -> bool:
        deadline = since + self.reply_timeout_s
        while True:
            if self._drain():
                return True
            if self._clock() >= deadline:
                return False
            self._sleep(0.005)

    def _accept_reply(self, data: bytes) -> bool:
        if self._key is not None:
            opened = open_sealed(self._key, data)
            if opened is None:
                return False
            data = opened[1]
        elif is_sealed(data):
            return False
        status = decode_status(data)
        if status is None or status["session"] != self._session:
            return False
        self._flags = status["flags"]
        return True
