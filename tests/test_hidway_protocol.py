"""HIDway wire protocol, crypto and the UDP transport (core/hidway.py), offline.

Where each vector comes from (HIDway repository, read-only):
  * INPUT_VECTOR — the input values of ``test_protocol_input`` in
    ``tests/test_common.c``, encoded by hand following ``hidway_input_encode``
    in ``common/protocol.h`` (all fields little-endian; key bitmap bit
    ``usage & 7`` of byte ``usage >> 3``).
  * STATUS_VECTOR — laid out by hand from ``hidway_status_encode``
    (``common/protocol.h``).
  * HChaCha20 — draft-irtf-cfrg-xchacha-03 §2.2.1.
  * AEAD_XChaCha20_Poly1305 — draft-irtf-cfrg-xchacha-03 Appendix A.3.1, the
    same vector ``test_xchacha_kat`` uses to prove HIDway's vendored
    Monocypher (``crypto_aead_lock``) is the standard construction.
  * Envelope layout — ``hidway_seal`` in ``common/hidway_crypto.c``: header
    ``'H' 2 0x10`` as associated data, nonce, then ciphertext of
    ``ts_us (u64 LE) || packet`` followed by the 16-byte tag. Key/nonce/ts
    and packet values are those of ``test_seal_open``.
No C compiler was available, so no envelope bytes were produced by the C code
itself; the envelope test checks the layout field by field instead.
"""

from __future__ import annotations

import logging
import struct
import threading
from pathlib import Path

import pytest

from netsentry.core import hidway
from netsentry.core.remote_input import Frame

INPUT_VECTOR = bytes.fromhex(
    "48010100" "efbeadde" "04030201" "15cd5b07"      # magic ver STATE flags, session, seq, time
    "05"                                             # mods
    "00000004" + "00" * 16 + "80"                    # keys: usage 0x1A and 0xA7
    + "13" "90eefeff" "e8fd0000" "fdff" "0700")      # buttons, x=-70000, y=65000, wheel=-3, pan=7

STATUS_VECTOR = bytes.fromhex(
    "48018100" "efbeadde" "05000000" "e8030000" "09000000" "0200" "3200" "00")


# ─── protocol.h ──────────────────────────────────────────────────

def test_input_packet_matches_protocol_h_byte_for_byte() -> None:
    packet = hidway.encode_input(hidway.MSG_STATE, 0xDEADBEEF, 0x01020304, 123456789,
                                 mods=0x05, keys={0x1A, 0xA7}, buttons=0x13,
                                 x=-70000, y=65000, wheel=-3, pan=7)
    assert len(packet) == hidway.INPUT_LEN == 51
    assert packet == INPUT_VECTOR


def test_counters_wrap_like_the_c_casts() -> None:
    a = hidway.encode_input(hidway.MSG_STATE, 1, 1, 0, x=0xFFFFFFFF, wheel=0xFFFF)
    b = hidway.encode_input(hidway.MSG_STATE, 1, 1, 0, x=-1, wheel=-1)
    assert a == b
    with pytest.raises(hidway.HidwayError):
        hidway.encode_input(hidway.MSG_STATE, 1, 1, 0, keys={0xE0})   # modifiers are not keys


def test_status_reply_decodes_and_rejects_garbage() -> None:
    st = hidway.decode_status(STATUS_VECTOR)
    assert st == {"session": 0xDEADBEEF, "seq": 5, "client_time_us": 1000, "frames_ok": 9,
                  "seq_gaps": 2, "flags": 0x32, "leds": 0}
    assert st["flags"] & hidway.STATUS_SERIAL_OPEN
    assert hidway.TARGETS[(st["flags"] & hidway.STATUS_TARGET_MASK) >> 4] == "on"
    assert hidway.decode_status(STATUS_VECTOR[:-1]) is None
    assert hidway.decode_status(b"X" + STATUS_VECTOR[1:]) is None
    assert hidway.decode_status(INPUT_VECTOR[:25]) is None             # an input, not a status


# ─── hidway_crypto.c ─────────────────────────────────────────────

def test_hchacha20_draft_vector() -> None:
    key = bytes(range(32))
    nonce = bytes.fromhex("000000090000004a0000000031415927")
    assert hidway.hchacha20(key, nonce).hex() == (
        "82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc")


def test_xchacha20_poly1305_draft_vector_a31() -> None:
    key = bytes(range(0x80, 0xA0))
    nonce = bytes(range(0x40, 0x58))
    aad = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
    plain = (b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip "
             b"for the future, sunscreen would be it.")
    ct = bytes.fromhex(
        "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb"
        "731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452"
        "2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9"
        "21f9664c97637da9768812f615c68b13b52e")
    tag = bytes.fromhex("c0875924c1c7987947deafd8780acf49")
    assert hidway.xchacha_seal(key, nonce, plain, aad) == ct + tag
    assert hidway.xchacha_open(key, nonce, ct + tag, aad) == plain
    assert hidway.xchacha_open(key, nonce, ct + bytes(16), aad) is None


def _seal_open_values() -> tuple[bytes, bytes, int, bytes]:
    key = bytes((i * 7 + 1) & 0xFF for i in range(32))
    nonce = bytes(0xA0 + i for i in range(24))
    inner = hidway.encode_input(hidway.MSG_STATE, 0x01020304, 77, 0, keys={0x1A}, x=-1234)
    return key, nonce, 0x0123456789ABCDEF, inner


def test_envelope_layout_follows_hidway_seal() -> None:
    key, nonce, ts, inner = _seal_open_values()
    env = hidway.seal(key, nonce, ts, inner)
    assert hidway.SEAL_OVERHEAD == 3 + 24 + 8 + 16
    assert len(env) == len(inner) + hidway.SEAL_OVERHEAD == 102
    assert env[:3] == b"H\x02\x10" and env[3:27] == nonce
    assert env[27:] == hidway.xchacha_seal(key, nonce, struct.pack("<Q", ts) + inner, b"H\x02\x10")
    assert inner not in env                                   # nothing in clear
    assert hidway.is_sealed(env) and not hidway.is_sealed(inner)
    assert hidway.open_sealed(key, env) == (ts, inner)


def test_envelope_rejects_wrong_key_any_flipped_bit_and_truncation() -> None:
    key, nonce, ts, inner = _seal_open_values()
    env = bytearray(hidway.seal(key, nonce, ts, inner))
    other = bytes((i * 7 + 2) & 0xFF for i in range(32))
    assert hidway.open_sealed(other, bytes(env)) is None
    for i in range(len(env)):
        env[i] ^= 1
        assert hidway.open_sealed(key, bytes(env)) is None
        env[i] ^= 1
    assert hidway.open_sealed(key, bytes(env[:-1])) is None
    with pytest.raises(hidway.HidwayError):
        hidway.seal(key, nonce, 1, bytes(65))                  # HIDWAY_SEAL_MAX_INNER = 64


def test_key_parse_is_exactly_64_hex_and_never_quotes_the_value() -> None:
    good = "ab" * 32
    assert hidway.parse_key("  " + good + "\n") == bytes([0xAB]) * 32
    for bad in ("", "ab" * 31, "zz" * 32, good + "00"):
        with pytest.raises(hidway.HidwayError) as err:
            hidway.parse_key(bad)
        assert bad.strip() == "" or bad not in str(err.value)


# ─── the transport against a fake relay ──────────────────────────

def _decode_input(data: bytes) -> dict:
    """Mirror of hidway_input_decode, for the fake relay."""
    assert len(data) == 51 and data[0] == 0x48 and data[1] == 1
    _, _, kind, _, session, seq, _ = struct.unpack_from("<BBBBIII", data)
    mods = data[16]
    bitmap = data[17:38]
    keys = {i for i in range(0xA8) if bitmap[i >> 3] >> (i & 7) & 1}
    buttons, x, y, wheel, _ = struct.unpack_from("<Biihh", data, 38)
    return {"type": kind, "session": session, "seq": seq, "mods": mods, "keys": keys,
            "buttons": buttons, "x": x, "y": y, "wheel": wheel}


class FakeRelay:
    """A socket that behaves like hidwayd for one sender."""

    def __init__(self, key: bytes | None = None) -> None:
        self.key = key
        self.packets: list[dict] = []
        self.raw: list[bytes] = []
        self.timestamps: list[int] = []
        self.inbox: list[bytes] = []
        self.silent = False
        self.flags = 0x0032
        self.reply_key: bytes | None = key
        self.reply_session: int | None = None
        self.bound = None
        self.closed = False

    # socket API used by HidwayRelay
    def bind(self, addr) -> None:
        self.bound = addr

    def setblocking(self, flag: bool) -> None:
        pass

    def close(self) -> None:
        self.closed = True

    def sendto(self, data: bytes, addr) -> int:
        self.raw.append(data)
        if self.key is not None:
            opened = hidway.open_sealed(self.key, data)
            assert opened is not None, "a packet the relay cannot open"
            self.timestamps.append(opened[0])
            data = opened[1]
        else:
            assert not hidway.is_sealed(data)
        pkt = _decode_input(data)
        self.packets.append(pkt)
        if not self.silent:
            reply = struct.pack("<BBBBIIIIHHB", 0x48, 1, 0x81, 0,
                                self.reply_session if self.reply_session is not None
                                else pkt["session"], pkt["seq"], 0, len(self.packets), 0,
                                self.flags, 0)
            if self.reply_key is not None:
                reply = hidway.seal(self.reply_key, bytes(24), 1, reply)
            self.inbox.append(reply)
        return len(data)

    def recvfrom(self, size: int):
        if not self.inbox:
            raise BlockingIOError
        return self.inbox.pop(0), ("192.0.2.10", 47800)


class Clock:
    def __init__(self) -> None:
        self.t = 1000.0
        self.slept: list[float] = []

    def __call__(self) -> float:
        return self.t

    def sleep(self, s: float) -> None:
        self.slept.append(s)
        self.t += s


def _relay(tmp_path: Path, fake: FakeRelay, *, key: bytes | None = None, wall=None,
           state: str | None = "link=down\nserial=open\ntarget=on\ncrypto=off\n"):
    state_file = tmp_path / "state"
    if state is not None:
        state_file.write_text(state, encoding="utf-8")
    clock = Clock()
    counter = iter(range(1, 10_000))
    relay = hidway.HidwayRelay(
        "192.0.2.10", 47800, key=key, state_file=str(state_file),
        socket_factory=lambda: fake, sleep=clock.sleep, clock=clock,
        wall_us=wall or (lambda: 1_800_000_000_000_000),
        random_bytes=lambda n: bytes([next(counter) & 0xFF]) * n)
    return relay, clock


def test_session_binds_the_source_address_and_probe_never_sends_input(tmp_path: Path) -> None:
    fake = FakeRelay()
    relay, _ = _relay(tmp_path, fake)
    relay.start()
    assert fake.bound == ("192.0.2.10", 0)
    assert relay.probe() is True
    assert [p["type"] for p in fake.packets] == [hidway.MSG_PROBE]
    assert fake.packets[0]["keys"] == set() and fake.packets[0]["session"] != 0


def test_probe_without_an_answer_fails(tmp_path: Path) -> None:
    fake = FakeRelay()
    fake.silent = True
    relay, clock = _relay(tmp_path, fake)
    relay.start()
    assert relay.probe() is False
    assert clock.t - 1000.0 >= relay.reply_timeout_s


def test_send_paces_states_and_needs_an_acknowledgement(tmp_path: Path) -> None:
    fake = FakeRelay()
    relay, clock = _relay(tmp_path, fake)
    relay.start()
    frames = [Frame(), Frame(mods=2), Frame(mods=2, keys=frozenset({0x04})), Frame(mods=2), Frame()]
    assert relay.send(frames, threading.Event()) == ""
    sent = [p for p in fake.packets if p["type"] == hidway.MSG_STATE]
    assert [(p["mods"], p["keys"]) for p in sent] == [(0, set()), (2, set()), (2, {4}),
                                                       (2, set()), (0, set())]
    assert [p["seq"] for p in fake.packets] == sorted(p["seq"] for p in fake.packets)
    assert clock.slept.count(relay.frame_gap_s) == 4
    fake.silent = True
    assert relay.send([Frame()], threading.Event()) == "no_answer"


def test_replies_for_another_session_do_not_count(tmp_path: Path) -> None:
    fake = FakeRelay()
    fake.reply_session = 0x12345678           # someone else's session
    relay, _ = _relay(tmp_path, fake)
    relay.start()
    assert relay.send([Frame()], threading.Event()) == "no_answer"


def test_input_fault_and_cancel_are_reported(tmp_path: Path) -> None:
    fake = FakeRelay()
    fake.flags = 0x0032 | hidway.STATUS_INPUT_FAULT
    relay, _ = _relay(tmp_path, fake)
    relay.start()
    assert relay.send([Frame()], threading.Event()) == "input_fault"
    stop = threading.Event()
    stop.set()
    before = len(fake.packets)
    assert relay.send([Frame(), Frame()], stop) == "cancelled"
    assert len(fake.packets) == before


def test_release_sends_everything_up_then_release(tmp_path: Path) -> None:
    fake = FakeRelay()
    relay, _ = _relay(tmp_path, fake)
    relay.release()                           # no session yet: nothing, no error
    assert fake.packets == []
    relay.start()
    relay.send([Frame(x=5, y=-3), Frame(mods=1, keys=frozenset({0x06}), x=5, y=-3)],
               threading.Event())
    relay.release()
    last_two = fake.packets[-2:]
    assert last_two[0]["type"] == hidway.MSG_STATE and last_two[0]["keys"] == set()
    assert last_two[0]["mods"] == 0 and (last_two[0]["x"], last_two[0]["y"]) == (5, -3)
    assert last_two[1]["type"] == hidway.MSG_RELEASE
    relay.stop()
    assert fake.closed


def test_encrypted_relay_gets_only_sealed_packets_with_rising_timestamps(tmp_path: Path) -> None:
    key = bytes(range(32))
    fake = FakeRelay(key)
    relay, _ = _relay(tmp_path, fake, key=key, wall=lambda: 5_000_000,
                      state="link=down\nserial=open\ntarget=on\ncrypto=on\n")
    relay.start()
    assert relay.probe()
    assert relay.send([Frame(), Frame(keys=frozenset({0x04})), Frame()], threading.Event()) == ""
    relay.release()
    assert all(hidway.is_sealed(raw) for raw in fake.raw)
    assert fake.timestamps == sorted(set(fake.timestamps))   # strictly increasing, clock stood still
    fake.reply_key = bytes(32)                # a reply sealed with another key is ignored
    assert relay.send([Frame()], threading.Event()) == "no_answer"


def test_view_reads_the_state_file(tmp_path: Path) -> None:
    fake = FakeRelay()
    relay, _ = _relay(tmp_path, fake, state=None)
    view = relay.view()
    assert not view.running and "not running" in view.problem

    path = Path(relay.state_file)
    path.write_text("link=up\nsession=deadbeef\nserial=open\ntarget=asleep\ncrypto=off\n",
                    encoding="utf-8")
    view = relay.view()
    assert view.running and view.control == "other" and view.target == "asleep"
    assert view.serial_open is True and view.encrypted is False and view.problem == ""

    relay.start()
    path.write_text(f"link=up\nsession={relay._session:08x}\nserial=closed\ncrypto=off\n",
                    encoding="utf-8")
    view = relay.view()
    assert view.control == "you" and view.serial_open is False
    path.write_text("link=down\nsession=deadbeef\ncrypto=on\n", encoding="utf-8")
    view = relay.view()
    assert view.control == "none" and "requires encryption" in view.problem


def test_key_mode_mismatch_the_other_way(tmp_path: Path) -> None:
    fake = FakeRelay(bytes(32))
    relay, _ = _relay(tmp_path, fake, key=bytes(32))
    assert "without encryption" in relay.view().problem


def test_bad_settings_are_refused() -> None:
    with pytest.raises(hidway.HidwayError):
        hidway.HidwayRelay("pi.example", 47800)
    with pytest.raises(hidway.HidwayError):
        hidway.HidwayRelay("192.0.2.10", 0)
    with pytest.raises(hidway.HidwayError):
        hidway.HidwayRelay("192.0.2.10", 47800, key=b"short")


def test_send_errors_are_logged_without_content(tmp_path: Path, caplog) -> None:
    class Broken(FakeRelay):
        def sendto(self, data, addr):
            raise OSError("network down")

    relay, _ = _relay(tmp_path, Broken())
    relay.start()
    with caplog.at_level(logging.WARNING):
        assert relay.send([Frame(keys=frozenset({0x04}))], threading.Event()) == "no_answer"
    assert "cannot send to the relay (OSError)" in caplog.text
