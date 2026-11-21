"""
Remote keyboard and mouse: the rules, independent of how input travels.

``RemoteInput`` is what the dashboard's Remote page talks to. It owns the
safety rules and nothing else:

  * **Disarmed by default.** Nothing is sent until ``arm()``; it disarms by
    itself after ``idle_timeout_s`` without input, and on ``disarm()``. The
    page disarms too, but this side enforces it.
  * **Allow-lists and caps.** Key names and modifiers come from fixed tables
    (``core/hid_keys``), text is capped and must be typeable on a US layout,
    mouse steps are clamped, input is rate limited.
  * **No stuck keys.** Every operation is a burst of complete keyboard/mouse
    states that ends with everything up, and the transport's ``release()``
    runs afterwards whatever happened (a failure, a disarm mid-word).
  * **No fighting.** Before every operation it asks the transport who is in
    control; if another sender (the owner's HIDway client) is live, it
    disarms instead of taking over.
  * **Nothing kept.** Typed text and key names are never logged, stored or
    put in an error message; they live only for the call.

How states reach the PC is the transport's business (``InputTransport``):
``core/hidway.HidwayRelay`` speaks HIDway's protocol to the relay on this host,
over UDP or the relay's local socket.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Protocol, Sequence

from . import hid_keys

# Mouse button bits (HID boot mouse / HIDway ``buttons``).
BUTTONS = {"left": 0x01, "right": 0x02, "middle": 0x04}

# Limits that the configuration may lower but never raise.
HARD_MAX_TEXT = 256
HARD_MAX_STEP = 2000
HARD_MAX_WHEEL = 20
HARD_MAX_RATE = 60


@dataclass(frozen=True)
class Frame:
    """One complete input state: what is held right now, and where the mouse
    counters stand (cumulative, so a lost state loses no movement)."""
    mods: int = 0
    keys: frozenset[int] = field(default_factory=frozenset)
    buttons: int = 0
    x: int = 0
    y: int = 0
    wheel: int = 0


@dataclass(frozen=True)
class RelayView:
    """What can be seen about the relay without sending anything."""
    running: bool                 # the relay process publishes its state
    serial_open: bool | None = None   # its link to the Pico (None = unknown)
    target: str = "unknown"       # the PC as the Pico sees it: on/asleep/off/unknown
    encrypted: bool | None = None
    control: str = "none"         # who is sending right now: you / other / none
    problem: str = ""             # why it cannot be used ("" = usable)
    transport: str = ""           # how input goes: local (socket) / udp / "" unknown


class InputTransport(Protocol):
    """How complete input states reach the PC."""

    def view(self) -> RelayView:
        """Passive look at the relay: running, who has control. Sends nothing."""

    def start(self) -> None:
        """Begin a fresh session (on arm). Takes control only when the first
        state is sent."""

    def probe(self) -> bool:
        """Is the relay there and does it accept us? Never reaches the PC."""

    def send(self, frames: Sequence[Frame], cancel: threading.Event) -> str:
        """Send ``frames`` in order, paced. "" when the relay acknowledged them,
        else a short reason: ``no_answer``, ``input_fault``, ``cancelled``."""

    def release(self) -> None:
        """Everything up, now. Must not raise for a missing session."""

    def stop(self) -> None:
        """End the session (on disarm)."""


class RemoteError(Exception):
    """A refusal or failure the page shows as is. ``message`` never contains
    anything the owner typed."""

    def __init__(self, code: str, message: str, status: int = 409) -> None:
        super().__init__(code)
        self.code = code
        self.message = message
        self.status = status


_SEND_FAILED = {
    "no_answer": "The relay did not confirm it, so it may not have reached the PC. "
                 "Every key was released.",
    "input_fault": "The receiver dropped input it could not keep up with. "
                   "Every key was released — try again.",
    "cancelled": "Disarmed — stopped. Every key was released.",
}


def _clamp(value: Any, limit: int) -> int | None:
    """An int within ±limit; None when the value is not a number at all."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    if value != value:                       # NaN
        return None
    return int(max(-limit, min(limit, value)))


class RemoteInput:
    """The armed window, the allow-lists and the operations."""

    def __init__(self, transport: InputTransport, *, idle_timeout_s: float = 180.0,
                 rate_per_s: float = 25.0, max_text: int = 128, max_step: int = 400,
                 max_wheel: int = 10, logger: logging.Logger | None = None,
                 clock: Callable[[], float] = time.monotonic) -> None:
        self.transport = transport
        self.idle_timeout_s = max(15.0, min(float(idle_timeout_s), 3600.0))
        self.rate_per_s = max(1.0, min(float(rate_per_s), HARD_MAX_RATE))
        self.max_text = max(1, min(int(max_text), HARD_MAX_TEXT))
        self.max_step = max(1, min(int(max_step), HARD_MAX_STEP))
        self.max_wheel = max(1, min(int(max_wheel), HARD_MAX_WHEEL))
        self.log = logger or logging.getLogger(__name__)
        self._clock = clock
        self._state_lock = threading.Lock()   # armed window, counters, bucket
        self._op_lock = threading.Lock()      # one burst at a time
        self._cancel = threading.Event()
        self._armed_until = 0.0
        self._armed = False
        self._tokens = self.rate_per_s
        self._refill_ts = clock()
        self._x = self._y = self._wheel = 0
        self._last_error = ""

    # ─── the armed window ────────────────────────────────────────

    def _armed_left(self) -> float:
        """Seconds left; disarms (and says so in the log) once it ran out."""
        with self._state_lock:
            if not self._armed:
                return 0.0
            left = self._armed_until - self._clock()
            if left > 0:
                return left
            self._armed = False
            self._cancel.set()
        self.log.info("remote keyboard: disarmed after %d min without input",
                      round(self.idle_timeout_s / 60))
        self._release_and_stop()
        return 0.0

    def _release_and_stop(self) -> None:
        """Release and end the session unless a burst is running (it releases
        and stops by itself when it sees the cancel flag)."""
        if not self._op_lock.acquire(blocking=False):
            return
        try:
            self._safe_release()
            self._safe(self.transport.stop)
        finally:
            self._op_lock.release()

    def status(self) -> dict[str, Any]:
        left = self._armed_left()
        view = self._view()
        return {
            "armed": left > 0,
            "armed_left_s": int(left + 0.999),
            "idle_timeout_s": int(self.idle_timeout_s),
            "max_text_chars": self.max_text,
            "relay": "running" if view.running else "not running",
            "pico": ("connected" if view.serial_open else
                     "not connected" if view.serial_open is False else "unknown"),
            "pc": view.target,
            "encrypted": view.encrypted,
            "control": view.control,
            "transport": view.transport,
            "problem": view.problem,
            "error": self._last_error,
        }

    def arm(self) -> dict[str, Any]:
        view = self._view()
        if view.problem:
            raise RemoteError("relay_unusable", view.problem, 503)
        if view.control == "other":
            raise RemoteError("in_use", "The HIDway client on another computer is in "
                              "control right now. Disarm it there first.")
        with self._op_lock:
            try:
                self.transport.start()
                answered = self.transport.probe()
            except OSError as exc:              # e.g. source_host is not on this host
                self.log.warning("remote keyboard: cannot open the connection to the relay "
                                 "(%s)", type(exc).__name__)
                self._safe(self.transport.stop)
                hint = ("check that NetSentry's user is in the local socket's group "
                        "(restart NetSentry after adding it)" if view.transport == "local"
                        else "check relay_host and source_host")
                raise RemoteError("relay_unusable", "Cannot open a connection to the relay "
                                  f"from this host — {hint}.", 503) from None
            if not answered:
                self._safe(self.transport.stop)
                self._last_error = "The relay did not answer when arming."
                raise RemoteError(
                    "no_answer", "The relay did not answer. Nothing was sent to the PC. "
                    "Check that the relay allows this host and that the key matches "
                    "(see docs/WORKSTATION.md).", 503)
            with self._state_lock:
                self._armed = True
                self._armed_until = self._clock() + self.idle_timeout_s
                self._cancel.clear()
                self._tokens = self.rate_per_s
                self._last_error = ""
        self.log.info("remote keyboard: armed for %d min of inactivity",
                      round(self.idle_timeout_s / 60))
        return self.status()

    def disarm(self, reason: str = "from the page") -> dict[str, Any]:
        with self._state_lock:
            was = self._armed
            self._armed = False
            self._cancel.set()
        if was:
            self.log.info("remote keyboard: disarmed %s", reason)
        self._release_and_stop()
        return self.status()

    # ─── operations (each one burst, ending with everything up) ──

    def press_key(self, name: Any, mods: Any = None) -> dict[str, Any]:
        bits = hid_keys.mods_from_names(mods)
        stroke = hid_keys.key_stroke(name, bits or 0) if bits is not None else None
        if stroke is None:
            raise RemoteError("bad_key", "That key is not on the list this page may press.", 400)
        return self._run(self._stroke_frames([stroke]))

    def type_text(self, text: Any, *, enter: bool = False) -> dict[str, Any]:
        if not isinstance(text, str) or not text:
            raise RemoteError("bad_text", "Nothing to type.", 400)
        if len(text) > self.max_text:
            raise RemoteError("too_long", f"At most {self.max_text} characters at a time. "
                              "Nothing was typed.", 400)
        strokes = hid_keys.text_strokes(text)
        if strokes is None:
            raise RemoteError(
                "untypeable", "Some characters have no key on a US keyboard (letters with "
                "accents, Greek, emoji, line breaks). Nothing was typed.", 400)
        if enter:
            strokes.append(hid_keys.Stroke(0, hid_keys.KEYS["enter"]))
        return self._run(self._stroke_frames(strokes))

    def mouse(self, dx: Any = 0, dy: Any = 0, wheel: Any = 0, click: Any = None,
              double: bool = False) -> dict[str, Any]:
        mx, my = _clamp(dx, self.max_step), _clamp(dy, self.max_step)
        mw = _clamp(wheel, self.max_wheel)
        if mx is None or my is None or mw is None:
            raise RemoteError("bad_mouse", "Mouse values must be numbers.", 400)
        button = 0
        if click is not None:
            if not isinstance(click, str) or click not in BUTTONS:
                raise RemoteError("bad_mouse", "Unknown mouse button.", 400)
            button = BUTTONS[click]
        if not (mx or my or mw or button):
            raise RemoteError("bad_mouse", "Nothing to do.", 400)

        def frames() -> list[Frame]:
            with self._state_lock:
                before = Frame(x=self._x, y=self._y, wheel=self._wheel)
                if mx or my:
                    self._x = (self._x + mx) & 0xFFFFFFFF
                    self._y = (self._y + my) & 0xFFFFFFFF
                if mw:
                    self._wheel = (self._wheel + mw) & 0xFFFF
                at = {"x": self._x, "y": self._y, "wheel": self._wheel}
            out = [before]                       # where the counters stood: the baseline
            if mx or my or mw:
                out.append(Frame(**at))
            for _ in range(2 if (button and double) else 1 if button else 0):
                out += [Frame(buttons=button, **at), Frame(**at)]
            return out

        return self._run(frames)

    # ─── internals ───────────────────────────────────────────────

    def _stroke_frames(self, strokes: list[hid_keys.Stroke]) -> Callable[[], list[Frame]]:
        """Modifiers go down first, each key goes down and up while they are
        held, modifiers change only between keys, and the last state has
        nothing held."""
        def frames() -> list[Frame]:
            with self._state_lock:
                at = {"x": self._x, "y": self._y, "wheel": self._wheel}
            out: list[Frame] = [Frame(**at)]     # start from "nothing held"
            held = 0
            for s in strokes:
                if s.mods != held:
                    out.append(Frame(mods=s.mods, **at))
                    held = s.mods
                if s.usage:
                    out.append(Frame(mods=s.mods, keys=frozenset({s.usage}), **at))
                    out.append(Frame(mods=s.mods, **at))
            out.append(Frame(**at))
            return out
        return frames

    def _take_token(self) -> bool:
        now = self._clock()
        self._tokens = min(self.rate_per_s,
                           self._tokens + (now - self._refill_ts) * self.rate_per_s)
        self._refill_ts = now
        if self._tokens < 1.0:
            return False
        self._tokens -= 1.0
        return True

    def _run(self, build: Callable[[], list[Frame]]) -> dict[str, Any]:
        if self._armed_left() <= 0:
            raise RemoteError("not_armed", "Disarmed — tap Arm first. Nothing was sent.")
        with self._state_lock:
            allowed = self._take_token()
        if not allowed:
            raise RemoteError("slow_down", "Too fast — slow down a little. Nothing was sent.", 429)
        if not self._op_lock.acquire(timeout=0.5):
            raise RemoteError("busy", "Still sending the previous input. Nothing was sent.")
        reason = ""
        try:
            if self._cancel.is_set():
                raise RemoteError("not_armed", "Disarmed — tap Arm first. Nothing was sent.")
            view = self._view()
            if view.control == "other":
                with self._state_lock:
                    self._armed = False
                    self._cancel.set()
                self.log.info("remote keyboard: disarmed, the HIDway client took control")
                self._safe(self.transport.stop)
                raise RemoteError("in_use", "The HIDway client on another computer took "
                                  "control, so this page disarmed. Nothing was sent.")
            if view.problem:
                raise RemoteError("relay_unusable", view.problem, 503)
            try:
                reason = self.transport.send(build(), self._cancel)
            except Exception as exc:  # never echo input: log the type only
                self.log.warning("remote keyboard: sending failed (%s)", type(exc).__name__)
                reason = "no_answer"
            finally:
                self._safe_release()
            if self._cancel.is_set():
                self._safe(self.transport.stop)
                reason = "cancelled"
        finally:
            self._op_lock.release()
        if reason:
            self._last_error = _SEND_FAILED.get(reason, _SEND_FAILED["no_answer"])
            if reason != "cancelled":
                self.log.warning("remote keyboard: input not confirmed (%s)", reason)
            raise RemoteError(reason, self._last_error, 409 if reason == "cancelled" else 502)
        with self._state_lock:
            if self._armed:
                self._armed_until = self._clock() + self.idle_timeout_s
            self._last_error = ""
        return self.status()

    def _view(self) -> RelayView:
        try:
            return self.transport.view()
        except Exception as exc:
            self.log.warning("remote keyboard: cannot read the relay state (%s)",
                             type(exc).__name__)
            return RelayView(running=False, problem="The relay's state cannot be read.")

    def _safe_release(self) -> None:
        self._safe(self.transport.release)

    def _safe(self, func: Callable[[], Any]) -> None:
        try:
            func()
        except Exception as exc:
            self.log.warning("remote keyboard: %s failed (%s)",
                             getattr(func, "__name__", "call"), type(exc).__name__)
