"""
USB HID keyboard usages and a US-layout text map (pure, no I/O).

A USB keyboard does not send characters: it sends *key positions* (HID usage
ids from the Keyboard/Keypad page) plus modifier bits, and the computer's
active keyboard layout decides which character a position produces. This
module only knows the US layout: ``text_strokes("aA!")`` is "the keys a US
keyboard presses to type aA!". On a PC whose active layout is Greek (or
German, French…) the same strokes produce that layout's characters — the
remote keyboard page says so, and refuses characters it has no key for
instead of guessing.

Everything here is an allow-list: a key name or character that is not in the
tables is refused (``None``), never passed on.
"""

from __future__ import annotations

from dataclasses import dataclass

# Modifier bits, as the HID boot report (and HIDway's ``mods`` byte) carries
# them: bit n = usage 0xE0 + n. Only the left-hand ones are ever sent.
MOD_CTRL = 0x01
MOD_SHIFT = 0x02
MOD_ALT = 0x04
MOD_WIN = 0x08

MODIFIERS: dict[str, int] = {
    "ctrl": MOD_CTRL,
    "shift": MOD_SHIFT,
    "alt": MOD_ALT,
    "win": MOD_WIN,
}

# Highest usage HIDway's key bitmap carries (common/hidway_kbd.h).
USAGE_MAX = 0xA7

_LETTERS = {chr(ord("a") + i): 0x04 + i for i in range(26)}          # a..z
_DIGITS = {str((i + 1) % 10): 0x1E + i for i in range(10)}           # 1..9, 0

# Named keys the page may press (one tap = down + up). A name not listed here
# is refused by the server.
KEYS: dict[str, int] = {
    **_LETTERS,
    **_DIGITS,
    "enter": 0x28,
    "esc": 0x29,
    "backspace": 0x2A,
    "tab": 0x2B,
    "space": 0x2C,
    "capslock": 0x39,
    **{f"f{i}": 0x3A + i - 1 for i in range(1, 13)},                 # F1..F12
    "printscreen": 0x46,
    "pause": 0x48,
    "insert": 0x49,
    "home": 0x4A,
    "pageup": 0x4B,
    "delete": 0x4C,
    "end": 0x4D,
    "pagedown": 0x4E,
    "right": 0x4F,
    "left": 0x50,
    "down": 0x51,
    "up": 0x52,
    "menu": 0x65,
}

# Keys that are a modifier on their own: "win" opens the Start menu. They are
# pressed as a modifier bit with no key.
MODIFIER_KEYS: dict[str, int] = {"win": MOD_WIN}

# Printable US-layout characters: char -> (usage, shifted).
_US_UNSHIFTED = {
    " ": 0x2C, "-": 0x2D, "=": 0x2E, "[": 0x2F, "]": 0x30, "\\": 0x31,
    ";": 0x33, "'": 0x34, "`": 0x35, ",": 0x36, ".": 0x37, "/": 0x38,
}
_US_SHIFTED = {
    "!": 0x1E, "@": 0x1F, "#": 0x20, "$": 0x21, "%": 0x22, "^": 0x23,
    "&": 0x24, "*": 0x25, "(": 0x26, ")": 0x27,
    "_": 0x2D, "+": 0x2E, "{": 0x2F, "}": 0x30, "|": 0x31,
    ":": 0x33, '"': 0x34, "~": 0x35, "<": 0x36, ">": 0x37, "?": 0x38,
}

US_LAYOUT: dict[str, tuple[int, bool]] = {}
US_LAYOUT.update({c: (u, False) for c, u in _LETTERS.items()})
US_LAYOUT.update({c.upper(): (u, True) for c, u in _LETTERS.items()})
US_LAYOUT.update({c: (u, False) for c, u in _DIGITS.items()})
US_LAYOUT.update({c: (u, False) for c, u in _US_UNSHIFTED.items()})
US_LAYOUT.update({c: (u, True) for c, u in _US_SHIFTED.items()})


@dataclass(frozen=True)
class Stroke:
    """One key press: hold ``mods``, tap ``usage`` (0 = modifiers only)."""
    mods: int
    usage: int


def mods_from_names(names: object) -> int | None:
    """Modifier names (``["ctrl", "alt"]``) -> bits; None if anything is not
    a known modifier name or the list is not a short list of strings."""
    if names is None:
        return 0
    if not isinstance(names, (list, tuple)) or len(names) > len(MODIFIERS):
        return None
    bits = 0
    for name in names:
        if not isinstance(name, str) or name not in MODIFIERS:
            return None
        bits |= MODIFIERS[name]
    return bits


def key_stroke(name: object, mods: int = 0) -> Stroke | None:
    """The stroke for a named key with extra modifiers, or None if the name is
    not on the allow-list."""
    if not isinstance(name, str):
        return None
    if name in MODIFIER_KEYS:
        return Stroke(mods | MODIFIER_KEYS[name], 0)
    usage = KEYS.get(name)
    if usage is None:
        return None
    return Stroke(mods, usage)


def text_strokes(text: str) -> list[Stroke] | None:
    """The strokes that type ``text`` on a US layout, or None if any character
    has no key there (accents, Greek, emoji, control characters, newlines).
    Nothing is half-typed: the caller refuses the whole text."""
    out: list[Stroke] = []
    for ch in text:
        hit = US_LAYOUT.get(ch)
        if hit is None:
            return None
        usage, shifted = hit
        out.append(Stroke(MOD_SHIFT if shifted else 0, usage))
    return out
