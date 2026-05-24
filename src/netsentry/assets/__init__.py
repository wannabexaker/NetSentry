"""
Bundled branding assets.

Use via:
    from netsentry.assets import state_icon, logo_path

The PNGs ship inside the wheel/sdist so they're available regardless of
where NetSentry is installed.
"""

from __future__ import annotations

from pathlib import Path

# Five canonical alert states. Plugins should map their notifications
# to one of these — keep the visual language consistent across the bot.
STATES = ("protected", "scanning", "warning", "attack", "offline")

_HERE = Path(__file__).resolve().parent


def state_icon(state: str) -> Path:
    """Return the path to a state PNG. Falls back to `protected.png`."""
    state = (state or "").lower()
    if state not in STATES:
        state = "protected"
    return _HERE / "states" / f"{state}.png"


def logo_path(variant: str = "logo") -> Path:
    """
    variant:
        "logo"  → with NetSentry text  (for messages, README header)
        "mark"  → badge only           (for circle avatars / favicons)
    """
    if variant == "mark":
        return _HERE / "netsentry-mark.png"
    return _HERE / "netsentry-logo.png"


__all__ = ["STATES", "state_icon", "logo_path"]
