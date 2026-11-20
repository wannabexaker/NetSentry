"""
How loud NetSentry is: message kinds × the owner's notification mode.

Every *unprompted* message (an alert, a recovery, a scheduled report) is sent
with a kind; the owner picks one of three modes in /settings and the table
below decides whether it arrives with sound, silently, or not at all. Replies
to something the owner just did are not unprompted and never go through here.

| kind      | relaxed  | normal (default) | everything |
|-----------|----------|------------------|------------|
| urgent    | sound    | sound            | sound      |
| attention | silent   | sound            | sound      |
| recovery  | silent   | silent           | sound      |
| report    | silent   | silent           | sound      |
| info      | —        | silent           | sound      |
| success   | —        | —                | silent     |

The mode comes from the notifier's ``notify_mode`` config key and can be
changed live; a change made in Telegram is stored in a small state file and
wins over the config until it is changed again. Anything unreadable → normal.

This module also carries the hand-off between a plugin that alerted the owner
itself and the self-check watchdog, so one problem gives one alert and one
recovery (:func:`report_problem`).
"""

from __future__ import annotations

import logging
import threading
from pathlib import Path
from typing import Any

from .jsonstore import read_json, write_json

log = logging.getLogger(__name__)

URGENT = "urgent"         # 🚨 attack or outage
ATTENTION = "attention"   # ⚠️ needs you
RECOVERY = "recovery"     # ✅ back to normal
REPORT = "report"         # scheduled reports and briefings
INFO = "info"             # ℹ️ FYI, 🆕 new device
SUCCESS = "success"       # a scheduled job worked

KINDS = (URGENT, ATTENTION, RECOVERY, REPORT, INFO, SUCCESS)

RELAXED, NORMAL, EVERYTHING = "relaxed", "normal", "everything"
MODES = (RELAXED, NORMAL, EVERYTHING)
DEFAULT_MODE = NORMAL

SOUND, SILENT = "sound", "silent"

_TABLE: dict[str, dict[str, str | None]] = {
    URGENT:    {RELAXED: SOUND,  NORMAL: SOUND,  EVERYTHING: SOUND},
    ATTENTION: {RELAXED: SILENT, NORMAL: SOUND,  EVERYTHING: SOUND},
    RECOVERY:  {RELAXED: SILENT, NORMAL: SILENT, EVERYTHING: SOUND},
    REPORT:    {RELAXED: SILENT, NORMAL: SILENT, EVERYTHING: SOUND},
    INFO:      {RELAXED: None,   NORMAL: SILENT, EVERYTHING: SOUND},
    SUCCESS:   {RELAXED: None,   NORMAL: None,   EVERYTHING: SILENT},
}

# Shown in /settings → 🔔 Notifications.
MODE_INFO: dict[str, tuple[str, str]] = {
    RELAXED: ("😌 Relaxed",
              "Only attacks and outages make a sound. Problems arrive silently; "
              "FYI messages are not sent."),
    NORMAL: ("🔔 Normal",
             "Attacks, outages and problems make a sound. Reports, recoveries and "
             "new devices arrive silently."),
    EVERYTHING: ("📣 Everything",
                 "Every message makes a sound, and you also hear when a scheduled "
                 "job worked."),
}


def normalize_mode(value: Any) -> str:
    text = str(value or "").strip().lower()
    return text if text in MODES else DEFAULT_MODE


def delivery(kind: str, mode: str) -> str | None:
    """``"sound"``, ``"silent"`` or ``None`` (do not send) for one message.

    An unknown kind is treated as ``attention``: when in doubt, deliver.
    """
    row = _TABLE.get(kind, _TABLE[ATTENTION])
    return row[normalize_mode(mode)]


class NotifyPolicy:
    """The owner's notification mode: config default + a stored live override."""

    def __init__(self, default: Any = None, state_file: Path | str | None = None) -> None:
        self._default = normalize_mode(default)
        if default not in (None, "") and str(default).strip().lower() not in MODES:
            log.warning("notify_mode %r is not one of %s; using %s",
                        default, "/".join(MODES), self._default)
        self._file = Path(state_file) if state_file else None
        self._lock = threading.Lock()

    @property
    def mode(self) -> str:
        stored = self._stored()
        return normalize_mode(stored) if stored else self._default

    @property
    def default(self) -> str:
        return self._default

    def overridden(self) -> bool:
        return bool(self._stored())

    def set_mode(self, mode: str) -> bool:
        """Store ``mode`` (it then wins over the config). False for an unknown mode."""
        if str(mode).strip().lower() not in MODES:
            return False
        if self._file is None:
            self._default = str(mode).strip().lower()   # no state file: this run only
            return True
        with self._lock:
            try:
                write_json(self._file, {"mode": str(mode).strip().lower()})
            except OSError:
                log.exception("could not store the notification mode")
                return False
        log.info("Notification mode set to %s", mode)
        return True

    def delivery(self, kind: str) -> str | None:
        return delivery(kind, self.mode)

    def _stored(self) -> str:
        if self._file is None:
            return ""
        with self._lock:
            data = read_json(self._file, {})
        value = data.get("mode") if isinstance(data, dict) else None
        return str(value) if value else ""


# ─── one problem → one alert → one recovery ─────────────────────────

HEALTH_ALERTED = "health.alerted"


def report_problem(ctx: Any, check: str) -> bool:
    """A plugin just told the owner about a problem that its ``health()`` reports
    as the check named ``check``.

    The watchdog (self_check) then counts the owner as told: it sends no second
    "went bad" alert, and it sends the recovery once the check is OK again —
    even if that happens before its next round. Returns True when such a
    watchdog is loaded; a plugin that gets False should announce the recovery
    itself.
    """
    events = getattr(ctx, "events", None)
    if events is not None:
        try:
            events.publish(HEALTH_ALERTED, {"check": check})
        except Exception:
            log.exception("could not hand %r to the watchdog", check)
    return watchdog_loaded(ctx)


def watchdog_loaded(ctx: Any) -> bool:
    return any(getattr(getattr(p, "ctx", None), "name", "") == "self_check"
               for p in getattr(ctx, "_all_plugins", []) or [])
