"""
Reading what the root maintenance helper wrote.

NetSentry cannot run apt, prune Docker or reboot: it hands one word to the
root helper (``deploy/netsentry-maintenance-helper.sh``) through the power
plugin's request file. The helper answers in a root-owned folder NetSentry may
read but not write (default ``/var/lib/netsentry-maintenance``), so NetSentry
can never forge a plan. This module only reads that folder.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any

DEFAULT_OUT_DIR = "/var/lib/netsentry-maintenance"

#: What each helper word is called on screen.
LABELS: dict[str, str] = {
    "refresh": "The update check",
    "upgrade": "The upgrade",
    "prune": "The Docker clean-up",
    "kernels-plan": "The old-kernel check",
    "kernels": "The old-kernel removal",
    "eeprom": "The bootloader update",
    "status": "The status check",
    "health": "The health check",
    "reboot": "The restart",
}

# busy.json older than this is a leftover (the helper's own limit is 70 min).
_BUSY_STALE_S = 80 * 60


def read(out_dir: Path | str, name: str) -> dict[str, Any] | None:
    """One of the helper's JSON files, or None when missing or unreadable."""
    try:
        data = json.loads((Path(out_dir) / name).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def busy(out_dir: Path | str) -> dict[str, Any] | None:
    """``{"action", "started"}`` while the helper is running, else None.

    A file left behind by a helper that was killed (a reboot mid-run) does not
    count: its process is gone, or it is far older than any action can take.
    """
    data = read(out_dir, "busy.json")
    if not data:
        return None
    try:
        started = float(data.get("started") or 0)
    except (TypeError, ValueError):
        return None
    if time.time() - started > _BUSY_STALE_S:
        return None
    pid = data.get("pid")
    if isinstance(pid, int) and pid > 0 and os.path.isdir("/proc/self") \
            and not os.path.exists(f"/proc/{pid}"):
        return None
    return {"action": str(data.get("action") or ""), "started": started}


def label(action: str) -> str:
    return LABELS.get(action, f"The {action}")
