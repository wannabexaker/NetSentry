#!/usr/bin/env python3
"""NetSentry read agent — the ONLY thing the read-only ssh key may run.

The key is pinned to this script in the service user's authorized_keys with

    restrict,from="<PC address>",command="/usr/bin/python3 -I <path>/netsentry_read.py" <key>

so whatever the caller asks for arrives here as text in SSH_ORIGINAL_COMMAND.
It is only ever compared, whole and exactly, against the fixed list below.
Nothing from it is executed, interpolated, logged or passed on, and no
argument in it is honoured. A listed action prints one JSON object on one
line (under 8 KB) and exits 0; anything else prints one line on stderr and
exits 64.

What it prints comes from the snapshot NetSentry's read_access plugin writes
(already cleaned) — this script reads that one file and nothing else. It uses
the standard library only, never imports NetSentry, opens no network
connection and writes nothing but stdout/stderr. Run it as ``python3 -I`` so
no environment variable or nearby file can change what it imports.

The answers are documented in docs/READ_ACCESS.md. To remove the access:
delete the key's line from authorized_keys (see README.md next to this file).
"""

from __future__ import annotations

import json
import os
import sys
import time

ACTIONS = ("status", "findings", "alerts", "health")
# Where read_access writes (the service user's state folder). If the service
# runs with NETSENTRY_STATE_DIR, pass --snapshot in the authorized_keys command.
DEFAULT_SNAPSHOT = "~/.local/share/netsentry/read_access/snapshot.json"
MAX_AGE_S = 600                 # older than this: NetSentry is not writing it
MAX_ANSWER_BYTES = 8192         # every answer is shorter than this
MAX_SNAPSHOT_BYTES = 1 << 20
REFUSED = 64
_LISTS = ("items", "failing")   # trimmed from the end if an answer is too large
_ENVELOPE = ("ok", "action", "generated", "age_s")


def answer(request: object, snapshot_path: str, now: float) -> tuple[int, str, str]:
    """(exit code, stdout line, stderr line) for one request. Pure: no output."""
    if not isinstance(request, str) or request not in ACTIONS:
        return REFUSED, "", "netsentry-read: that action is not on the list"
    try:
        return 0, _render(request, snapshot_path, now), ""
    except Exception:
        return 0, _dump(_refusal(request, "the snapshot could not be read")), ""


def _refusal(action: str, reason: str, **extra: object) -> dict:
    return {"ok": False, "action": action, **extra, "reason": reason}


def _render(action: str, path: str, now: float) -> str:
    snap, reason = _load(path)
    if snap is None:
        return _dump(_refusal(action, reason))
    generated, ts = snap.get("generated"), snap.get("generated_ts")
    if not isinstance(generated, str) or isinstance(ts, bool) or not isinstance(ts, (int, float)):
        return _dump(_refusal(action, "the snapshot is damaged"))
    generated = generated[:40]
    age = max(0, int(now - ts))
    if age > MAX_AGE_S:
        return _dump(_refusal(action, f"the snapshot is {age // 60} min old: NetSentry "
                                      "is not writing it", generated=generated, age_s=age))
    section = snap.get(action)
    if not isinstance(section, dict):
        return _dump(_refusal(action, "this part is missing from the snapshot",
                              generated=generated, age_s=age))
    out = {"ok": True, "action": action, "generated": generated, "age_s": age}
    out.update((k, v) for k, v in section.items() if k not in _ENVELOPE)
    return _fit(out)


def _load(path: str) -> tuple[dict | None, str]:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    try:
        fd = os.open(path, flags)
    except FileNotFoundError:
        return None, "no snapshot: NetSentry is not running or read_access is not enabled"
    except OSError:
        return None, "the snapshot cannot be opened"
    with os.fdopen(fd, "rb") as f:
        raw = f.read(MAX_SNAPSHOT_BYTES + 1)
    if len(raw) > MAX_SNAPSHOT_BYTES:
        return None, "the snapshot is too large"
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        return None, "the snapshot is damaged"
    if not isinstance(data, dict):
        return None, "the snapshot is damaged"
    return data, ""


def _dump(obj: dict) -> str:
    # ensure_ascii: one line of plain ASCII whatever the strings contain.
    return json.dumps(obj, ensure_ascii=True, separators=(",", ":"), allow_nan=False)


def _fit(out: dict) -> str:
    text = _dump(out)
    for key in _LISTS:
        items = out.get(key)
        while isinstance(items, list) and items and len(text) >= MAX_ANSWER_BYTES:
            items.pop()
            text = _dump(out)
    if len(text) >= MAX_ANSWER_BYTES:
        return _dump(_refusal(out["action"], "the answer would be too large",
                              generated=out["generated"], age_s=out["age_s"]))
    return text


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    path = DEFAULT_SNAPSHOT
    if args:
        # Only the authorized_keys command line can pass this, never the caller.
        if len(args) == 2 and args[0] == "--snapshot" and args[1]:
            path = args[1]
        else:
            sys.stderr.write("netsentry-read: usage: netsentry_read.py [--snapshot PATH]\n")
            return REFUSED
    code, out, err = answer(os.environ.get("SSH_ORIGINAL_COMMAND", ""),
                            os.path.expanduser(path), time.time())
    if out:
        sys.stdout.write(out + "\n")
    if err:
        sys.stderr.write(err + "\n")
    return code


if __name__ == "__main__":
    sys.exit(main())
