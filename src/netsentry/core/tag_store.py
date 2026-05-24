"""Shared persistent MAC tag store."""

from __future__ import annotations

import json
import os
import re
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Iterator


_MAC_RE = re.compile(r"^[0-9A-F]{2}(:[0-9A-F]{2}){5}$", re.IGNORECASE)
_COMPACT_MAC_RE = re.compile(r"^[0-9A-F]{12}$", re.IGNORECASE)
_RESERVED_KEYS = {"retired_tags"}


class TagStore:
    """Read and write NetSentry MAC tags with locking and schema compatibility."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path).expanduser()

    @staticmethod
    def normalize_mac(value: str) -> str | None:
        """Return a canonical uppercase MAC address, or None if invalid."""
        text = (value or "").strip().upper().replace("-", ":")
        if _MAC_RE.fullmatch(text):
            return text
        compact = text.replace(":", "")
        if _COMPACT_MAC_RE.fullmatch(compact):
            return ":".join(compact[i:i + 2] for i in range(0, 12, 2))
        return None

    @staticmethod
    def fallback_lan_scanner_path() -> Path:
        """Return the dashboard fallback path for the lan_scanner tag file."""
        state_base = os.environ.get("NETSENTRY_STATE_DIR")
        if state_base:
            return Path(state_base).expanduser() / "lan_scanner" / "tags.json"
        local_share = Path("~/.local/share/netsentry/lan_scanner/tags.json").expanduser()
        config_state = Path("~/.config/netsentry/state/lan_scanner/tags.json").expanduser()
        return local_share if local_share.exists() else config_state

    def snapshot(self) -> dict[str, Any]:
        """Return the whole tag JSON document as a normalized copy."""
        with self._locked():
            return self._read_unlocked()

    def replace(self, tags: dict[str, Any]) -> None:
        """Replace the whole tag JSON document."""
        with self._locked():
            self._write_unlocked(self._normalize_document(tags))

    def get(self, mac: str, *, include_retired: bool = True) -> dict[str, Any] | None:
        """Return tag metadata for a MAC address."""
        norm = self.normalize_mac(mac)
        if not norm:
            return None
        with self._locked():
            tags = self._read_unlocked()
        return self.entry_from_snapshot(norm, tags, include_retired=include_retired)

    def name_for(self, mac: str, *, include_retired: bool = True) -> str | None:
        """Return the friendly name for a MAC address."""
        entry = self.get(mac, include_retired=include_retired)
        if not isinstance(entry, dict):
            return None
        name = str(entry.get("name", "") or "").strip()
        return name or None

    def set(self, mac: str, name: str, *, source: str = "") -> dict[str, Any] | None:
        """Assign or update a friendly name for a MAC address."""
        norm = self.normalize_mac(mac)
        if not norm:
            raise ValueError(f"Bad MAC: {mac}")
        clean_name = name.strip()[:80]
        if not clean_name:
            raise ValueError("Tag name cannot be empty")

        with self._locked():
            tags = self._read_unlocked()
            previous = self.entry_from_snapshot(norm, tags, include_retired=True)
            now = self._now()
            retired = tags.get("retired_tags")
            if isinstance(retired, dict):
                retired.pop(norm, None)
            elif retired is not None:
                tags["retired_tags"] = {}

            tagged_at = (
                str(previous.get("tagged_at", "") or "")
                if isinstance(previous, dict) and not previous.get("retired")
                else ""
            )
            entry: dict[str, Any] = {
                "name": clean_name,
                "tagged_at": tagged_at or now,
                "updated_at": now,
            }
            if source:
                entry["source"] = source
            tags[norm] = entry
            self._write_unlocked(tags)
            return dict(previous) if isinstance(previous, dict) else None

    def remove(self, mac: str) -> dict[str, Any] | None:
        """Remove active and retired tag data for a MAC address."""
        norm = self.normalize_mac(mac)
        if not norm:
            raise ValueError(f"Bad MAC: {mac}")
        with self._locked():
            tags = self._read_unlocked()
            previous = self.entry_from_snapshot(norm, tags, include_retired=True)
            tags.pop(norm, None)
            retired = tags.get("retired_tags")
            if isinstance(retired, dict):
                retired.pop(norm, None)
            self._write_unlocked(tags)
            return dict(previous) if isinstance(previous, dict) else None

    def retire(self, mac: str) -> dict[str, Any]:
        """Mark a MAC tag as retired while preserving its historical name."""
        norm = self.normalize_mac(mac)
        if not norm:
            raise ValueError(f"Bad MAC: {mac}")
        with self._locked():
            tags = self._read_unlocked()
            retired = tags.setdefault("retired_tags", {})
            if not isinstance(retired, dict):
                retired = {}
                tags["retired_tags"] = retired
            current = self.entry_from_snapshot(norm, tags, include_retired=True) or {}
            now = self._now()
            entry = {
                **current,
                "name": str(current.get("name", "") or ""),
                "retired": True,
                "retired_at": now,
                "updated_at": now,
            }
            retired[norm] = entry
            tags[norm] = entry
            self._write_unlocked(tags)
            return dict(entry)

    def has_active(self, mac: str) -> bool:
        """Return True when a MAC has a non-retired tag."""
        entry = self.get(mac, include_retired=False)
        return bool(entry and str(entry.get("name", "") or "").strip())

    def tag_info(self, mac: str) -> tuple[str, bool]:
        """Return (name, retired) for a MAC address."""
        return self.tag_info_from_snapshot(mac, self.snapshot())

    def label_for(self, mac: str, ip: str = "", hostname: str = "") -> str:
        """Return a human-readable device label that prefers the MAC tag."""
        name, retired = self.tag_info(mac)
        return self.format_label(mac, name, retired, ip=ip, hostname=hostname)

    @classmethod
    def tag_info_from_snapshot(
        cls,
        mac: str,
        tags: dict[str, Any],
    ) -> tuple[str, bool]:
        """Return (name, retired) for a MAC from an already-loaded snapshot."""
        norm = cls.normalize_mac(mac)
        if not norm:
            return "", False
        entry = cls.entry_from_snapshot(norm, tags, include_retired=True)
        if not isinstance(entry, dict):
            return "", False
        return str(entry.get("name", "") or ""), bool(entry.get("retired"))

    @classmethod
    def has_active_in_snapshot(cls, mac: str, tags: dict[str, Any]) -> bool:
        """Return True when a snapshot contains a non-retired tag for a MAC."""
        norm = cls.normalize_mac(mac)
        if not norm:
            return False
        entry = cls.entry_from_snapshot(norm, tags, include_retired=False)
        return bool(entry and str(entry.get("name", "") or "").strip())

    @classmethod
    def entry_from_snapshot(
        cls,
        mac: str,
        tags: dict[str, Any],
        *,
        include_retired: bool = True,
    ) -> dict[str, Any] | None:
        """Return a normalized entry from an already-loaded snapshot."""
        norm = cls.normalize_mac(mac)
        if not norm or not isinstance(tags, dict):
            return None
        current = tags.get(norm)
        retired = False
        if isinstance(current, dict):
            retired = bool(current.get("retired"))
            if not retired or include_retired:
                return dict(current)

        if not include_retired:
            return None

        retired_tags = tags.get("retired_tags")
        if isinstance(retired_tags, dict):
            retired_entry = retired_tags.get(norm)
            if isinstance(retired_entry, dict):
                entry = dict(retired_entry)
                entry["retired"] = True
                return entry
        return None

    @staticmethod
    def format_label(
        mac: str,
        name: str = "",
        retired: bool = False,
        *,
        ip: str = "",
        hostname: str = "",
    ) -> str:
        """Format a compact label for buttons and Telegram messages."""
        clean_name = (name or "").strip()
        if clean_name:
            suffix = " (retired)" if retired else ""
            return f"{clean_name}{suffix} - {mac}"
        if hostname and hostname != "(no hostname)":
            return f"{hostname} - {mac}"
        if ip and ip != "?":
            return f"{ip} - {mac}"
        return mac

    @contextmanager
    def _locked(self) -> Iterator[None]:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        lock_path = self.path.with_suffix(self.path.suffix + ".lock")
        with lock_path.open("a+b") as lock:
            self._lock_handle(lock)
            try:
                if not self.path.exists():
                    self.path.write_text("{}", encoding="utf-8")
                yield
            finally:
                self._unlock_handle(lock)

    def _read_unlocked(self) -> dict[str, Any]:
        try:
            raw = self.path.read_text(encoding="utf-8")
            data = json.loads(raw) if raw.strip() else {}
        except (OSError, json.JSONDecodeError, TypeError):
            data = {}
        return self._normalize_document(data)

    def _write_unlocked(self, data: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_name(f"{self.path.name}.tmp")
        tmp.write_text(
            json.dumps(self._normalize_document(data), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        tmp.replace(self.path)

    @classmethod
    def _normalize_document(cls, data: Any) -> dict[str, Any]:
        if not isinstance(data, dict):
            return {}
        out: dict[str, Any] = {}
        retired_out: dict[str, Any] = {}

        raw_retired = data.get("retired_tags")
        if isinstance(raw_retired, dict):
            for raw_mac, entry in raw_retired.items():
                norm = cls.normalize_mac(str(raw_mac))
                if norm and isinstance(entry, dict):
                    retired_entry = dict(entry)
                    retired_entry["retired"] = True
                    retired_out[norm] = retired_entry

        for raw_mac, entry in data.items():
            if raw_mac in _RESERVED_KEYS:
                continue
            norm = cls.normalize_mac(str(raw_mac))
            if norm and isinstance(entry, dict):
                out[norm] = dict(entry)

        if retired_out:
            out["retired_tags"] = retired_out
        return out

    @staticmethod
    def _now() -> str:
        return datetime.now().isoformat(timespec="seconds")

    @staticmethod
    def _lock_handle(handle: Any) -> None:
        if os.name == "nt":
            import msvcrt

            handle.seek(0)
            handle.write(b"0")
            handle.flush()
            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_LOCK, 1)
        else:
            import fcntl

            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)

    @staticmethod
    def _unlock_handle(handle: Any) -> None:
        if os.name == "nt":
            import msvcrt

            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
