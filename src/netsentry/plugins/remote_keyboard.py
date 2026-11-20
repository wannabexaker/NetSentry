"""
remote_keyboard — type and use the mouse on the gaming PC from the phone.

The dashboard's Remote page (``/remote``) sends keys, text and mouse moves
here; they reach the PC as real USB keyboard/mouse input through HIDway's
relay on this host (``core/hidway.py``), so they work at the Windows login
screen and in the BIOS too. The rules — disarmed by default, an idle
timeout, allow-lists, a rate limit, no stuck keys, never fighting the owner's
own HIDway client — live in ``core/remote_input.py``. Keystrokes never go
through Telegram and are never logged or stored. Set-up and the security model:
docs/WORKSTATION.md, "Remote keyboard".

Off unless configured: the plugin must be enabled AND ``relay_host`` set.
Config keys:
    relay_host        the address hidwayd listens on (its HIDWAY_BIND, i.e. this
                      host's Tailscale address)
    relay_port        default 47800 (HIDWAY_PORT)
    source_host       the address NetSentry sends from (default = relay_host);
                      the relay must allow it (HIDWAY_ALLOW_EXTRA)
    key               the relay's 64-hex-character key (hidwayd.key), best as
                      ${vault:HIDWAY_KEY}
    allow_plaintext   true only for a relay without encryption (default false:
                      without a key nothing is sent)
    relay_state_file  default /run/hidway/state
    idle_timeout_s    disarm after this long without input (default 180)
    rate_limit_per_s  inputs per second (default 25)
    max_text_chars    characters per send (default 128, at most 256)
    max_mouse_step    largest move per send, in mouse counts (default 400)
    key_interval_ms   pause between key states (default 10)
"""

from __future__ import annotations

from typing import Any

from ..core.hidway import HidwayError, HidwayRelay, parse_key
from ..core.plugin import HealthCheck, Plugin
from ..core.remote_input import RemoteInput

HEALTH_NAME = "Remote keyboard"


class RemoteKeyboardPlugin(Plugin):
    """Owns the remote-input controller; the dashboard calls ``remote``."""

    def on_load(self) -> None:
        self.remote: RemoteInput | None = None
        self.setup_error = ""
        cfg = self.cfg
        host = str(cfg.get("relay_host") or "").strip()
        if not host:
            self.log.info("remote_keyboard: relay_host is not set; the Remote page stays off")
            return
        try:
            key = None
            if str(cfg.get("key") or "").strip():
                key = parse_key(cfg.get("key"))
            elif not bool(cfg.get("allow_plaintext", False)):
                raise HidwayError("no key is set (and allow_plaintext is false)")
            transport = HidwayRelay(
                host, int(cfg.get("relay_port", 47800)),
                source_host=str(cfg.get("source_host") or "").strip(),
                key=key,
                state_file=str(cfg.get("relay_state_file") or "/run/hidway/state"),
                frame_gap_s=float(cfg.get("key_interval_ms", 10)) / 1000.0,
                logger=self.log)
            self.remote = RemoteInput(
                transport,
                idle_timeout_s=float(cfg.get("idle_timeout_s", 180)),
                rate_per_s=float(cfg.get("rate_limit_per_s", 25)),
                max_text=int(cfg.get("max_text_chars", 128)),
                max_step=int(cfg.get("max_mouse_step", 400)),
                logger=self.log)
        except (HidwayError, ValueError, TypeError) as exc:
            # HidwayError never quotes the key; ValueError/TypeError come from
            # the number fields only.
            self.setup_error = str(exc) if isinstance(exc, HidwayError) else "a number setting is not a number"
            self.remote = None
            self.log.error("remote_keyboard: settings not usable: %s", self.setup_error)
            return
        self.log.info("remote_keyboard: ready (relay %s:%s, %s)", host,
                      cfg.get("relay_port", 47800),
                      "encrypted" if key is not None else "plaintext")

    def on_unload(self) -> None:
        if self.remote is not None:
            self.remote.disarm("on shutdown")

    @property
    def configured(self) -> bool:
        """True when the Remote page should exist (enabled and usable)."""
        return getattr(self, "remote", None) is not None

    def api_status(self) -> dict[str, Any]:
        if self.remote is None:
            return {"configured": False}
        return {"configured": True, **self.remote.status()}

    def health(self) -> list[HealthCheck]:
        """A fault only when it is configured but cannot work: settings that do
        not load, or a relay that is not running / refuses our key mode.
        Passive — reads the relay's state file, sends nothing."""
        if getattr(self, "setup_error", ""):
            return [HealthCheck(HEALTH_NAME, False, f"settings not usable: {self.setup_error}")]
        remote = getattr(self, "remote", None)
        if remote is None:
            return []
        view = remote.transport.view()
        if view.problem:
            return [HealthCheck(HEALTH_NAME, False, view.problem.rstrip("."))]
        pico = ("Pico connected" if view.serial_open else
                "Pico not connected" if view.serial_open is False else "Pico unknown")
        return [HealthCheck(HEALTH_NAME, True, f"relay running, {pico}")]


PLUGIN = RemoteKeyboardPlugin
