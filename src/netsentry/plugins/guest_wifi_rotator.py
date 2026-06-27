"""
guest_wifi_rotator — Rotate a guest WiFi password on a schedule and on demand.

Telegram commands:
    /rotate    Generate new password + QR, push to router, send QR to chat.
    /guest     Show the current guest password + QR (no rotation).

Config keys:
    ssid                 SSID name to advertise in QR (e.g. "Guest")
    security_profile     Router security profile to update (e.g. "guest-visitor")
    rotation_cron        5-field cron (default: Mondays 09:00)
    diceware_words       Words in generated password (default 4)
    diceware_digits      Trailing digits (default 4)
    throttle_seconds     Min interval between manual /rotate calls (default 30)
"""

from __future__ import annotations

import secrets
import subprocess
import time
from datetime import datetime
from pathlib import Path

from ..core.plugin import Plugin, ScheduledTask


DICEWARE_WORDS = (
    "amber bronze clay coral delta emerald forest granite hazel iris jade kestrel "
    "lotus mango nectar opal pearl quartz raven sable thunder umber violet whisper "
    "xenon yellow zephyr canyon river ocean meadow island summit valley harbor "
    "garden orchard breeze cinder dawn ember frost glade horizon ivory juniper "
    "kelp linden moss nettle oak pinion ridge sienna tundra willow brook cedar "
    "dune elm fern grove"
).split()


class GuestWifiRotatorPlugin(Plugin):
    COMMANDS = [
        {"command": "rotate", "description": "🔄 Rotate guest WiFi password + QR"},
        {"command": "guest",  "description": "🔐 Show current guest password + QR"},
    ]

    def on_load(self) -> None:
        self._last_rotate_ts = 0.0

    # ─── scheduled rotation ──────────────────────────────────────

    def scheduled_tasks(self) -> list[ScheduledTask]:
        cron = self.cfg.get("rotation_cron", "0 9 * * 1")
        return [ScheduledTask(cron=cron, func=self.rotate, name="rotate")]

    # ─── commands ────────────────────────────────────────────────

    def on_command(self, command: str, args: str, chat_id: int) -> None:
        if command == "/rotate":
            self._handle_rotate(chat_id)
        elif command == "/guest":
            self._handle_show(chat_id)

    def _handle_rotate(self, chat_id: int) -> None:
        throttle = int(self.cfg.get("throttle_seconds", 30))
        elapsed = time.time() - self._last_rotate_ts
        if elapsed < throttle:
            self.notifier.send_to(chat_id, f"⏳ Throttled. Try again in {int(throttle - elapsed)}s.")
            return
        self._last_rotate_ts = time.time()
        self.notifier.send_to(chat_id, "🔄 Rotating…")
        self.rotate(target_chat=chat_id)

    def _handle_show(self, chat_id: int) -> None:
        profile = self.cfg["security_profile"]
        passphrase = self.router.get_wifi_passphrase(profile)
        if not passphrase:
            self.notifier.send_to(chat_id, "❌ Couldn't read current passphrase.")
            return
        ssid = self.cfg.get("ssid", "Guest")
        self._send_qr(chat_id, passphrase, caption_prefix=f"🔐 Current {ssid}")

    # ─── core logic ──────────────────────────────────────────────

    def rotate(self, target_chat: int | None = None) -> None:
        """Generate new password, push to router, send QR. Used by cron + /rotate."""
        ssid = self.cfg["ssid"]
        profile = self.cfg["security_profile"]
        n_words = int(self.cfg.get("diceware_words", 4))
        n_digits = int(self.cfg.get("diceware_digits", 4))

        new_pass = self._generate_passphrase(n_words, n_digits)
        ok = self.router.set_wifi_passphrase(profile, new_pass)
        if not ok:
            msg = f"❌ Rotation failed: router read-back verification failed. Profile={profile}"
            self.log.error("Failed to set and verify passphrase on router profile %s", profile)
            if target_chat is not None and hasattr(self.notifier, "send_to"):
                self.notifier.send_to(target_chat, msg)
            else:
                self.notifier.send(msg)
            return

        self.log.info("Rotated %s passphrase", profile)

        if self.ctx.events:
            self.ctx.events.publish("wifi.password.rotated",
                                    {"ssid": ssid, "profile": profile})

        chat = target_chat if target_chat is not None else None
        self._send_qr(chat, new_pass, caption_prefix=f"🔐 New {ssid} password",
                      ssid=ssid)

    def _send_qr(self, chat_id: int | None, passphrase: str,
                 caption_prefix: str, ssid: str | None = None) -> None:
        """Generate WIFI-format QR code, send via Telegram."""
        ssid = ssid or self.cfg["ssid"]
        wifi_str = f"WIFI:S:{ssid};T:WPA;P:{passphrase};;"
        png_path = Path(self.ctx.state_dir) / f"qr-{int(time.time())}.png"
        png_path.parent.mkdir(parents=True, exist_ok=True)
        if not _make_qr(wifi_str, png_path):
            self.notifier.send(f"❌ QR generation failed.\nPassword: {passphrase}")
            return

        caption = (
            f"{caption_prefix}\n"
            f"SSID: {ssid}\n"
            f"Password: {passphrase}\n"
            f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M')}"
        )
        if chat_id is not None:
            self.notifier.send_to(chat_id, caption, photo_path=str(png_path))
        else:
            self.notifier.send(caption, photo_path=str(png_path))

        try:
            png_path.unlink()
        except OSError:
            pass

    def _generate_passphrase(self, n_words: int, n_digits: int) -> str:
        rng = secrets.SystemRandom()
        words = rng.sample(DICEWARE_WORDS, n_words)
        digits = "".join(secrets.choice("0123456789") for _ in range(n_digits))
        prefix = (self.cfg.get("password_prefix") or "guest").lower()
        return f"{prefix}-" + "-".join(words) + "-" + digits


def _make_qr(content: str, out_path: Path) -> bool:
    """Generate a PNG QR. Tries `qrcode` (pip) first, then `qrencode` (system)."""
    try:
        import qrcode
        img = qrcode.make(content, box_size=10, border=4)
        img.save(out_path)
        return True
    except ImportError:
        pass
    try:
        r = subprocess.run(
            ["qrencode", "-t", "PNG", "-s", "10", "-m", "4", "-o", str(out_path), content],
            capture_output=True, timeout=10,
        )
        return r.returncode == 0
    except Exception:
        return False
