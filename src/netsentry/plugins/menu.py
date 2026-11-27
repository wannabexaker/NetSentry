"""
menu — every NetSentry command as buttons, so there is nothing to memorise.

`/menu` opens a home screen of categories; a category lists its commands as
buttons; tapping one runs it exactly as if you had typed it (same confirmation
step for the risky ones). The screens are built from the commands the loaded
plugins register, so a new plugin shows up here by itself.

Commands that need a choice open their own button screen when tapped
(/rotation, /scans, /audit, /allow, /kick …).
"""

from __future__ import annotations

from ..core import ui
from ..core.plugin import Plugin

# Category → the plugins whose commands belong there, in display order.
_CATEGORIES: list[tuple[str, str, tuple[str, ...]]] = [
    ("net", "🌐 Network", ("router_info", "lan_scanner", "locator", "lan_dashboard",
                           "pihole_stats", "speedtest", "channel_scan",
                           "traffic_report")),
    ("sec", "🛡 Security", ("threat_detector", "who_asked", "security_actions",
                           "wifi_monitor")),
    ("guest", "📶 Guest WiFi", ("guest_wifi_rotator",)),
    ("sys", "🩺 System", ("self_check", "site_watch", "access", "settings", "power", "maintenance",
                         "workstation",
                         "ai_control",
                         "config_backup",
                         "self_backup", "health_monitor", "morning_briefing",
                         "telegram_bot")),
    ("lib", "📚 Library", ("youtube_bookmarks", "github_explorer")),
]
_OTHER = ("other", "🧩 Other")


class MenuPlugin(Plugin):
    COMMANDS = [
        {"command": "menu", "description": "🧭 Everything as buttons"},
    ]

    def on_command(self, command: str, args: str, chat_id: int) -> None:
        if command == "/menu":
            self._show_home(chat_id, None)

    def on_callback(self, data: str, chat_id: int, message_id: int,
                    callback_id: str) -> None:
        # menu:h (home) | menu:c:<category> | menu:r:<command>
        verb, _, arg = data.partition(":")[2].partition(":")
        answer = getattr(self.notifier, "answer_callback", None)

        def ack(text: str = "") -> None:
            if answer:
                answer(callback_id, text)

        if verb == "c":
            ack()
            self._show_category(chat_id, message_id, arg)
        elif verb == "r":
            bot = self._bot()
            known = {cmd for cmd, _, _ in self._catalog()}
            if bot is None or arg not in known:
                ack("Not available")
                return
            ack(arg)
            bot.dispatch_command(arg, "", chat_id)
        else:
            ack()
            self._show_home(chat_id, message_id)

    # ─── screens ─────────────────────────────────────────────────

    def show_home(self, chat_id: int, note: str = "") -> None:
        """Open the home screen as a new message, with an optional line on top
        (the bot uses it for /start and for a command it doesn't know)."""
        self._show_home(chat_id, None, note)

    def _show_home(self, chat_id: int, message_id: int | None, note: str = "") -> None:
        name = self.ctx.name
        cells = [{"text": f"{label} ({len(cmds)})", "callback_data": f"{name}:c:{key}"}
                 for key, label, cmds in self._grouped()]
        rows = [cells[i:i + 2] for i in range(0, len(cells), 2)]
        self._show(chat_id, message_id,
                   (f"{note}\n\n" if note else "")
                   + ui.title("🧭", "NetSentry menu") + "\n"
                   "Pick an area, then tap what you want. Nothing to type.", rows)

    def _show_category(self, chat_id: int, message_id: int, key: str) -> None:
        group = next((g for g in self._grouped() if g[0] == key), None)
        if group is None:
            self._show_home(chat_id, message_id)
            return
        name = self.ctx.name
        _, label, cmds = group
        rows = [[{"text": _button_label(cmd, desc), "callback_data": f"{name}:r:{cmd}"}]
                for cmd, desc in cmds]
        rows.append([{"text": "⬅ Back", "callback_data": f"{name}:h"}])
        # (menu:h is also the "🏠 Menu" button other screens put on their last row)
        self._show(chat_id, message_id,
                   f"{label}\n{ui.RULE}\nTap to run.", rows)

    def _show(self, chat_id: int, message_id: int | None, text: str,
              buttons: list) -> None:
        edit = getattr(self.notifier, "edit_message", None)
        if message_id is not None and edit:
            edit(chat_id, message_id, text, buttons=buttons)
        else:
            self.notifier.send_to(chat_id, text, buttons=buttons)

    # ─── catalogue ───────────────────────────────────────────────

    def _bot(self) -> Plugin | None:
        return next((p for p in getattr(self.ctx, "_all_plugins", [])
                     if hasattr(p, "dispatch_command")), None)

    def _catalog(self) -> list[tuple[str, str, str]]:
        """``(command, description, plugin)`` for everything but this menu."""
        bot = self._bot()
        if bot is None:
            return []
        return [(cmd, desc, plugin) for cmd, desc, plugin in bot.command_catalog()
                if plugin != self.ctx.name]

    def _grouped(self) -> list[tuple[str, str, list[tuple[str, str]]]]:
        """Non-empty categories as ``(key, label, [(command, description)])``."""
        catalog = self._catalog()
        placed: set[str] = set()
        out = []
        for key, label, plugins in _CATEGORIES:
            cmds = [(cmd, desc) for p in plugins
                    for cmd, desc, plugin in catalog if plugin == p]
            placed.update(cmd for cmd, _ in cmds)
            if cmds:
                out.append((key, label, cmds))
        rest = [(cmd, desc) for cmd, desc, _ in catalog if cmd not in placed]
        if rest:
            out.append((*_OTHER, rest))
        return out


def _button_label(cmd: str, desc: str) -> str:
    """Button text: the command's own description, minus any usage hint."""
    text = desc.split(":", 1)[0].split("(/", 1)[0].strip() or cmd
    return text if len(text) <= 44 else text[:43] + "…"
