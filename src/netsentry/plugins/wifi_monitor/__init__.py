"""wifi_monitor — passive 802.11 attack detection off a monitor-mode adapter.

Uses a dedicated USB Wi-Fi adapter (e.g. RTL8821AU as ``wlan1``) put into
monitor mode to watch management frames and flag two classic attacks:

* **NS-WIFI-001 deauth/disassoc flood** — someone spraying deauthentication
  frames to kick your devices off Wi-Fi (jamming, or a prelude to an evil-twin
  / handshake-capture attack);
* **NS-WIFI-002 rogue AP / evil-twin** — one of *your* SSIDs being broadcast by
  an access point whose BSSID isn't yours.

The radio + capture live here; the detection is pure (``detect.py``) and the
findings are handed to ``threat_detector`` so they show up in the dashboard,
reports, and one-click explainers like every other NS-… finding.
"""

from __future__ import annotations

import subprocess  # nosec B404 - fixed argv, no shell
import threading
import time
from collections import Counter
from pathlib import Path

from ...core import notify, ui
from ...core.plugin import HealthCheck, Plugin
from . import detect

_CHECK = "WiFi attack monitor"


class WifiMonitorPlugin(Plugin):
    COMMANDS = [
        {"command": "wifi", "description": "📡 WiFi monitor status"},
    ]

    def on_load(self) -> None:
        self._iface = str(self.cfg.get("interface", "wlan1"))
        self._protect = [str(s) for s in (self.cfg.get("protect_ssids", []) or [])]
        self._allow_bssids = {
            b.lower() for b in (self.cfg.get("allow_bssids", []) or [])
        }
        self._channels = [int(c) for c in (self.cfg.get("channels", [1, 6, 11]) or [1, 6, 11])]
        self._hop_seconds = max(3, int(self.cfg.get("hop_seconds", 8)))
        self._deauth_threshold = int(self.cfg.get("deauth_threshold", 20))
        # Default: run iw/ip/tcpdump directly, relying on the service's
        # AmbientCapabilities (CAP_NET_ADMIN + CAP_NET_RAW). The systemd unit
        # sets NoNewPrivileges, so sudo can't escalate anyway.
        self._sudo = bool(self.cfg.get("use_sudo", False))
        # If the adapter can't be put in monitor mode (unplugged, rfkill-blocked
        # after a reboot, driver change) keep retrying instead of giving up for
        # the life of the process, and tell the owner — a dead monitor that
        # says nothing looks exactly like "no attacks".
        self._retry_seconds = max(30, int(self.cfg.get("retry_seconds", 300)))
        self._max_silent_captures = int(self.cfg.get("max_silent_captures", 40))
        self._state_file = Path(self.ctx.state_dir) / "wifi_baseline.json"

        self._stop = threading.Event()
        self._status = "starting"
        self._told = False                  # the owner was alerted that the radio is down
        self._last_seen: dict[str, int] = {}
        self._started_ts = time.time()
        self._last_frames_ts = 0.0          # last capture that heard anything
        # The loader only instantiates this plugin when it's enabled, so start
        # monitoring straight away (the adapter is dedicated to this).
        self._thread: threading.Thread | None = threading.Thread(
            target=self._loop, name="wifi_monitor", daemon=True)
        self._thread.start()

    def on_unload(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=3)
        self._iface_down()

    def health(self) -> list[HealthCheck]:
        name = _CHECK
        if self._status != "monitoring":
            # Not yet "told" while still starting; once the radio failed, the
            # owner got this plugin's own alert.
            return [HealthCheck(name, False, self._status,
                                notified=getattr(self, "_told", False))]
        heard = self._last_frames_ts or self._started_ts
        age = time.time() - heard
        if age > 900:
            return [HealthCheck(name, False,
                                f"radio is up but has heard nothing for {int(age // 60)} min")]
        return [HealthCheck(name, True, f"listening on {self._iface}")]

    def on_command(self, command: str, args: str, chat_id: int) -> None:
        if command != "/wifi":
            return
        base = detect.load_baseline(self._state_file)
        lines = [
            "📡 WiFi monitor",
            f"  interface: {self._iface}  ·  status: {self._status}",
            f"  protecting SSIDs: {', '.join(self._protect) or '(none)'}",
            f"  APs seen last cycle: {len(self._last_seen)}",
            f"  baselined SSIDs: {', '.join(sorted(base)) or '(learning)'}",
        ]
        if hasattr(self.notifier, "send_to"):
            self.notifier.send_to(chat_id, "\n".join(lines))
        else:
            self.notifier.send("\n".join(lines))

    # ─── radio ──────────────────────────────────────────────────

    def _sx(self, *args: str) -> tuple[int, str]:
        cmd = (["sudo", "-n", *args] if self._sudo else list(args))
        try:
            p = subprocess.run(  # nosec B603 - fixed argv, no shell
                cmd, capture_output=True, text=True, timeout=15)
            return p.returncode, (p.stderr or "")
        except (subprocess.SubprocessError, OSError) as e:
            return 1, str(e)

    def _iface_up_monitor(self) -> tuple[bool, str]:
        """Put the adapter in monitor mode. Returns ``(ok, reason-if-not)``."""
        self._sx("rfkill", "unblock", "all")
        self._sx("ip", "link", "set", self._iface, "down")
        rc, err = self._sx("iw", "dev", self._iface, "set", "type", "monitor")
        if rc != 0:
            self.log.warning("wifi_monitor: monitor mode failed on %s: %s", self._iface, err)
            return False, f"monitor mode failed: {err.strip() or 'unknown error'}"
        rc, err = self._sx("ip", "link", "set", self._iface, "up")
        if rc != 0:
            self.log.warning("wifi_monitor: could not bring %s up: %s", self._iface, err)
            return False, f"could not bring {self._iface} up: {err.strip() or 'unknown error'}"
        return True, ""

    def _wait_for_radio(self) -> bool:
        """Bring the adapter up, retrying until it works or we're stopped.

        The owner hears about it once when the monitor is down and once when it
        comes back. Returns False only when the plugin is shutting down.
        """
        told = False
        watchdog = False
        while not self._stop.is_set():
            ok, why = self._iface_up_monitor()
            if ok:
                self._status = "monitoring"
                self._told = False
                # With the self-check watchdog loaded, it announces the recovery
                # (with how long it lasted) — one alert, one recovery.
                if told and not watchdog:
                    self._notify(notify.RECOVERY,
                                 f"{ui.OK} Back to normal: WiFi attack monitor "
                                 f"(listening on {self._iface})")
                return True
            self._status = f"NOT running — {why}"
            if not told:
                told = True
                self._told = True
                rfkill = "rf-kill" in why.lower() or "rfkill" in why.lower()
                hint = ("\nThe adapter is switched off by rfkill. On the Pi run: "
                        "sudo rfkill unblock wifi — it stays off across reboots "
                        "until the WiFi country is set." if rfkill else "")
                self._notify(
                    notify.ATTENTION,
                    f"{ui.header(ui.ATTENTION, 'WiFi attack monitor', 'not running')}\n"
                    f"The {self._iface} adapter couldn't be started, so deauth / "
                    "evil-twin attacks are NOT being watched. NetSentry retries every "
                    f"{self._retry_seconds // 60 or 1} min.{hint}")
                self.log.warning("wifi_monitor: not running: %s", why)
                watchdog = notify.report_problem(self.ctx, _CHECK)
            self._stop.wait(self._retry_seconds)
        return False

    def _notify(self, kind: str, text: str) -> None:
        try:
            self.notifier.notify(kind, text)
        except Exception:
            self.log.exception("wifi_monitor: could not notify")

    def _iface_down(self) -> None:
        self._sx("ip", "link", "set", self._iface, "down")
        self._sx("iw", "dev", self._iface, "set", "type", "managed")

    def _set_channel(self, ch: int) -> None:
        self._sx("iw", "dev", self._iface, "set", "channel", str(ch))

    def _capture(self, seconds: int) -> str:
        cmd = (["sudo", "-n"] if self._sudo else []) + [
            "tcpdump", "-i", self._iface, "-e", "-s", "256", "-nn", "-l",
            "type", "mgt",
        ]
        try:
            p = subprocess.run(  # nosec B603 - fixed argv, no shell
                cmd, capture_output=True, text=True, timeout=seconds)
            return p.stdout or ""
        except subprocess.TimeoutExpired as e:
            return e.stdout.decode("utf-8", "replace") if isinstance(e.stdout, bytes) else (e.stdout or "")
        except (subprocess.SubprocessError, OSError) as exc:
            self.log.warning("wifi_monitor: capture failed: %s", exc)
            return ""

    # ─── loop ───────────────────────────────────────────────────

    def _loop(self) -> None:
        if not self._wait_for_radio():
            return
        self.log.info("wifi_monitor: monitoring on %s (protect: %s)",
                      self._iface, ", ".join(self._protect) or "-")
        ci = 0
        silent = 0
        while not self._stop.is_set():
            ch = self._channels[ci % len(self._channels)]
            ci += 1
            self._set_channel(ch)
            text = self._capture(self._hop_seconds)
            # A working radio always hears *something* (your own AP's beacons at
            # the very least). A long run of empty captures means the adapter
            # went away under us — re-initialise it rather than idle forever.
            silent = 0 if text.strip() else silent + 1
            if text.strip():
                self._last_frames_ts = time.time()
            if silent >= self._max_silent_captures:
                self.log.warning("wifi_monitor: %d empty captures in a row — "
                                 "re-initialising %s", silent, self._iface)
                silent = 0
                if not self._wait_for_radio():
                    return
                continue
            try:
                self._analyse(text)
            except Exception:
                self.log.exception("wifi_monitor: analyse failed")
            self._stop.wait(0.2)

    def _analyse(self, text: str) -> None:
        ssid_bssids, deauths = detect.parse_capture(text)
        self._last_seen = dict(Counter(
            b for bs in ssid_bssids.values() for b in bs))

        baseline = detect.load_baseline(self._state_file)
        # Rogue-AP: only our protected SSIDs, vs the learned baseline.
        rogue = detect.rogue_ap_findings(
            ssid_bssids, baseline, self._protect, self._allow_bssids)
        # Learn/extend the baseline for protected SSIDs we now trust.
        baseline = detect.learn_baseline(ssid_bssids, baseline, self._protect)
        detect.save_baseline(self._state_file, baseline)

        # Deauth flood — only count frames aimed at YOUR APs (your BSSIDs, by
        # vendor OUI), so a neighbour's deauth noise on the same channel doesn't
        # cry wolf.
        own_bssids = {b for bl in baseline.values() for b in bl}
        deauth = detect.deauth_flood_findings(
            deauths, own_bssids, threshold=self._deauth_threshold)

        det = self._threat()
        for f in (*rogue, *deauth):
            if det is not None:
                det.record_finding(f.kind, f.subject, f.detail, immediate=True)
            else:
                self.log.warning("wifi_monitor finding (no threat_detector): %s %s",
                                 f.kind, f.subject)

    def _threat(self):
        for p in getattr(self.ctx, "_all_plugins", []):
            if getattr(getattr(p, "ctx", None), "name", "") == "threat_detector":
                return p
        return None
