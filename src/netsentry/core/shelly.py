"""Minimal client for a Shelly smart plug (Gen2 / Gen3 / Plus RPC over HTTP).

Used to power-cycle a device that has no API of its own — typically the ISP's
router. The one call that matters is ``cycle``: the plug switches off and
*itself* switches back on after N seconds, so the power returns even though the
network (and with it NetSentry's connection to the plug) may be gone meanwhile.

Only plain ``http://<address>[:port]`` targets are accepted, and only the fixed
RPC paths below are ever requested.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass

_BASE_RE = re.compile(r"^http://[A-Za-z0-9.-]{1,253}(:\d{1,5})?$")


class PlugError(Exception):
    """The plug could not be reached or refused; the message is fit to show."""


@dataclass(frozen=True)
class PlugState:
    on: bool                      # is the socket powered right now
    watts: float | None           # what the plugged-in device draws, if metered
    after_power_cut: str          # "on" | "off" | "restore_last" | "match_input" | ""

    @property
    def comes_back_by_itself(self) -> bool:
        """After a mains power cut, will the socket be powered again?"""
        return self.after_power_cut in ("on", "restore_last")


class ShellyPlug:
    def __init__(self, base_url: str, switch: int = 0, timeout: float = 6.0) -> None:
        base_url = base_url.rstrip("/")
        if not _BASE_RE.fullmatch(base_url):
            raise PlugError(f"not a plain http://address[:port] plug address: {base_url!r}")
        self._base = base_url
        self._switch = int(switch)
        self._timeout = timeout

    def state(self) -> PlugState:
        status = self._rpc("Switch.GetStatus")
        config = self._rpc("Switch.GetConfig")
        watts = status.get("apower")
        return PlugState(
            on=bool(status.get("output")),
            watts=float(watts) if isinstance(watts, (int, float)) else None,
            after_power_cut=str(config.get("initial_state") or ""),
        )

    def cycle(self, off_seconds: int) -> None:
        """Switch off now; the plug switches itself back on after ``off_seconds``."""
        seconds = max(3, min(int(off_seconds), 120))
        self._rpc("Switch.Set", on="false", toggle_after=str(seconds))

    def turn_on(self) -> None:
        self._rpc("Switch.Set", on="true")

    def come_back_on_after_power_cut(self) -> None:
        """Make the socket power up again when mains returns (it must, for a router)."""
        self._rpc("Switch.SetConfig", config=json.dumps({"initial_state": "on"}))

    def _rpc(self, method: str, **params: str) -> dict:
        query = urllib.parse.urlencode({"id": self._switch, **params})
        url = f"{self._base}/rpc/{method}?{query}"
        try:
            with urllib.request.urlopen(url, timeout=self._timeout) as r:  # nosec B310 - http only, see _BASE_RE
                data = json.loads(r.read().decode("utf-8", "replace"))
        except urllib.error.HTTPError as e:
            if e.code == 401:
                raise PlugError("the plug asks for a password — NetSentry only talks to a "
                                "plug without one (it sits on your own network)") from e
            raise PlugError(f"the plug answered HTTP {e.code}") from e
        except (urllib.error.URLError, OSError) as e:
            raise PlugError(f"the plug did not answer ({getattr(e, 'reason', e)})") from e
        except ValueError as e:
            raise PlugError("the plug's answer was not understood — is it a Shelly "
                            "Gen2/Gen3/Plus device?") from e
        if not isinstance(data, dict):
            raise PlugError("the plug's answer was not understood")
        return data
