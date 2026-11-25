"""Pi-hole v6 REST API — just enough to add and remove NetSentry's own deny rules.

Every call logs in with the CLI password Pi-hole keeps in ``/etc/pihole/cli_pw``
(``POST /api/auth``), sends the session id in ``X-FTL-SID`` and logs out again
(``DELETE /api/auth``). NetSentry only ever touches regex deny entries whose
comment is :data:`COMMENT`; anything else on the list is left alone.

The password and the session id are never logged.
"""

from __future__ import annotations

import json
import logging
import re
import socket
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable

log = logging.getLogger(__name__)

COMMENT = "netsentry"
_DENY_REGEX = "/api/domains/deny/regex"
_RULE_RE = re.compile(r"^\(\\\.\|\^\)((?:[a-z0-9_-]+\\\.)+[a-z0-9-]+)\$$")


class PiholeError(Exception):
    """Pi-hole refused or could not be reached. ``str()`` is one plain line."""


def deny_regex_for(domain: str) -> str:
    """``example.com`` → ``(\\.|^)example\\.com$`` — the domain and its subdomains."""
    return r"(\.|^)" + domain.lower().replace(".", r"\.") + "$"


def domain_of_regex(regex: str) -> str | None:
    """The domain of a rule made by :func:`deny_regex_for`, else None."""
    m = _RULE_RE.match(regex or "")
    return m.group(1).replace(r"\.", ".") if m else None


class PiholeAPI:
    def __init__(self, base_url: str = "http://127.0.0.1",
                 password_file: str = "/etc/pihole/cli_pw", *, timeout: float = 5.0,
                 opener: Callable[..., Any] = urllib.request.urlopen) -> None:
        base = str(base_url or "").strip().rstrip("/")
        if urllib.parse.urlsplit(base).scheme not in ("http", "https"):
            raise ValueError(f"pihole_api must be an http(s) URL, not {base_url!r}")
        self.base = base
        self._password_file = str(password_file)
        self._timeout = timeout
        self._open = opener

    # ─── what the plugin uses ────────────────────────────────────

    def netsentry_blocks(self) -> list[str]:
        """Domains NetSentry blocked (regex deny entries with our comment)."""
        with self._session() as sid:
            return self._ours(sid)

    def block(self, domain: str) -> None:
        """Deny ``domain`` and its subdomains. Already blocked counts as done."""
        regex = deny_regex_for(domain)
        with self._session() as sid:
            status, data = self._request("POST", _DENY_REGEX,
                                         {"domain": regex, "comment": COMMENT}, sid)
            if status not in (200, 201):
                if _already_present(data):
                    return
                raise PiholeError(_reason(status, data))
            errors = ((data or {}).get("processed") or {}).get("errors") or []
            errors = [e for e in errors if "already present" not in str(e.get("error", ""))]
            if errors:
                raise PiholeError(str(errors[0].get("error") or "refused"))
        log.info("Pi-hole: blocked %s", domain)

    def unblock(self, domain: str) -> None:
        """Remove NetSentry's rule for ``domain`` — never someone else's."""
        with self._session() as sid:
            if domain not in self._ours(sid):
                raise PiholeError(f"no NetSentry block for {domain}")
            path = f"{_DENY_REGEX}/{urllib.parse.quote(deny_regex_for(domain), safe='')}"
            status, data = self._request("DELETE", path, None, sid)
            if status not in (200, 204, 404):
                raise PiholeError(_reason(status, data))
        log.info("Pi-hole: unblocked %s", domain)

    # ─── plumbing ────────────────────────────────────────────────

    def _ours(self, sid: str) -> list[str]:
        status, data = self._request("GET", _DENY_REGEX, None, sid)
        if status != 200 or not isinstance(data, dict):
            raise PiholeError(_reason(status, data))
        out: list[str] = []
        for entry in data.get("domains") or []:
            if not isinstance(entry, dict) or entry.get("comment") != COMMENT:
                continue
            domain = domain_of_regex(str(entry.get("domain", "")))
            if domain and domain not in out:
                out.append(domain)
        return out

    @contextmanager
    def _session(self) -> Iterator[str]:
        try:
            password = Path(self._password_file).read_text(encoding="utf-8").strip()
        except OSError as e:
            raise PiholeError(f"can't read Pi-hole's password file ({e.strerror or e})") from e
        status, data = self._request("POST", "/api/auth", {"password": password})
        del password
        session = (data or {}).get("session") if isinstance(data, dict) else None
        sid = session.get("sid") if isinstance(session, dict) and session.get("valid") else None
        if not sid:
            raise PiholeError("login refused — " + _reason(status, data))
        try:
            yield str(sid)
        finally:
            try:
                self._request("DELETE", "/api/auth", None, str(sid))
            except PiholeError as e:
                log.warning("Pi-hole: logout failed: %s", e)

    def _request(self, method: str, path: str, body: dict | None,
                 sid: str | None = None) -> tuple[int, Any]:
        headers = {"Accept": "application/json"}
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        if sid:
            headers["X-FTL-SID"] = sid
        req = urllib.request.Request(self.base + path, data=data, headers=headers,
                                     method=method)
        try:
            # The scheme is checked in __init__ (http/https only).
            with self._open(req, timeout=self._timeout) as r:  # nosec B310
                status, raw = int(getattr(r, "status", 200) or 200), r.read()
        except urllib.error.HTTPError as e:
            status, raw = e.code, e.read() if e.fp else b""
        except (urllib.error.URLError, socket.timeout, OSError) as e:
            reason = getattr(e, "reason", None) or e
            raise PiholeError(f"could not reach Pi-hole ({reason})") from e
        log.debug("Pi-hole %s %s → %s", method, path.split("?")[0], status)
        try:
            return status, json.loads(raw) if raw else None
        except ValueError:
            return status, None


def _reason(status: int, data: Any) -> str:
    err = data.get("error") if isinstance(data, dict) else None
    if isinstance(err, dict):
        text = str(err.get("message") or err.get("key") or "")
        hint = err.get("hint")
        if isinstance(hint, str) and hint:
            text += f" ({hint})"
        if text:
            return text
    return f"HTTP {status}"


def _already_present(data: Any) -> bool:
    err = data.get("error") if isinstance(data, dict) else None
    return isinstance(err, dict) and "already present" in str(err.get("hint", ""))
