"""
Facts about the machine NetSentry runs on: its name, model, OS, Tailscale
address, how long this process has been up, and where its code came from.

Every function here is read-only, never raises, and returns "" / None when a
fact is not available (Windows, macOS, no Tailscale, no git…). Commands run
with a fixed argument list and a short timeout — nothing here is ever built
from text a user typed.
"""

from __future__ import annotations

import os
import platform
import socket
import subprocess  # nosec B404 - fixed argv, no shell, short timeouts
import time
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

# Fallback for "process started" where /proc is not available: the moment this
# module was first imported, which is during NetSentry's start-up.
_IMPORTED_AT = time.time()


def tailscale_ipv4(timeout: float = 2.0) -> str | None:
    """This host's Tailscale IPv4 address (``tailscale ip -4``), or None."""
    try:
        result = subprocess.run(  # nosec B603 B607 - fixed argv, no shell
            ["tailscale", "ip", "-4"], capture_output=True, text=True, timeout=timeout)
        if result.returncode == 0:
            first = result.stdout.strip().splitlines()[0:1]
            if first and first[0].strip():
                return first[0].strip()
    except Exception:
        pass
    return None


def host_name() -> str:
    try:
        return socket.gethostname()
    except Exception:
        return ""


def host_model(path: str = "/proc/device-tree/model") -> str:
    """The board's own name (e.g. a Raspberry Pi model); "" when not exposed."""
    try:
        return Path(path).read_bytes().decode("utf-8", "replace").strip("\x00 \n")
    except OSError:
        return ""


def os_name(path: str = "/etc/os-release") -> str:
    """``PRETTY_NAME`` from os-release, else what ``platform`` says."""
    try:
        for line in Path(path).read_text(encoding="utf-8", errors="replace").splitlines():
            key, _, value = line.partition("=")
            if key.strip() == "PRETTY_NAME" and value.strip():
                return value.strip().strip('"').strip("'")
    except OSError:
        pass
    try:
        return " ".join(p for p in (platform.system(), platform.release()) if p)
    except Exception:
        return ""


def process_started() -> float:
    """When this process started (epoch seconds).

    On Linux from /proc (start ticks after boot + boot time); elsewhere the
    moment this module was imported, which is close enough for "up 3 h".
    """
    try:
        fields = Path("/proc/self/stat").read_text().rsplit(")", 1)[1].split()
        start_ticks = int(fields[19])               # field 22 of the whole line
        for line in Path("/proc/stat").read_text().splitlines():
            if line.startswith("btime "):
                return int(line.split()[1]) + start_ticks / os.sysconf("SC_CLK_TCK")
    except (OSError, ValueError, IndexError, AttributeError):
        pass
    return _IMPORTED_AT


def code_folder() -> Path:
    """The project folder NetSentry runs from (the checkout for an editable
    install, the package folder for a normal one)."""
    pkg = Path(__file__).resolve().parent.parent          # …/netsentry
    return pkg.parent.parent if pkg.parent.name == "src" else pkg


def git_remote(folder: Path, timeout: float = 2.0) -> str:
    """The readable ``origin`` URL of the git checkout at ``folder``; "" if none."""
    try:
        result = subprocess.run(  # nosec B603 B607 - fixed argv, folder is our own code dir
            ["git", "-C", str(folder), "config", "--get", "remote.origin.url"],
            capture_output=True, text=True, timeout=timeout)
    except Exception:
        return ""
    if result.returncode != 0:
        return ""
    return readable_remote(result.stdout.strip())


def readable_remote(url: str) -> str:
    """A git remote as something to read or open in a browser, with any
    embedded credentials, query or fragment removed; "" when unsure.

    ``git@github.com:user/repo.git`` → ``https://github.com/user/repo``.
    """
    url = (url or "").strip()
    if not url or any(c.isspace() for c in url):
        return ""
    if "://" not in url:                                   # scp-like: user@host:path
        host_part, sep, path = url.partition(":")
        if not sep or "/" in host_part or not path:
            return ""
        host = host_part.rpartition("@")[2]
        return _web(host, path)
    try:
        parts = urlsplit(url)
        host = parts.hostname or ""
        port = parts.port
    except ValueError:
        return ""
    if not host:
        return ""
    if parts.scheme in ("ssh", "git", "git+ssh"):
        return _web(host, parts.path)
    if parts.scheme in ("http", "https"):
        netloc = host + (f":{port}" if port else "")       # drops user:token@
        return urlunsplit((parts.scheme, netloc, _trim(parts.path), "", ""))
    return ""


def _web(host: str, path: str) -> str:
    path = _trim(path)
    return f"https://{host}/{path.lstrip('/')}" if host and path.strip("/") else ""


def _trim(path: str) -> str:
    path = path.rstrip("/")
    return path[:-4] if path.endswith(".git") else path


def home_short(path: str | os.PathLike[str]) -> str:
    """``/home/user/x`` → ``~/x`` (and the home folder itself → ``~``)."""
    p = Path(path)
    try:
        rel = p.relative_to(Path.home())
    except (ValueError, RuntimeError):
        return str(p)
    return "~" if str(rel) == "." else f"~/{rel.as_posix()}"
