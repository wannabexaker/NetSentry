"""Wake-on-LAN: build and send the "magic packet" that switches a PC on.

The packet is six 0xFF bytes followed by the target's MAC address sixteen
times, sent over UDP (port 9 by convention). A sleeping network card that has
"wake on magic packet" enabled powers the machine up when it sees it.

A broadcast only reaches the local subnet. When the PC sits behind a router
(another subnet, as seen from NetSentry), the packet goes to a *relay* address
instead — typically the router, which forwards UDP 9 to the PC — so the target
is a plain ``host[:port]`` and no broadcast is needed.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from typing import Callable

DEFAULT_PORT = 9

_MAC_RE = re.compile(r"^[0-9A-Fa-f]{2}([:-]?)(?:[0-9A-Fa-f]{2}\1){4}[0-9A-Fa-f]{2}$")
_DOTTED_MAC_RE = re.compile(r"^[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}$")
_HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,62})"
                          r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,62}))*$")


class WakeError(ValueError):
    """The MAC or the target is not usable, or the packet could not be sent.
    The message is fit to show the owner."""


def parse_mac(mac: str) -> bytes:
    """The six bytes of ``AA:BB:CC:DD:EE:FF`` (also ``-``, ``.``-grouped or bare hex)."""
    text = str(mac or "").strip()
    if not (_MAC_RE.fullmatch(text) or _DOTTED_MAC_RE.fullmatch(text)):
        raise WakeError(f"not a MAC address: {text!r}")
    raw = bytes.fromhex(re.sub(r"[^0-9A-Fa-f]", "", text))
    if raw == b"\x00" * 6 or raw == b"\xff" * 6:
        raise WakeError("that MAC address cannot belong to a PC")
    return raw


def parse_target(wake_to: str) -> tuple[str, int]:
    """``host[:port]`` → ``(host, port)``; the port defaults to 9.

    Only an IPv4 address or a hostname is accepted (a relay or a broadcast
    address) — nothing that could be read as an option or a URL.
    """
    text = str(wake_to or "").strip()
    host, port = text, DEFAULT_PORT
    if ":" in text:
        host, _, port_text = text.rpartition(":")
        if not port_text.isdigit():
            raise WakeError(f"not a port number: {port_text!r}")
        port = int(port_text)
        if not 1 <= port <= 65535:
            raise WakeError(f"port out of range: {port}")
    try:
        ipaddress.IPv4Address(host)
    except ValueError:
        if not _HOSTNAME_RE.fullmatch(host) or host.replace(".", "").isdigit():
            raise WakeError(f"not an address to send the wake signal to: {text!r}") from None
    return host, port


def magic_packet(mac: str) -> bytes:
    """6 × 0xFF, then the MAC 16 times (102 bytes)."""
    return b"\xff" * 6 + parse_mac(mac) * 16


def send_magic_packet(mac: str, wake_to: str, *, repeat: int = 3,
                      sock_factory: Callable[..., socket.socket] = socket.socket) -> int:
    """Send the packet ``repeat`` times to ``wake_to``; returns how many went out.

    Sent more than once because UDP gives no guarantee and the packet is tiny.
    """
    packet = magic_packet(mac)
    host, port = parse_target(wake_to)
    sent = 0
    try:
        with sock_factory(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            # Harmless for a unicast relay; required when wake_to is a broadcast.
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            for _ in range(max(1, int(repeat))):
                sock.sendto(packet, (host, port))
                sent += 1
    except OSError as e:
        raise WakeError(f"the wake signal could not be sent ({e.strerror or e})") from e
    return sent
