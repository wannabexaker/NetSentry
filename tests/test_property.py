"""Property-based (fuzz) tests for the security-critical pure functions.

These assert *invariants* over arbitrary input — the strongest guard against the
edge cases a hand-written table would miss (injection, unicode, huge strings).
"""

from __future__ import annotations

import math

from hypothesis import given
from hypothesis import strategies as st

from netsentry.core.router import _MAC_RE, _routeros_quote, _valid_mac
from netsentry.plugins.threat_detector.detectors import (
    dns_tunnel_findings,
    new_domains,
    shannon_entropy,
    suspicious_tld_findings,
)

_INJECTION_CHARS = set(';"\\\n\r ')


def _has_unescaped_quote(inner: str) -> bool:
    """Scan a RouterOS quoted-string body for a `"` that would terminate it."""
    i = 0
    while i < len(inner):
        if inner[i] == "\\":
            i += 2  # the next char is escaped — skip it
            continue
        if inner[i] == '"':
            return True
        i += 1
    return False


@given(st.text())
def test_valid_mac_never_yields_injectable_output(s: str) -> None:
    out = _valid_mac(s)
    assert out is None or _MAC_RE.match(out)
    if out is not None:
        # nothing that could carry a second RouterOS command survives
        assert not (_INJECTION_CHARS & set(out))


@given(st.from_regex(_MAC_RE, fullmatch=True))
def test_valid_mac_accepts_and_normalises_real_macs(mac: str) -> None:
    out = _valid_mac(mac)
    assert out is not None
    assert out == out.upper()
    assert "-" not in out  # normalised to colon form


@given(st.text())
def test_routeros_quote_cannot_be_broken_out_of(s: str) -> None:
    q = _routeros_quote(s)
    assert q[0] == '"' and q[-1] == '"'
    assert not _has_unescaped_quote(q[1:-1])


@given(st.text())
def test_shannon_entropy_is_nonnegative_and_bounded(s: str) -> None:
    e = shannon_entropy(s)
    assert e >= 0.0
    if s:
        assert e <= math.log2(len(set(s))) + 1e-9


@given(st.lists(st.text(max_size=120), max_size=200))
def test_detectors_never_crash_on_arbitrary_input(domains: list[str]) -> None:
    # No exception, and every finding refers to a string subject.
    for finding in (
        dns_tunnel_findings(domains)
        + suspicious_tld_findings(domains)
        + new_domains(domains, set())
    ):
        assert isinstance(finding.subject, str)
