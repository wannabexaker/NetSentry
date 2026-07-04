from __future__ import annotations

from netsentry.core import netscan
from netsentry.plugins.threat_detector.detectors import weak_service_findings


def test_valid_ip_private_only() -> None:
    assert netscan.valid_ip("192.168.1.10") == "192.168.1.10"
    assert netscan.valid_ip("10.0.0.5") == "10.0.0.5"
    assert netscan.valid_ip("8.8.8.8") is None       # public
    assert netscan.valid_ip("999.1.1.1") is None      # not an octet
    assert netscan.valid_ip("nope") is None


def test_valid_cidr() -> None:
    assert netscan.valid_cidr("192.168.1.0/24") == "192.168.1.0/24"
    assert netscan.valid_cidr("192.168.1.5/24") == "192.168.1.0/24"   # host bits cleared
    assert netscan.valid_cidr("8.8.8.0/24") is None                   # public
    assert netscan.valid_cidr("10.0.0.0/8") is None                   # too many addresses
    assert netscan.valid_cidr("bad") is None


def test_parse_hosts_up() -> None:
    txt = "\n".join([
        "Host: 192.168.1.10 ()\tStatus: Up",
        "Host: 192.168.1.20 ()\tStatus: Down",
        "Host: 192.168.1.30 ()\tStatus: Up",
    ])
    assert netscan.parse_hosts_up(txt) == ["192.168.1.10", "192.168.1.30"]


def test_parse_ports() -> None:
    txt = ("Host: 192.168.1.10 ()\tPorts: 22/open/tcp//ssh///, "
           "80/open/tcp//http///\tIgnored State: closed (98)")
    assert netscan.parse_ports(txt) == {"192.168.1.10": [22, 80]}


def test_parse_services() -> None:
    txt = ("Host: 192.168.1.10 ()\tPorts: 22/open/tcp//ssh//OpenSSH 8.9//, "
           "80/open/tcp//http//nginx 1.24//")
    svc = netscan.parse_services(txt)["192.168.1.10"]
    assert svc[0].port == 22 and svc[0].service == "ssh" and "OpenSSH" in svc[0].version
    assert svc[1].port == 80 and svc[1].service == "http" and "nginx" in svc[1].version


def test_weak_service_findings_ports_and_default_cred() -> None:
    port_map = {"192.168.1.14": [23, 80], "192.168.1.20": [443]}
    banners = {"192.168.1.14": "<title>Login</title> The password is the default one."}
    out = {f.subject: f for f in weak_service_findings(port_map, banners)}

    assert "192.168.1.14" in out
    assert "telnet/23" in out["192.168.1.14"].detail
    assert "default-credential" in out["192.168.1.14"].detail
    assert out["192.168.1.14"].severity == "attack"
    assert "192.168.1.20" not in out   # https alone isn't weak


def test_weak_service_findings_empty_when_clean() -> None:
    assert weak_service_findings({"192.168.1.10": [22, 443]}) == []
