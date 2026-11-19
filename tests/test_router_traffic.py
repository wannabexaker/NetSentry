from __future__ import annotations

from netsentry.core.router import MikroTikRouter


def _router_with_output(
    output: str,
    commands: list[str] | None = None,
) -> MikroTikRouter:
    router = MikroTikRouter("router.local", "admin", "key")

    def fake_ssh(command: str, timeout: int = 10) -> tuple[int, str]:
        if commands is not None:
            commands.append(command)
        return 0, output

    def fake_ssh_with_stderr(
        command: str,
        timeout: int = 10,
    ) -> tuple[int, str, str]:
        if commands is not None:
            commands.append(command)
        return 0, output, ""

    router._ssh = fake_ssh  # type: ignore[method-assign]
    router._ssh_with_stderr = fake_ssh_with_stderr  # type: ignore[method-assign]
    return router


def test_blocked_macs_parses_reject_access_list() -> None:
    commands: list[str] = []
    router = _router_with_output(
        ' 0 mac-address=AA:BB:CC:DD:EE:01 action=reject comment="blocked"\n'
        ' 1 mac-address=aa:bb:cc:dd:ee:02 action=reject\n',
        commands,
    )
    assert router.blocked_macs() == {"AA:BB:CC:DD:EE:01", "AA:BB:CC:DD:EE:02"}
    assert commands == ["/interface wifi access-list print where action=reject"]


def test_wifi_traffic_parses_registration_detail_bytes_pair() -> None:
    commands: list[str] = []
    router = _router_with_output(
        """
 0 A interface=wifi1 ssid=home mac-address=AA:BB:CC:DD:EE:FF uptime=2m10s last-activity=20ms signal=-41 auth-type=wpa2-psk
     packets=12,34 bytes=1024,4096 tx-bits-per-second=0 rx-bits-per-second=0
 1 A interface=wifi2 ssid=home mac-address=11:22:33:44:55:66 uptime=1m last-activity=1s
     tx-bytes=2048 rx-bytes=8192
""",
        commands,
    )

    rows = router.wifi_traffic()

    assert commands == ["/interface wifi registration-table print detail"]
    assert rows[0].mac == "AA:BB:CC:DD:EE:FF"
    assert rows[0].tx_bytes == 1024
    assert rows[0].rx_bytes == 4096
    assert rows[0].last_activity_ms == 20
    assert rows[1].mac == "11:22:33:44:55:66"
    assert rows[1].tx_bytes == 2048
    assert rows[1].rx_bytes == 8192


def test_wifi_traffic_parses_registration_table_bytes_pair() -> None:
    router = _router_with_output(
        """
Columns: INTERFACE, SSID, MAC-ADDRESS, LAST-ACTIVITY, BYTES
# INTERFACE SSID MAC-ADDRESS LAST-ACTIVITY BYTES
0 wifi1 home AA:BB:CC:DD:EE:FF 30ms 1500,2500
""",
    )

    rows = router.wifi_traffic()

    assert len(rows) == 1
    assert rows[0].mac == "AA:BB:CC:DD:EE:FF"
    assert rows[0].tx_bytes == 1500
    assert rows[0].rx_bytes == 2500
    assert rows[0].last_activity_ms == 30


def test_ip_accounting_snapshot_parses_detail_records() -> None:
    commands: list[str] = []
    router = _router_with_output(
        """
 0 src-address=203.0.113.10 dst-address=1.1.1.1 packets=3 bytes=300
 1 src-address=1.1.1.1 dst-address=203.0.113.10 packets=4 bytes=700
""",
        commands,
    )

    snapshot = router.ip_accounting_snapshot()

    assert commands == [
        "/ip accounting snapshot take; /ip accounting snapshot print detail"
    ]
    assert snapshot["203.0.113.10"] == (300, 700)
    assert snapshot["1.1.1.1"] == (700, 300)


def _router_with_stderr_output(
    rc: int, out: str, err: str, calls: list[str]
) -> MikroTikRouter:
    router = MikroTikRouter("router.local", "admin", "key")

    def fake_ssh_with_stderr(
        command: str, timeout: int = 10
    ) -> tuple[int, str, str]:
        calls.append(command)
        return rc, out, err

    router._ssh_with_stderr = fake_ssh_with_stderr  # type: ignore[method-assign]
    return router


def test_ip_accounting_disables_when_error_only_in_stdout() -> None:
    # RouterOS v7 prints "bad command name accounting" to the session output
    # (stdout) with rc=0 and an empty stderr — the exact case that used to
    # slip past detection and hammer the router every poll.
    calls: list[str] = []
    router = _router_with_stderr_output(
        0, "bad command name accounting (line 1 column 5)", "", calls
    )

    assert router.ip_accounting_snapshot() == {}
    # Subsequent calls must short-circuit without touching the router again.
    assert router.ip_accounting_snapshot() == {}
    assert router.ip_accounting_snapshot() == {}
    assert len(calls) == 1


def test_ip_accounting_disables_after_repeated_empty_snapshots() -> None:
    # Log-only failure: nothing on either SSH stream, nothing parses. We must
    # still give up after a few empty polls instead of hitting it forever.
    calls: list[str] = []
    router = _router_with_stderr_output(0, "", "", calls)

    for _ in range(3):
        assert router.ip_accounting_snapshot() == {}
    assert len(calls) == 3

    # Now disabled — further calls short-circuit.
    assert router.ip_accounting_snapshot() == {}
    assert len(calls) == 3


# ─── WiFi clients ────────────────────────────────────────────────

DETAIL = """Flags: A - AUTHORIZED
 0 A interface=wifi-iot ssid="IoT" mac-address=50:EC:50:EE:0B:18
     uptime=19w5d12h26m31s last-activity=6s10ms signal=-65 auth-type=wpa2-psk
     band=2ghz-n

 1 A interface=wifi1 ssid="My Home" mac-address=a0:b1:c2:d3:e4:f5
     uptime=3m last-activity=0ms signal=-48 auth-type=wpa3-psk
     band=5ghz-ax
"""

# What the router prints once a long uptime no longer leaves room for AUTH-TYPE.
TABLE_WITHOUT_AUTH = """Flags: A - AUTHORIZED
Columns: INTERFACE, SSID, MAC-ADDRESS, UPTIME, LAST-ACTIVITY, SIGNAL
 #   INTERFACE  SSID   MAC-ADDRESS        UPTIME          LAST-ACTIVITY  SIGNAL
 0 A wifi-iot   IoT    50:EC:50:EE:0B:18  19w5d12h26m24s  6s             -65
 1 A wifi1      Home   A0:B1:C2:D3:E4:F5  3m              9s10ms         -48
"""

TABLE_WITH_AUTH = """ #   INTERFACE  SSID  MAC-ADDRESS        UPTIME  LAST-ACTIVITY  SIGNAL  AUTH-TYPE
 0 A wifi2      Home  A0:B1:C2:D3:E4:F5  3m      20ms           -51     wpa2-psk
"""


def test_wifi_clients_come_from_the_detail_listing() -> None:
    from netsentry.core.router import parse_wifi_clients

    iot, phone = parse_wifi_clients(DETAIL)
    assert (iot.mac, iot.ssid, iot.interface, iot.signal_dbm) == (
        "50:EC:50:EE:0B:18", "IoT", "wifi-iot", -65)
    assert iot.band == "2.4ghz" and iot.auth_type == "wpa2-psk"
    assert iot.last_activity_ms == 6010
    assert (phone.mac, phone.ssid, phone.band) == ("A0:B1:C2:D3:E4:F5", "My Home", "5ghz")


def test_wifi_clients_ask_for_the_detail_listing() -> None:
    commands: list[str] = []
    router = _router_with_output(DETAIL, commands)
    assert len(router.wifi_clients()) == 2
    assert commands == ["/interface wifi registration-table print detail without-paging"]


def test_wifi_clients_survive_a_table_that_lost_its_last_column() -> None:
    """Regression: with a long uptime in the table RouterOS drops the AUTH-TYPE
    column; the old parser required it and returned no clients at all."""
    from netsentry.core.router import parse_wifi_clients

    clients = parse_wifi_clients(TABLE_WITHOUT_AUTH)
    assert [(c.mac, c.signal_dbm, c.auth_type) for c in clients] == [
        ("50:EC:50:EE:0B:18", -65, ""), ("A0:B1:C2:D3:E4:F5", -48, "")]
    assert clients[1].band == "5ghz" and clients[1].last_activity_ms == 9010
    (with_auth,) = parse_wifi_clients(TABLE_WITH_AUTH)
    assert with_auth.auth_type == "wpa2-psk" and with_auth.signal_dbm == -51


def test_wifi_clients_ignore_what_is_not_a_client() -> None:
    from netsentry.core.router import parse_wifi_clients

    assert parse_wifi_clients("") == []
    assert parse_wifi_clients("bad command name registration-table (line 1 column 17)") == []
    assert parse_wifi_clients(" 0 A interface=wifi1 mac-address=not-a-mac signal=-40") == []
    assert parse_wifi_clients(" 0 A interface=wifi1 mac-address=A0:B1:C2:D3:E4:F5 signal=strong") == []
