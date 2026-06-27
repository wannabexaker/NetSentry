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
