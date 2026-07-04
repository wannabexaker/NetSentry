from __future__ import annotations

from pathlib import Path

from netsentry.plugins.wifi_monitor import detect

_PRE = "12:59:23.481903 367186us tsft 6.0 Mb/s 2437 MHz 11g -78dBm signal antenna 0 "


def _beacon(bssid: str, ssid: str) -> str:
    return (_PRE + f"BSSID:{bssid} DA:ff:ff:ff:ff:ff:ff SA:{bssid} "
            f"Beacon ({ssid}) [6.0* 9.0 Mbit] ESS, PRIVACY [|802.11]")


def test_parse_capture_beacons() -> None:
    txt = "\n".join([
        _beacon("04:f4:1c:d1:48:c4", "Sky"),
        _beacon("06:f4:1c:d1:48:c4", "Cielo"),
        _beacon("de:ad:be:ef:00:01", "Sky"),        # same SSID, foreign BSSID
    ])
    ssid_bssids, deauths = detect.parse_capture(txt)
    assert ssid_bssids["Sky"] == {"04:f4:1c:d1:48:c4", "de:ad:be:ef:00:01"}
    assert ssid_bssids["Cielo"] == {"06:f4:1c:d1:48:c4"}
    assert deauths == []


def test_parse_capture_deauth() -> None:
    txt = (_PRE + "BSSID:04:f4:1c:d1:48:c4 DA:11:22:33:44:55:66 "
           "SA:de:ad:be:ef:00:01 DeAuthentication (...)")
    _, deauths = detect.parse_capture(txt)
    assert deauths == [("de:ad:be:ef:00:01", "11:22:33:44:55:66", "04:f4:1c:d1:48:c4")]


def test_rogue_ap_flags_foreign_vendor_not_own_band() -> None:
    ssid_bssids = {"Sky": {
        "04:f4:1c:d1:48:c4", "04:f4:1c:d1:48:c5", "de:ad:be:ef:00:01"}}
    baseline = {"Sky": ["04:f4:1c:d1:48:c4"]}
    subs = {f.subject for f in detect.rogue_ap_findings(ssid_bssids, baseline, ["Sky"])}
    assert "de:ad:be:ef:00:01" in subs         # different OUI -> evil-twin
    assert "04:f4:1c:d1:48:c5" not in subs      # same OUI -> my other band


def test_rogue_ap_ignores_unprotected_and_allowlist() -> None:
    assert detect.rogue_ap_findings(
        {"NeighborWiFi": {"aa:bb:cc:dd:ee:ff"}}, {}, ["Sky"]) == []
    assert detect.rogue_ap_findings(
        {"Sky": {"de:ad:be:ef:00:01"}}, {"Sky": ["04:f4:1c:d1:48:c4"]},
        ["Sky"], frozenset({"de:ad:be:ef:00:01"})) == []


def test_rogue_ap_silent_while_learning() -> None:
    # No baseline yet for Sky -> still learning, no alarm.
    assert detect.rogue_ap_findings({"Sky": {"de:ad:be:ef:00:01"}}, {}, ["Sky"]) == []


def test_deauth_flood_threshold() -> None:
    events = [("de:ad:be:ef:00:01", "11:22:33:44:55:66", "b") for _ in range(25)]
    events.append(("aa:aa:aa:aa:aa:aa", "x", "y"))     # single -> below threshold
    out = {f.subject: f for f in detect.deauth_flood_findings(events, threshold=20)}
    assert "de:ad:be:ef:00:01" in out and "25" in out["de:ad:be:ef:00:01"].detail
    assert "aa:aa:aa:aa:aa:aa" not in out


def test_learn_baseline_first_then_same_oui() -> None:
    base = detect.learn_baseline({"Sky": {"04:f4:1c:d1:48:c4"}}, {}, ["Sky"])
    assert base["Sky"] == ["04:f4:1c:d1:48:c4"]
    base2 = detect.learn_baseline(
        {"Sky": {"04:f4:1c:d1:48:c5", "de:ad:be:ef:00:01"}}, base, ["Sky"])
    assert "04:f4:1c:d1:48:c5" in base2["Sky"]       # same OUI learned
    assert "de:ad:be:ef:00:01" not in base2["Sky"]   # foreign OUI not trusted


def test_baseline_roundtrip(tmp_path: Path) -> None:
    p = tmp_path / "wifi.json"
    detect.save_baseline(p, {"Sky": {"04:f4:1c:d1:48:c4"}})
    assert detect.load_baseline(p) == {"Sky": ["04:f4:1c:d1:48:c4"]}
    assert detect.load_baseline(tmp_path / "missing.json") == {}
