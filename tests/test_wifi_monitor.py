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


def test_parse_capture_deauth_with_signal() -> None:
    # _PRE carries "-78dBm signal", so the parser should capture -78.
    txt = (_PRE + "BSSID:04:f4:1c:d1:48:c4 DA:11:22:33:44:55:66 "
           "SA:de:ad:be:ef:00:01 DeAuthentication (...)")
    _, deauths = detect.parse_capture(txt)
    assert deauths == [
        ("de:ad:be:ef:00:01", "11:22:33:44:55:66", "04:f4:1c:d1:48:c4", -78)]


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


def test_deauth_flood_classifies_yours_vs_nearby() -> None:
    own = {"04:f4:1c:d1:48:c5"}                     # your AP (OUI 04:f4:1c)
    at_you = [("de:ad:be:ef:00:01", "ff:ff:ff:ff:ff:ff", "04:f4:1c:d1:48:c4", -40)
              for _ in range(25)]                    # same-vendor target = yours
    at_neighbour = [("de:ad:be:ef:00:02", "ff:ff:ff:ff:ff:ff", "aa:bb:cc:dd:ee:ff", -70)
                    for _ in range(30)]              # different vendor = not yours
    out = {f.subject: f
           for f in detect.deauth_flood_findings(at_you + at_neighbour, own, threshold=20)}
    # attack on your AP -> NS-WIFI-001 (attack)
    yours = out["de:ad:be:ef:00:01"]
    assert yours.kind == "deauth_flood" and yours.severity == "attack"
    assert "04:f4:1c:d1:48:c4" in yours.detail                  # names the target BSSID
    assert "-40 dBm" in yours.detail and "very close" in yours.detail
    # neighbour's noise -> NS-WIFI-003 (info), stated plainly as not yours
    nearby = out["de:ad:be:ef:00:02"]
    assert nearby.kind == "deauth_nearby" and nearby.severity == "info"
    assert "NOT your Wi-Fi" in nearby.detail


def test_deauth_nearby_needs_baseline() -> None:
    # Same off-target frames: without a baseline they fall back to the attack
    # path (fail-safe); with a baseline they become a calm "nearby" info notice.
    many = [("de:ad:be:ef:00:03", "x", "zz:zz:zz:zz:zz:zz", -60) for _ in range(25)]
    assert [f.kind for f in detect.deauth_flood_findings(many, frozenset())] == ["deauth_flood"]
    out = detect.deauth_flood_findings(many, {"04:f4:1c:d1:48:c5"})
    assert [f.kind for f in out] == ["deauth_nearby"] and out[0].severity == "info"


def test_deauth_source_hitting_both_reports_attack_only() -> None:
    # A source spraying both your AP and a neighbour's is your attacker — it must
    # not also be double-reported as harmless "nearby".
    own = {"04:f4:1c:d1:48:c5"}
    frames = ([("aa:aa:aa:aa:aa:aa", "x", "04:f4:1c:d1:48:c4", -50) for _ in range(25)]
              + [("aa:aa:aa:aa:aa:aa", "x", "bb:bb:bb:bb:bb:bb", -50) for _ in range(25)])
    kinds = {f.kind for f in detect.deauth_flood_findings(frames, own, threshold=20)}
    assert kinds == {"deauth_flood"}


def test_deauth_flood_threshold_and_no_baseline_fallback() -> None:
    own = {"04:f4:1c:d1:48:c5"}
    few = [("de:ad:be:ef:00:01", "x", "04:f4:1c:d1:48:c4", -60) for _ in range(10)]
    assert detect.deauth_flood_findings(few, own, threshold=20) == []   # below threshold
    # No own BSSIDs known yet -> best-effort: count all (can't confirm target).
    many = [("de:ad:be:ef:00:03", "x", "zz:zz:zz:zz:zz:zz", -60) for _ in range(25)]
    assert len(detect.deauth_flood_findings(many, frozenset(), threshold=20)) == 1


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
