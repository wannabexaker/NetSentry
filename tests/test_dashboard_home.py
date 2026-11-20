"""Dashboard Home: the verdict that answers "is anything wrong / does anything need me?"."""

from __future__ import annotations

from pathlib import Path

from netsentry.plugins.lan_dashboard import _local_ts, build_verdict

STATIC = Path(__file__).resolve().parents[1] / "src" / "netsentry" / "plugins" / "lan_dashboard"
DOWN = [{"name": "WiFi monitor", "ok": False, "detail": "radio is switched off"}]


def test_all_clear_has_no_rows_and_the_protected_picture() -> None:
    v = build_verdict(attacks=0, to_review=0, problems=[], unnamed=0)
    assert v["level"] == "ok" and v["headline"] == "All clear"
    assert v["items"] == [] and v["picture"] == "protected"


def test_a_failing_monitor_is_not_all_clear_and_is_named() -> None:
    v = build_verdict(attacks=0, to_review=0, problems=DOWN, unnamed=0)
    assert v["level"] == "attention" and v["picture"] == "warning"
    assert "WiFi monitor" in v["reason"] and "radio is switched off" in v["reason"]
    assert v["items"] == [{"label": "WiFi monitor is not working",
                           "detail": "radio is switched off", "href": "/system"}]


def test_order_attack_then_monitor_then_findings_then_devices_capped_at_three() -> None:
    v = build_verdict(attacks=1, to_review=2, problems=DOWN * 3, unnamed=4)
    assert v["level"] == "attack" and v["picture"] == "attack"
    assert [i["href"] for i in v["items"]] == ["/threats", "/system", "/threats"]
    assert v["items"][0]["label"] == "1 finding at attack level"
    assert v["items"][1]["label"] == "WiFi monitor and 2 others are not working"
    assert v["items"][2]["label"] == "2 findings to review"


def test_findings_to_review_come_before_unnamed_devices() -> None:
    v = build_verdict(attacks=0, to_review=1, problems=[], unnamed=1)
    assert v["level"] == "review" and v["headline"] == "Review 1 finding"
    assert [i["href"] for i in v["items"]] == ["/threats", "/devices"]
    assert v["items"][1]["label"] == "1 unnamed device"


def test_unnamed_devices_are_a_nudge_not_a_warning() -> None:
    # A few nameless gadgets must not keep Home amber for good.
    v = build_verdict(attacks=0, to_review=0, problems=[], unnamed=3)
    assert v["level"] == "ok" and v["headline"] == "All clear" and v["picture"] == "protected"
    assert v["reason"] == "No threats, every monitor running. 3 devices have no name yet."
    assert [i["href"] for i in v["items"]] == ["/devices"]

    one = build_verdict(attacks=0, to_review=0, problems=[], unnamed=1)
    assert one["reason"].endswith("1 device has no name yet.")


def test_guest_times_are_read_from_the_rotator_format() -> None:
    assert _local_ts("Mon 2026-11-23 09:00") is not None
    assert _local_ts("") is None and _local_ts(None) is None and _local_ts("soon") is None


def test_pages_use_the_owner_vocabulary_and_no_confirm_dialogs() -> None:
    js = (STATIC / "static" / "dashboard.js").read_text(encoding="utf-8")
    assert "window.confirm" not in js and "Tap again to block" in js
    texts = [p.read_text(encoding="utf-8") for p in (STATIC / "templates").glob("*.html")]
    texts.append(js)
    for text in texts:
        assert ">Retire<" not in text and "Untagged first" not in text
        assert " Untagged<" not in text and "known-bad feeds" not in text
        assert "innerHTML" not in text
    index = (STATIC / "templates" / "index.html").read_text(encoding="utf-8")
    assert "Mark as no longer used" in index and "no longer used</span>" in index
    assert 'aria-expanded="false"' in index


def test_every_page_has_the_one_status_pill_and_the_shared_script() -> None:
    base = (STATIC / "templates" / "base.html").read_text(encoding="utf-8")
    assert 'id="pageStatus"' in base and 'aria-live="polite"' in base and "common.js" in base
    for page in (STATIC / "templates").glob("*.html"):
        assert "{% block status %}" not in page.read_text(encoding="utf-8"), page.name
