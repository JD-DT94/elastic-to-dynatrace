"""AppD schedules -> Dynatrace maintenance windows, and the topology detectors.

The schedule conversion produces a real deployable Settings object, so the tests
pin the arithmetic (duration, midnight crossing) and the two things that make a
maintenance window dangerous when wrong: a missing timezone, and a placeholder
window silently standing in for a real one.
"""

import json

import pytest

from e2d.appd.instrumentation import (BACKENDS, DB_COLLECTORS, SERVICE_ENDPOINTS,
                                      detect_kind, translate_instrumentation)
from e2d.appd.schedules import (SCHEMA, looks_like_schedules, render_schedules,
                                translate_schedules)
from e2d.migrate import classify, run_migration


def _window(res, index=0):
    return res.windows[index]["value"]


def _timewindow(value):
    sched = value["schedule"]
    block = sched.get("weeklyRecurrence") or sched.get("dailyRecurrence")
    return block["timeWindow"]


BUSINESS_HOURS = {"name": "Business Hours", "timezone": "Europe/London",
                  "scheduleType": "WEEKLY", "startTime": "09:00", "endTime": "17:30",
                  "days": ["MONDAY", "TUESDAY", "WEDNESDAY", "THURSDAY", "FRIDAY"]}
NIGHTLY = {"name": "Nightly Batch", "timeZone": "UTC", "recurrenceType": "DAILY",
           "startTime": "23:00", "endTime": "02:00"}


# --- detection --------------------------------------------------------------- #

def test_schedule_export_is_detected(tmp_path):
    p = tmp_path / "sched.json"
    text = json.dumps([BUSINESS_HOURS])
    p.write_text(text, encoding="utf-8")
    assert classify(p, text) == "appd_schedules"


def test_schedule_detection_does_not_claim_other_appd_json():
    # a health rule also has `name`, and must not be mistaken for a schedule
    assert not looks_like_schedules([{"name": "rule", "evalCriterias": {}}])
    assert not looks_like_schedules([{"name": "x"}])
    assert not looks_like_schedules({})


# --- conversion --------------------------------------------------------------- #

def test_weekly_schedule_becomes_a_weekly_window():
    res = translate_schedules(json.dumps([BUSINESS_HOURS]))
    value = _window(res)
    assert res.windows[0]["schemaId"] == SCHEMA
    assert value["schedule"]["scheduleType"] == "WEEKLY"
    tw = _timewindow(value)
    assert tw["startTime"] == "09:00"
    assert tw["durationMinutes"] == 510          # 09:00 to 17:30
    assert tw["timeZone"] == "Europe/London"
    assert value["schedule"]["weeklyRecurrence"]["days"] == [
        "MONDAY", "TUESDAY", "WEDNESDAY", "THURSDAY", "FRIDAY"]


def test_window_crossing_midnight_gets_a_positive_duration():
    res = translate_schedules(json.dumps([NIGHTLY]))
    tw = _timewindow(_window(res))
    assert tw["startTime"] == "23:00"
    assert tw["durationMinutes"] == 180          # 23:00 -> 02:00, not negative


def test_missing_timezone_defaults_to_utc_and_says_so():
    res = translate_schedules(json.dumps([
        {"name": "No TZ", "timezone": "", "scheduleType": "DAILY",
         "startTime": "01:00", "endTime": "02:00"}]))
    assert _timewindow(_window(res))["timeZone"] == "UTC"
    notes = " ".join(res.report.format_deduped())
    assert "no timezone" in notes
    # the consequence has to be stated, not just the fact
    assert "outage nobody was told about" in notes


def test_unreadable_schedule_emits_a_flagged_placeholder():
    res = translate_schedules(json.dumps([{"name": "Vague", "timezone": "UTC",
                                           "scheduleType": "DAILY"}]))
    assert res.windows
    notes = " ".join(res.report.format_deduped())
    assert "placeholder" in notes
    assert "Set the real window before deploying" in notes


def test_suppression_mode_is_stated():
    res = translate_schedules(json.dumps([BUSINESS_HOURS]))
    assert _window(res)["generalProperties"]["suppression"] == "DONT_DETECT_PROBLEMS"
    assert any("suppression mode" in n for n in res.report.format_deduped())


def test_multiple_occurrence_blocks_are_flagged_not_dropped():
    res = translate_schedules(json.dumps([
        dict(BUSINESS_HOURS, occurrence=[{"a": 1}, {"b": 2}, {"c": 3}])]))
    assert any("3 separate occurrence blocks" in n for n in res.report.format_deduped())


def test_hour_and_minute_object_form_is_understood():
    res = translate_schedules(json.dumps([
        {"name": "Obj", "timezone": "UTC", "scheduleType": "DAILY",
         "startTime": {"hour": 7, "minute": 5}, "durationInMinutes": 45}]))
    tw = _timewindow(_window(res))
    assert tw["startTime"] == "07:05"
    assert tw["durationMinutes"] == 45


def test_render_lists_each_window():
    res = translate_schedules(json.dumps([BUSINESS_HOURS, NIGHTLY]))
    md = render_schedules(res, "sched.json")
    assert "Business Hours" in md and "Nightly Batch" in md
    assert "settings/objects" in md


def test_empty_export_is_manual():
    res = translate_schedules(json.dumps([]))
    assert res.report.has_blocking


# --- topology detectors -------------------------------------------------------- #

@pytest.mark.parametrize("doc,expected", [
    ([{"name": "/checkout", "serviceEndpointType": "SERVLET", "tierName": "web"}],
     SERVICE_ENDPOINTS),
    ([{"name": "orders-db", "exitPointType": "JDBC"}], BACKENDS),
    ([{"name": "prod-oracle", "collectorType": "ORACLE"}], DB_COLLECTORS),
])
def test_topology_detection(doc, expected):
    assert detect_kind(doc) == expected


def test_service_endpoints_are_reported_as_nothing_to_recreate():
    res = translate_instrumentation(json.dumps(
        [{"name": "/checkout", "serviceEndpointType": "SERVLET", "tierName": "web"}]),
        SERVICE_ENDPOINTS)
    notes = " ".join(res.report.format_deduped())
    assert "nothing to recreate" in notes
    assert not res.report.has_blocking          # good news, not a gap


def test_backends_point_at_smartscape():
    res = translate_instrumentation(
        json.dumps([{"name": "orders-db", "exitPointType": "JDBC"}]), BACKENDS)
    assert "Smartscape" in " ".join(res.report.format_deduped())


def test_database_collectors_are_a_per_database_decision():
    res = translate_instrumentation(
        json.dumps([{"name": "prod-oracle", "collectorType": "ORACLE"}]), DB_COLLECTORS)
    notes = " ".join(res.report.format_deduped())
    assert "extension" in notes
    assert "per database" in notes


# --- end to end ----------------------------------------------------------------- #

def test_schedules_reach_the_output_as_a_settings_body(tmp_path):
    indir = tmp_path / "in"
    indir.mkdir()
    (indir / "schedules.json").write_text(json.dumps([BUSINESS_HOURS, NIGHTLY]),
                                          encoding="utf-8")
    out = tmp_path / "out"
    s = run_migration(str(indir), str(out))

    assert "appd_schedules" in s.appd_kinds
    assert any(it.category == "maintenance" for it in s.items)
    body = json.loads((out / "maintenance" / "schedules.windows.json")
                      .read_text(encoding="utf-8"))
    assert len(body) == 2
    assert all(o["schemaId"] == SCHEMA and o["scope"] == "environment" for o in body)
    # and the catalogue notices it
    covr = (out / "APPD-CATALOGUE.md").read_text(encoding="utf-8")
    assert "Schedules" in covr
