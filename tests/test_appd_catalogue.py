"""The AppD config catalogue, the phased sequencing guide, and the coverage report.

The catalogue is data that drives two generated documents, so the tests here are
mostly integrity checks: every item must land in a real area and a real phase,
every detector kind it references must actually be produced by classify(), and
the sequencing must keep the constraints that fix its order — instrumentation
before anything that reads agent data, Davis baselining before alert tuning,
decommission last.
"""

import json

import pytest

from e2d.appd import catalogue as cat
from e2d.appd import metrics as appd_metrics
from e2d.appd.instrumentation import (DATA_COLLECTORS, INFO_POINTS, TXN_RULES,
                                      detect_kind, render_instrumentation,
                                      translate_instrumentation)
from e2d.appd.sequencing import render_coverage, render_sequencing
from e2d.migrate import PRODUCT_OF_KIND, classify, run_migration

APPROACHES = {cat.AUTOMATIC, cat.ASSISTED, cat.REBUILD, cat.NOT_NEEDED}


# --- catalogue integrity ---------------------------------------------------- #

def test_catalogue_covers_every_area():
    areas = {i.area for i in cat.CATALOGUE}
    assert areas == set(cat.AREA_TITLE), areas.symmetric_difference(cat.AREA_TITLE)


def test_every_item_is_well_formed():
    for item in cat.CATALOGUE:
        assert item.appd and item.dynatrace, item
        assert item.approach in APPROACHES, item
        assert item.phase in cat.PHASE_TITLE, item
        assert item.area in cat.AREA_TITLE, item


def test_detector_kinds_are_real():
    """A detected_by kind classify() never emits would silently never mark present."""
    for item in cat.CATALOGUE:
        for kind in item.detected_by:
            assert kind in PRODUCT_OF_KIND, f"{item.appd} references unknown kind {kind}"
            assert PRODUCT_OF_KIND[kind] == "appdynamics", kind


def test_phases_are_a_contiguous_run():
    numbers = [n for n, _, _ in cat.PHASES]
    assert numbers == list(range(1, 11))


def test_the_not_needed_items_are_actually_populated():
    """The point of the catalogue is that some of the estate needs no work."""
    not_needed = [i for i in cat.CATALOGUE if i.approach == cat.NOT_NEEDED]
    assert len(not_needed) >= 5
    claims = " ".join(i.appd.lower() for i in not_needed)
    for expected in ("business transaction", "baseline", "snapshot"):
        assert expected in claims, expected


def test_detected_maps_kinds_to_items():
    items = cat.detected({"appd_health_rule"})
    assert items
    assert all("appd_health_rule" in i.detected_by for i in items)
    assert cat.detected(set()) == []


# --- sequencing -------------------------------------------------------------- #

def test_sequencing_lists_all_ten_phases_in_order():
    md = render_sequencing()
    positions = []
    for number, title, _ in cat.PHASES:
        heading = f"## Phase {number} — {title}"
        assert heading in md, heading
        positions.append(md.index(heading))
    assert positions == sorted(positions), "phases are out of order"


def test_sequencing_keeps_the_ordering_constraints():
    md = render_sequencing()
    # nothing exists until an agent reports, so instrumentation precedes alerting
    assert md.index("Phase 3 — Instrumentation") < md.index("Phase 5 — Alerting")
    # dashboards are built on data that must already flow
    assert md.index("Phase 3 — Instrumentation") < md.index("Phase 6 — Dashboards")
    # and nothing is removed until it has been validated
    assert md.index("Phase 9 — Validation") < md.index("Phase 10 — Decommission")
    # the two constraints that set the calendar
    assert "7 to 14 days" in md
    assert "2 to 4 weeks" in md


def test_sequencing_warns_against_a_one_to_one_port():
    md = render_sequencing()
    assert "Do not attempt a 1:1 port" in md
    assert "Rebuild dashboards" in md
    assert "Historical data does not transfer" in md


def test_sequencing_marks_what_the_export_contained():
    # count the marker only where it tags an item, not where the intro explains it
    tagged = "- [in your export] **"
    assert render_sequencing({"appd_health_rule"}).count(tagged) >= 1
    assert render_sequencing().count(tagged) == 0


def test_sequencing_reports_the_rollout_size():
    md = render_sequencing({"appd_inventory"}, hosts=320, waves=7)
    assert "320 host(s)" in md
    assert "7 wave(s)" in md


def test_sequencing_folds_in_the_health_rule_outcome():
    md = render_sequencing({"appd_health_rule"},
                           converted={"converted": 40, "covered-by-davis": 55, "manual": 5})
    assert "40 converted to detectors" in md
    assert "55 already covered by built-in Davis" in md
    assert "5 needing a manual rebuild" in md


# --- coverage report --------------------------------------------------------- #

def test_coverage_lists_every_catalogue_item():
    md = render_coverage()
    for item in cat.CATALOGUE:
        assert item.appd in md, item.appd


def test_coverage_marks_only_what_was_found():
    empty = render_coverage()
    found = render_coverage({"appd_health_rule", "appd_dashboard"})
    assert empty.count("| yes |") == 0
    assert found.count("| yes |") >= 3


def test_coverage_leads_with_the_nothing_to_migrate_count():
    md = render_coverage()
    n = cat.counts_by_approach()[cat.NOT_NEEDED]
    assert f"The {n} *nothing to migrate* items" in md


# --- new instrumentation detectors ------------------------------------------- #

@pytest.mark.parametrize("doc,expected", [
    ([{"name": "OrderValue", "informationPointType": "POJO"}], INFO_POINTS),
    ({"informationPoints": [{"name": "x"}]}, INFO_POINTS),
    ({"dataGathererConfigs": [{"name": "userId"}]}, DATA_COLLECTORS),
    ([{"name": "u", "dataGathererType": "METHOD_INVOCATION"}], DATA_COLLECTORS),
    ([{"name": "S", "ruleType": "custom", "entryPointType": "SERVLET"}], TXN_RULES),
])
def test_instrumentation_detection(doc, expected):
    assert detect_kind(doc) == expected


@pytest.mark.parametrize("doc", [
    {"name": "not appd"},
    [{"id": 1, "name": "plain"}],
    {"query": {"bool": {}}},
    [],
])
def test_instrumentation_detection_is_narrow(doc):
    assert detect_kind(doc) is None


def test_information_points_are_a_redesign_not_a_translation():
    res = translate_instrumentation(
        json.dumps([{"name": "OrderValue", "informationPointType": "POJO"}]), INFO_POINTS)
    assert res.names == ["OrderValue"]
    assert res.report.has_blocking          # not automatable, and says so
    notes = " ".join(res.report.format_deduped())
    assert "business events" in notes.lower()
    md = render_instrumentation(res, "info.json")
    assert "OrderValue" in md


def test_transaction_rules_start_from_assuming_none_are_needed():
    res = translate_instrumentation(
        json.dumps([{"name": "S", "ruleType": "custom", "entryPointType": "SERVLET"}]),
        TXN_RULES)
    notes = " ".join(res.report.format_deduped())
    assert "assuming you need none of them" in notes
    assert "custom service" in notes


def test_data_collectors_map_to_request_attributes():
    res = translate_instrumentation(
        json.dumps({"dataGathererConfigs": [{"name": "userId"}]}), DATA_COLLECTORS)
    assert "request attributes" in " ".join(res.report.format_deduped()).lower()


# --- widened metric map ------------------------------------------------------ #

def test_jvm_heap_rescales_mb_to_bytes():
    mapping, reason = appd_metrics.resolve(
        "Application Infrastructure Performance|web|JVM|Memory|Heap|Current Usage (MB)")
    assert reason is None
    assert appd_metrics.convert_threshold(512, mapping) == "536870912"


def test_cpu_idle_is_refused_with_the_inversion_explained():
    mapping, reason = appd_metrics.resolve(
        "Application Infrastructure Performance|web|Hardware Resources|CPU|%Idle")
    assert mapping is None
    assert "Invert the condition" in reason


def test_ambiguous_metric_names_are_refused_rather_than_assumed():
    for path in ("Overall Application Performance|ART (ms)",
                 "Overall Application Performance|Calls"):
        mapping, reason = appd_metrics.resolve(path)
        assert mapping is None, path
        assert reason


# --- end to end --------------------------------------------------------------- #

def test_appd_run_writes_the_sequencing_and_catalogue(tmp_path):
    indir = tmp_path / "in"
    indir.mkdir()
    (indir / "nodes.json").write_text(json.dumps(
        [{"id": 1, "name": "n1", "tierName": "web", "applicationName": "Checkout",
          "machineName": "host01", "appAgentVersion": "23.1"}]), encoding="utf-8")
    (indir / "info.json").write_text(json.dumps(
        [{"name": "OrderValue", "informationPointType": "POJO"}]), encoding="utf-8")
    out = tmp_path / "out"
    s = run_migration(str(indir), str(out))

    assert set(s.appd_kinds) == {"appd_inventory", "appd_infopoints"}
    seq = (out / "APPD-SEQUENCING.md").read_text(encoding="utf-8")
    covr = (out / "APPD-CATALOGUE.md").read_text(encoding="utf-8")
    assert "Phase 10 — Decommission" in seq
    assert "1 host(s)" in seq
    assert "| yes |" in covr
    assert (out / "instrumentation" / "info.md").exists()

    report = (out / "MIGRATION_REPORT.md").read_text(encoding="utf-8")
    assert "APPD-SEQUENCING.md" in report and "APPD-CATALOGUE.md" in report


def test_elastic_only_run_writes_no_appd_documents(tmp_path):
    indir = tmp_path / "in"
    indir.mkdir()
    (indir / "p.conf").write_text(
        'input { beats { port => 5044 } }\n'
        'filter { mutate { add_field => { "env" => "prod" } } }\n'
        'output { elasticsearch { hosts => ["es:9200"] } }\n', encoding="utf-8")
    out = tmp_path / "out"
    s = run_migration(str(indir), str(out))
    assert s.appd_kinds == []
    assert not (out / "APPD-SEQUENCING.md").exists()
    assert not (out / "APPD-CATALOGUE.md").exists()
