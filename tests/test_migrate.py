"""The `migrate` front door: folder of Elastic exports -> artifacts + report."""

import json
from pathlib import Path

import pytest

from e2d.migrate import classify, run_migration, render_report, MigrationSummary, Item

FIXROOT = Path(__file__).resolve().parents[1] / "examples" / "fixtures" / "elastic-fixtures"


def test_classify_by_suffix_and_content(tmp_path):
    assert classify(Path("x.ndjson")) == "kibana"
    assert classify(Path("q.esql")) == "esql"
    assert classify(Path("p.conf")) == "logstash"
    assert classify(Path("p.json"), '{"processors": []}') == "ingest"
    assert classify(Path("q.json"), '{"query": {"bool": {}}}') == "querydsl"
    assert classify(Path("a.json"), '{"name": "not a pipeline"}') == "unknown"
    assert classify(Path("notes.md")) == "unknown"


def test_secret_scan_flags_credentials():
    s = MigrationSummary()
    from e2d.migrate import _scan_secrets
    _scan_secrets('kafka { password => "hunter2" bootstrap => "h:9092" }', "p.conf", s)
    assert any("password" in x for x in s.secrets)


def test_report_renders_plain_english():
    s = MigrationSummary(items=[
        Item("dashboard", "dash.ndjson", "OK", ["dashboards/dash.json"]),
        Item("pipeline", "p.conf", "MANUAL", ["pipelines/p.dpl"], ["[MANUAL] ruby has no target"]),
    ])
    s.secrets = ["p.conf: password"]
    md = render_report(s)
    assert "migration report" in md.lower()
    assert "ready to use" in md
    assert "What needs your attention" in md and "ruby has no target" in md
    assert "🔐 Security" in md and "p.conf: password" in md
    assert "Next steps" in md


def test_classify_recognises_more_shapes(tmp_path):
    from e2d.migrate import classify
    # Kibana NDJSON saved with a .json extension
    nd = tmp_path / "vis.json"
    nd.write_text('{"id":"a","type":"visualization","attributes":{}}\n'
                  '{"id":"b","type":"index-pattern","attributes":{}}\n', encoding="utf-8")
    assert classify(nd) == "kibana"
    # cluster-config artifacts
    ilm = tmp_path / "ilm.json"
    ilm.write_text(json.dumps({"policy": {"phases": {"delete": {"min_age": "30d"}}}}),
                   encoding="utf-8")
    assert classify(ilm) == "ilm_policy"
    tpl = tmp_path / "tpl.json"
    tpl.write_text(json.dumps({"index_patterns": ["logs-*"], "template": {}}), encoding="utf-8")
    assert classify(tpl) == "index_template"
    enr = tmp_path / "enrich.json"
    enr.write_text(json.dumps({"match": {"indices": "ref", "match_field": "id",
                                         "enrich_fields": ["team"]}}), encoding="utf-8")
    assert classify(enr) == "enrich_policy"


def test_vis_only_export_synthesizes_dashboard(tmp_path):
    export = {"id": "v1", "type": "visualization", "references": [],
              "attributes": {"title": "Errors by service", "visState": json.dumps({
                  "type": "horizontal_bar", "title": "Errors by service",
                  "aggs": [{"id": "1", "type": "count", "schema": "metric", "params": {}},
                           {"id": "2", "type": "terms", "schema": "segment",
                            "params": {"field": "service.name", "size": 5}}]}),
                  "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps(
                      {"query": {"query": "", "language": "kuery"}, "filter": []})}}}
    (tmp_path / "in").mkdir()
    (tmp_path / "in" / "solo_vis.json").write_text(json.dumps(export), encoding="utf-8")
    s = run_migration(str(tmp_path / "in"), str(tmp_path / "out"))
    dashboards = list((tmp_path / "out" / "dashboards").glob("*.json"))
    assert len(dashboards) == 1
    dash = json.loads(dashboards[0].read_text(encoding="utf-8"))
    # files hold the bare content document (importable via Dashboards app Upload)
    assert "content" not in dash and "version" in dash and "layouts" in dash
    tiles = dash["tiles"]
    assert len(tiles) == 1
    assert "summarize" in list(tiles.values())[0]["query"]
    assert any("no dashboard, only saved visualizations" in n
               for it in s.items for n in it.notes)


def test_suggested_config_and_metrics_guide(tmp_path):
    panels = [{"panelIndex": "1", "type": "visualization",
               "gridData": {"x": 0, "y": 0, "w": 24, "h": 12},
               "embeddableConfig": {"savedVis": {
                   "type": "metrics", "title": "TS",
                   "params": {"type": "timeseries",
                              "series": [{"id": "a", "label": "avg_rt", "split_mode": "terms",
                                          "terms_field": "service.name",
                                          "metrics": [{"type": "avg", "field": "response_time"}]}]}}}}]
    export = "\n".join([
        json.dumps({"id": "ip1", "type": "index-pattern",
                    "attributes": {"title": "mysterious-index-*"}}),
        json.dumps({"id": "d1", "type": "dashboard", "references":
                    [{"name": "1:panel_1", "type": "index-pattern", "id": "ip1"}],
                    "attributes": {"title": "T", "panelsJSON": json.dumps(panels)}}),
    ])
    (tmp_path / "in").mkdir()
    (tmp_path / "in" / "export.ndjson").write_text(export, encoding="utf-8")
    s = run_migration(str(tmp_path / "in"), str(tmp_path / "out"))
    # unmatched index -> suggested mapping config
    assert "mysterious-index-*" in s.unmatched_indexes
    cfg = json.loads((tmp_path / "out" / "mapping.config.suggested.json").read_text(encoding="utf-8"))
    assert any(r["pattern"].startswith("^mysterious") for r in cfg["index_map"])
    # timeseries tile on logs -> metrics guide with extraction scaffold + swap query
    assert s.metrics_advisories >= 1
    guide = (tmp_path / "out" / "METRICS-GUIDE.md").read_text(encoding="utf-8")
    assert "Metric extraction" in guide and "response_time" in guide
    assert "timeseries avg(log.response.time" in guide.replace("_", ".") or "timeseries avg(" in guide
    # report mentions both
    report = (tmp_path / "out" / "MIGRATION_REPORT.md").read_text(encoding="utf-8")
    assert "METRICS-GUIDE.md" in report and "mapping.config.suggested.json" in report


def test_inline_mapping_config_is_applied(tmp_path):
    (tmp_path / "in").mkdir()
    (tmp_path / "in" / "mapping.config.json").write_text(json.dumps(
        {"index_map": [{"pattern": "^special", "data_object": "spans"}]}), encoding="utf-8")
    export = "\n".join([
        json.dumps({"id": "ip1", "type": "index-pattern", "attributes": {"title": "special-idx"}}),
        json.dumps({"id": "d1", "type": "dashboard", "references":
                    [{"name": "1:panel_1", "type": "index-pattern", "id": "ip1"}],
                    "attributes": {"title": "T", "panelsJSON": json.dumps(
                        [{"panelIndex": "1", "type": "visualization",
                          "gridData": {"x": 0, "y": 0, "w": 24, "h": 12},
                          "embeddableConfig": {"savedVis": {"type": "table", "title": "t",
                              "data": {"aggs": [], "searchSource": {}}}}}])}}),
    ])
    (tmp_path / "in" / "export.ndjson").write_text(export, encoding="utf-8")
    s = run_migration(str(tmp_path / "in"), str(tmp_path / "out"))
    assert any("applied to this whole run" in x for x in s.skipped)
    assert "special-idx" not in s.unmatched_indexes


def test_report_dedupes_repeated_notes():
    from e2d.report import Report
    r = Report()
    for _ in range(40):
        r.info("Dropped `.keyword` suffix from `x.keyword`.")
    r.warn("Something singular.")
    lines = r.format_deduped()
    assert len(lines) == 2
    assert "(×40)" in lines[0]


def test_malformed_panels_json_is_survivable(tmp_path):
    (tmp_path / "in").mkdir()
    (tmp_path / "in" / "bad.ndjson").write_text(json.dumps(
        {"id": "d1", "type": "dashboard", "references": [],
         "attributes": {"title": "Broken", "panelsJSON": "{{{not json"}}), encoding="utf-8")
    s = run_migration(str(tmp_path / "in"), str(tmp_path / "out"))
    assert s.counts()["ERROR"] == 0
    assert any("malformed panelsJSON" in n for it in s.items for n in it.notes)


@pytest.mark.skipif(not FIXROOT.exists(), reason="fixtures not present")
def test_migrate_fixtures_end_to_end(tmp_path):
    summary = run_migration(str(FIXROOT), str(tmp_path))
    # the fixtures include logstash, ingest and dashboards -> all three categories appear
    cats = {it.category for it in summary.items}
    assert {"pipeline", "dashboard"} <= cats
    # a report and at least one converted output exist
    assert (tmp_path / "MIGRATION_REPORT.md").exists()
    assert any((tmp_path / sub).exists() for sub in ("pipelines", "dashboards", "queries"))
    # the complex logstash pipeline carries a MANUAL (ruby/kafka)
    assert any(it.status in ("REVIEW", "MANUAL") for it in summary.items)
