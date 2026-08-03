"""Tests for the Kibana -> Dynatrace dashboard converter: KQL, aggs, and an
end-to-end smoke test against the bundled real export."""

import json
from pathlib import Path

import pytest

from e2d.config import MappingConfig
from e2d.report import Report
from e2d.dashboards.kql import translate_kql
from e2d.dashboards.aggs import build_agg_plan, translate_search_filters
from e2d.dashboards.kibana_loader import KibanaExport
from e2d.dashboards.converter import convert_dashboard

EXPORT = Path(__file__).resolve().parents[1] / "examples" / "export_dashboards.ndjson"


def kql(q, do="logs"):
    return translate_kql(q, MappingConfig(), do, Report())


# ---- KQL ----------------------------------------------------------------

def test_kql_field_match():
    assert kql('status : "ERROR"') == 'status == "ERROR"'


def test_kql_keyword_suffix_stripped():
    assert kql('app_name.keyword : "x"') == 'app_name == "x"'


def test_kql_or_list_to_in():
    out = kql('svc : ("a" or "b")')
    assert 'in(svc, {"a", "b"})' == out


def test_kql_and_or_not():
    out = kql('a : "1" and not b : "2"')
    assert "and" in out and "not" in out and 'a == "1"' in out


def test_kql_exists():
    assert kql("host : *") == "isNotNull(host)"


def test_kql_range():
    assert kql("bytes > 100") == "bytes > 100"


def test_kql_wildcard_to_matchesvalue():
    assert "matchesValue(name, \"web*\")" in kql('name : web*')


# ---- aggregations -------------------------------------------------------

def test_filters_agg_becomes_countif():
    aggs = [
        {"id": "1", "type": "count", "schema": "metric", "params": {}},
        {"id": "2", "type": "filters", "schema": "segment", "params": {"filters": [
            {"input": {"query": 'type : "a"', "language": "kuery"}, "label": "A"},
            {"input": {"query": 'type : "b"', "language": "kuery"}, "label": "B"},
        ]}},
    ]
    plan = build_agg_plan(aggs, MappingConfig(), "logs", Report())
    joined = " ".join(plan.metrics)
    assert "A = countIf(type == \"a\")" in joined
    assert "B = countIf(type == \"b\")" in joined


def test_date_histogram_makes_timeseries():
    aggs = [
        {"id": "1", "type": "count", "schema": "metric", "params": {}},
        {"id": "2", "type": "date_histogram", "schema": "segment",
         "params": {"field": "@timestamp", "interval": "auto", "used_interval": "10m"}},
    ]
    plan = build_agg_plan(aggs, MappingConfig(), "logs", Report())
    assert plan.mode == "makeTimeseries"
    assert plan.interval == "10m"


def test_terms_agg_groups_and_limits():
    aggs = [
        {"id": "1", "type": "count", "schema": "metric", "params": {}},
        {"id": "2", "type": "terms", "schema": "segment",
         "params": {"field": "host.name", "size": 5, "order": "desc"}},
    ]
    plan = build_agg_plan(aggs, MappingConfig(), "logs", Report())
    assert plan.by_fields == ["host.name"]
    assert plan.limit == 5


def test_terms_agg_strips_keyword_suffix():
    # Real-world Kibana terms buckets group by `<field>.keyword`; the keyword
    # multi-field has no DQL equivalent, so it must be stripped from `by:`.
    aggs = [
        {"id": "1", "type": "count", "schema": "metric", "params": {}},
        {"id": "2", "type": "terms", "schema": "segment",
         "params": {"field": "tracking.transactionName.keyword", "size": 100}},
    ]
    plan = build_agg_plan(aggs, MappingConfig(), "logs", Report())
    # lowercased: Grail normalizes attribute keys to lowercase at ingest
    assert plan.by_fields == ["tracking.transactionname"]


def test_field_audit_splits_builtin_and_custom():
    from e2d.dashboards.field_audit import audit_dashboard_fields
    dashboard = {"content": {"tiles": {
        "t1": {"type": "data", "query":
               "fetch logs\n| summarize Errors = countIf(loglevel == \"ERROR\"), "
               "by: {tracking.transactionName}\n| sort Errors desc\n| limit 100"},
        "t2": {"type": "data", "query":
               "fetch logs\n| filter application_name == \"x\" and audit.logText == \"y\"\n| limit 100"},
        "md": {"type": "markdown", "content": "ignored"},
    }}}
    audit = audit_dashboard_fields(dashboard)
    # loglevel is a semantic-dictionary field; the rest are bespoke attributes.
    assert audit["builtin"] == ["loglevel"]
    assert audit["custom"] == ["application_name", "audit.logText", "tracking.transactionName"]
    # aliases (Errors), functions (countIf), the data object (logs) are not fields
    assert "Errors" not in audit["custom"] and "logs" not in audit["custom"]


def test_field_manifest_renders_scaffold_for_custom_fields():
    from e2d.dashboards.field_audit import audit_dashboard_fields, render_field_manifest
    dashboard = {"content": {"tiles": {
        "t1": {"type": "data", "query":
               "fetch logs\n| summarize c = count(), by: {tracking.transactionName}\n| limit 10"},
    }}}
    audit = audit_dashboard_fields(dashboard)
    assert audit["objects"]["tracking.transactionName"] == ["logs"]
    md = render_field_manifest("My Dashboard", audit)
    assert "# Field dependencies — My Dashboard" in md
    assert "`tracking.transactionName`" in md
    # an OpenPipeline extraction scaffold with both rename + parse options and a TODO
    assert "OpenPipeline extraction scaffolds" in md
    assert "fieldsAdd tracking.transactionName" in md
    assert "parse content," in md
    assert "TODO" in md


def test_cardinality_to_countdistinct():
    aggs = [{"id": "1", "type": "cardinality", "schema": "metric",
             "params": {"field": "user.id"}}]
    plan = build_agg_plan(aggs, MappingConfig(), "logs", Report())
    assert "countDistinct(user.id)" in " ".join(plan.metrics)


def test_search_filter_phrase_and_exists():
    filters = [
        {"meta": {"type": "phrase", "key": "env.keyword", "params": {"query": "prod"}}},
        {"meta": {"type": "exists", "key": "trace.id"}},
    ]
    preds = translate_search_filters(filters, MappingConfig(), "logs", Report())
    assert 'env == "prod"' in preds[0]
    assert "isNotNull(trace.id)" in preds[1]


# ---- KQL robustness (real-world authored queries) ------------------------

def test_kql_quoted_field_name():
    # KQL allows quoted field names; must not become a full-text term
    out = kql('"tracking.transactionName.keyword": "tx.salesforce.guarantee"')
    # lowercased: Grail normalizes attribute keys to lowercase at ingest
    assert out == 'tracking.transactionname == "tx.salesforce.guarantee"'
    assert "matchesPhrase" not in out


def test_kql_quoted_field_does_not_drop_rest_of_query():
    out = kql('("f.keyword": "a" and (g : "b" or g : "c"))')
    assert 'f == "a"' in out and 'g == "b"' in out and 'g == "c"' in out


def test_kql_redundant_operator_tolerated():
    out = kql('a : "1" and AND b : "2"')
    assert out == 'a == "1" and b == "2"'


def test_kql_partial_parse_warns():
    rep = Report()
    translate_kql('a : "1" ) stray', MappingConfig(), "logs", rep)
    assert any("partially translated" in w.message for w in rep.warnings)


# ---- filter DSL: custom + combined ---------------------------------------

def test_custom_filter_translates_query_dsl():
    filters = [{"meta": {"type": "custom", "key": "query"},
                "query": {"bool": {"must": [{"match_phrase": {"env": "prod"}}],
                                   "must_not": [{"exists": {"field": "err"}}]}}}]
    preds = translate_search_filters(filters, MappingConfig(), "logs", Report())
    assert len(preds) == 1
    assert 'env == "prod"' in preds[0] and "isNotNull(err)" in preds[0]


def test_combined_filter_recurses():
    filters = [{"meta": {"type": "combined", "relation": "OR", "params": [
        {"meta": {"type": "phrase", "key": "a", "params": {"query": "1"}}},
        {"meta": {"type": "phrase", "key": "b", "params": {"query": "2"}}},
    ]}}]
    preds = translate_search_filters(filters, MappingConfig(), "logs", Report())
    assert preds == ['(a == "1") or (b == "2")']


# ---- filters bucket x non-count metric + pipeline aggs -------------------

def test_filters_bucket_with_avg_uses_if_wrapping():
    aggs = [
        {"id": "1", "type": "avg", "schema": "metric", "params": {"field": "duration"}},
        {"id": "2", "type": "filters", "schema": "segment", "params": {"filters": [
            {"input": {"query": 'type : "a"', "language": "kuery"}, "label": "A"},
        ]}},
    ]
    plan = build_agg_plan(aggs, MappingConfig(), "logs", Report())
    assert 'A = avg(if(type == "a", duration))' in " ".join(plan.metrics)


def test_cumulative_sum_becomes_array_function():
    aggs = [
        {"id": "1", "type": "cumulative_sum", "schema": "metric",
         "params": {"customMetric": {"id": "1-metric", "type": "count", "params": {}}}},
        {"id": "2", "type": "date_histogram", "schema": "segment",
         "params": {"field": "@timestamp", "used_interval": "1h"}},
    ]
    plan = build_agg_plan(aggs, MappingConfig(), "logs", Report())
    assert "count = count()" in " ".join(plan.metrics)
    assert any("arrayCumulativeSum(count)" in p for p in plan.post)


def test_lucene_filters_bucket_translated():
    aggs = [
        {"id": "1", "type": "count", "schema": "metric", "params": {}},
        {"id": "2", "type": "filters", "schema": "segment", "params": {"filters": [
            {"input": {"query": 'status:ERROR', "language": "lucene"}, "label": "Err"},
        ]}},
    ]
    plan = build_agg_plan(aggs, MappingConfig(), "logs", Report())
    joined = " ".join(plan.metrics)
    assert 'countIf(status == "ERROR")' in joined
    assert "countIf(true)" not in joined


# ---- Lens: filters split x metric, last_value, moving_average ------------

def _lens_state(columns, viz="lnsXY"):
    return {"visualizationType": viz, "title": "L",
            "state": {"datasourceStates": {"formBased": {"layers": {
                "l1": {"columns": columns}}}}, "query": {}, "filters": []}}


def test_lens_filters_split_with_avg_not_dropped():
    from e2d.dashboards.lens import convert_lens
    cols = {
        "c1": {"operationType": "average", "sourceField": "duration", "label": "AvgDur"},
        "c2": {"operationType": "filters", "params": {"filters": [
            {"input": {"query": 'type : "a"', "language": "kuery"}, "label": "A"},
            {"input": {"query": 'type : "b"', "language": "kuery"}, "label": "B"},
        ]}},
    }
    rep = Report()
    dql, viz, _, _ = convert_lens(_lens_state(cols), [], "logs-*", MappingConfig(), rep)
    assert 'avg(if(type == "a", duration))' in dql
    assert 'avg(if(type == "b", duration))' in dql
    assert not any("was dropped" in w.message for w in rep.warnings)


def test_lens_last_value_and_moving_average():
    from e2d.dashboards.lens import convert_lens
    cols = {
        "c0": {"operationType": "date_histogram", "sourceField": "@timestamp",
               "params": {"interval": "1h"}},
        "c1": {"operationType": "last_value", "sourceField": "state", "label": "LastState"},
        "c2": {"operationType": "avg", "sourceField": "rt", "label": "AvgRt"},
        "c3": {"operationType": "moving_average", "references": ["c2"],
               "label": "MovAvg", "params": {"window": 3}},
    }
    dql, _, _, _ = convert_lens(_lens_state(cols), [], "logs-*", MappingConfig(), Report())
    assert "takeLast(state)" in dql
    assert "arrayMovingAvg(AvgRt, 3)" in dql


# ---- Lens formulas -------------------------------------------------------

def _formula(f, alias="rate"):
    from e2d.dashboards.lens_formula import translate_formula
    rep = Report()
    ms, posts = translate_formula(f, alias, MappingConfig(), "logs", rep)
    return ms, (posts[0] if posts else None), rep


def test_formula_error_ratio():
    ms, post, _ = _formula("count(kql='status:error') / count()")
    exprs = {m.alias for m in ms}
    assert len(ms) == 2 and post is not None
    assert post.ratio is not None            # rendered with divide-by-zero guard / []
    assert post.alias == "rate"
    assert any(m.func == "countIf" for m in ms)


def test_formula_scaling_and_parens():
    ms, post, _ = _formula("(sum(bytes) - sum(cached_bytes)) / sum(bytes) * 100", alias="pct")
    assert len(ms) == 2                       # sum(bytes) reused, not duplicated
    assert post.expr.endswith("* 100")
    assert post.ratio is None                 # not a bare a/b


def test_formula_single_agg_needs_no_post():
    ms, post, _ = _formula("unique_count(user.id.keyword)", alias="Users")
    assert post is None
    assert len(ms) == 1 and ms[0].alias == "Users"
    assert ms[0].func == "countDistinct" and ms[0].field == "user.id"


def test_formula_round_is_dropped_and_unknown_fails():
    from e2d.dashboards.lens_formula import FormulaError
    ms, post, _ = _formula("round(average(rt) * 1000, 2)", alias="ms")
    assert post is not None and "* 1000" in post.expr
    with pytest.raises(FormulaError):
        _formula("count() + moving_average(count())")   # pipeline nested in arithmetic
    with pytest.raises(FormulaError):
        _formula("count(shift='1d')")


def test_formula_top_level_moving_average():
    from e2d.dashboards.lens_formula import translate_formula
    rep = Report()
    ms, posts = translate_formula("moving_average(average(response_time) / 1000, window=5)",
                                  "ma", MappingConfig(), "logs", rep)
    assert len(ms) == 1 and ms[0].func == "avg"
    assert len(posts) == 2
    assert posts[0].alias == "ma_src" and "/ 1000" in posts[0].expr
    assert posts[1].pipeline is not None
    assert posts[1].pipeline.op == "moving_avg" and posts[1].pipeline.window == 5


def test_lens_formula_column_end_to_end():
    from e2d.dashboards.lens import convert_lens
    cols = {
        "f1": {"operationType": "formula", "label": "Error rate",
               "params": {"formula": "count(kql='level:ERROR') / count()"}},
        "f1X0": {"operationType": "count", "label": "Part of Error rate"},
        "f1X1": {"operationType": "math", "label": "Part of Error rate"},
    }
    rep = Report()
    dql, _, _, _ = convert_lens(_lens_state(cols, viz="lnsMetric"), [], "logs-*",
                             MappingConfig(), rep)
    assert "countIf(level ==" in dql
    assert "fieldsAdd Error_rate" in dql
    # compiled helper columns skipped — no placeholder counts, no math warnings
    assert not any("placeholder" in w.message for w in rep.warnings)


# ---- series colors --------------------------------------------------------

def test_color_normalisation():
    from e2d.dashboards.colors import to_hex
    assert to_hex("rgba(255,0,4,1)") == "#ff0004"
    assert to_hex("rgb(0, 255, 110)") == "#00ff6e"
    assert to_hex("#AbC") == "#aabbcc"
    assert to_hex("#00A69B") == "#00a69b"
    assert to_hex("bogus") is None and to_hex(None) is None


def test_tsvb_series_colors_carried():
    params = {
        "type": "timeseries",
        "series": [{"id": "a", "label": "ERROR", "split_mode": "everything",
                    "chart_type": "bar", "color": "rgba(255,0,4,1)",
                    "metrics": [{"type": "count"}],
                    "filter": {"query": "level : \"ERROR\"", "language": "kuery"}}],
    }
    res, _ = tsvb(params)
    ov = res["settings"]["chartSettings"]["seriesOverrides"]
    assert ov == [{"seriesId": ["ERROR"],
                   "override": {"color": {"Default": "#ff0004"}}}]


def test_legacy_uistate_colors_carried():
    panels = [{"panelIndex": "1", "type": "visualization",
               "gridData": {"x": 0, "y": 0, "w": 24, "h": 12},
               "embeddableConfig": {"savedVis": {
                   "type": "histogram", "title": "By level",
                   "uiState": {"vis": {"colors": {"ERROR": "#ff0004", "WARN": "#d29922"}}},
                   "data": {"aggs": [
                       {"id": "1", "type": "count", "schema": "metric", "params": {}},
                       {"id": "2", "type": "terms", "schema": "segment",
                        "params": {"field": "level", "size": 5}}],
                       "searchSource": {}}}}}]
    export = _dashboard_export(panels)
    dashboard, _ = convert_dashboard(export.dashboards[0], export, MappingConfig())
    tile = dashboard["content"]["tiles"]["1"]
    ids = {o["seriesId"][0]: o["override"]["color"]["Default"]
           for o in tile["visualizationSettings"]["chartSettings"]["seriesOverrides"]}
    assert ids["ERROR"] == "#ff0004" and ids["WARN"] == "#d29922"


def test_lens_yconfig_colors_carried():
    from e2d.dashboards.lens import convert_lens
    cols = {
        "c0": {"operationType": "date_histogram", "sourceField": "@timestamp",
               "params": {"interval": "1h"}},
        "c1": {"operationType": "count", "label": "Errors"},
    }
    state = _lens_state(cols)
    state["state"]["visualization"] = {
        "preferredSeriesType": "line",
        "layers": [{"yConfig": [{"forAccessor": "c1", "color": "#e7664c"}]}]}
    _, _, _, settings = convert_lens(state, [], "logs-*", MappingConfig(), Report())
    assert settings["chartSettings"]["seriesOverrides"] == \
        [{"seriesId": ["Errors"], "override": {"color": {"Default": "#e7664c"}}}]


# ---- Vega -> standard tiles -----------------------------------------------

def _vega_panel(spec):
    return [{"panelIndex": "1", "type": "visualization",
             "gridData": {"x": 0, "y": 0, "w": 24, "h": 12},
             "embeddableConfig": {"savedVis": {
                 "type": "vega", "title": "V", "params": {"spec": spec},
                 "data": {"aggs": [], "searchSource": {}}}}}]


def test_vega_es_query_becomes_standard_tile():
    spec = json.dumps({
        "mark": "area",
        "data": {"url": {"%context%": True, "index": "web-logs-*", "body": {
            "size": 0,
            "query": {"bool": {"filter": [{"term": {"level": "ERROR"}}]}},
            "aggs": {"over_time": {"date_histogram": {"field": "@timestamp",
                                                      "fixed_interval": "30m"}}}}}},
        "encoding": {"x": {"field": "key"}, "y": {"field": "doc_count"}},
    })
    export = _dashboard_export(_vega_panel(spec))
    dashboard, report = convert_dashboard(export.dashboards[0], export, MappingConfig())
    tile = dashboard["content"]["tiles"]["1"]
    assert tile["type"] == "data"
    assert tile["visualization"] == "areaChart"
    assert "makeTimeseries" in tile["query"] and 'level == "ERROR"' in tile["query"]
    assert not report.has_blocking     # no MANUAL placeholder


def test_vega_hjson_comments_and_pie():
    spec = """{
      // errors by service
      "mark": {"type": "arc"},
      "data": {"url": {"index": "web-logs-*", "body": {
        "size": 0,
        "aggs": {"by_svc": {"terms": {"field": "service.name", "size": 5,}},},
      }}},
    }"""
    export = _dashboard_export(_vega_panel(spec))
    dashboard, report = convert_dashboard(export.dashboards[0], export, MappingConfig())
    tile = dashboard["content"]["tiles"]["1"]
    assert tile["type"] == "data" and tile["visualization"] == "pieChart"
    assert "by: {service.name}" in tile["query"]


def test_vega_without_es_source_stays_placeholder():
    spec = json.dumps({"mark": "line",
                       "data": {"values": [{"x": 1, "y": 2}]}})
    export = _dashboard_export(_vega_panel(spec))
    dashboard, report = convert_dashboard(export.dashboards[0], export, MappingConfig())
    assert dashboard["content"]["tiles"]["1"]["type"] == "markdown"
    assert report.has_blocking


# ---- drilldowns + saved time range ---------------------------------------

def test_drilldowns_and_time_restore_are_flagged():
    panels = [{"panelIndex": "1", "type": "visualization",
               "gridData": {"x": 0, "y": 0, "w": 24, "h": 12},
               "embeddableConfig": {
                   "title": "With drill",
                   "enhancements": {"dynamicActions": {"events": [
                       {"action": {"config": {"name": "Go to detail"}}}]}},
                   "savedVis": {"type": "markdown", "params": {"markdown": "x"}}}}]
    export = _dashboard_export(panels, attrs_extra={
        "timeRestore": True, "timeFrom": "now-7d", "timeTo": "now"})
    _, report = convert_dashboard(export.dashboards[0], export, MappingConfig())
    msgs = " ".join(w.message for w in report.warnings)
    assert "drilldown" in msgs and "Go to detail" in msgs
    assert "saved time range" in msgs and "now-7d" in msgs


# ---- verify --data helpers ------------------------------------------------

def test_strip_variable_filters_for_data_check():
    from e2d.api.client import _strip_variable_filters
    dql = ("fetch logs\n| filter in(env, array($Env))\n"
           "| filter level == \"ERROR\"\n| summarize count()")
    out = _strip_variable_filters(dql)
    assert "$Env" not in out
    assert 'level == "ERROR"' in out          # non-variable filters kept
    assert "array(" not in out                # variable stage dropped whole


# ---- TSVB ----------------------------------------------------------------

def tsvb(params, index_title="logs-*"):
    from e2d.dashboards.tsvb import convert_tsvb
    report = Report()
    return convert_tsvb(params, MappingConfig(), report, index_title=index_title), report


def test_tsvb_timeseries_filtered_series_to_maketimeseries():
    # the real-world shape: two series, each its own KQL filter, count metric
    params = {
        "type": "timeseries", "interval": "",
        "series": [
            {"id": "a", "label": "ERROR", "split_mode": "everything", "chart_type": "bar",
             "metrics": [{"type": "count"}],
             "filter": {"query": 'level.keyword:ERROR', "language": "kuery"}},
            {"id": "b", "label": "ALL", "split_mode": "everything", "chart_type": "bar",
             "metrics": [{"type": "count"}]},
        ],
    }
    res, _ = tsvb(params)
    assert res["kind"] == "data"
    assert res["visualization"] == "barChart"
    assert "makeTimeseries" in res["dql"]
    assert 'ERROR = countIf(level == "ERROR")' in res["dql"]
    assert "ALL = count()" in res["dql"]


def test_tsvb_terms_split_and_avg():
    params = {
        "type": "timeseries", "interval": ">=10m",
        "series": [{"id": "a", "label": "lat", "split_mode": "terms",
                    "terms_field": "host.name.keyword", "chart_type": "line",
                    "metrics": [{"type": "avg", "field": "duration"}]}],
    }
    res, _ = tsvb(params)
    assert "avg(duration)" in res["dql"]
    assert "by: {host.name}" in res["dql"]
    assert "interval: 10m" in res["dql"]
    assert res["visualization"] == "lineChart"


def test_tsvb_top_n_and_metric_panels():
    series = [{"id": "a", "label": "count", "split_mode": "terms",
               "terms_field": "svc", "metrics": [{"type": "count"}]}]
    res, _ = tsvb({"type": "top_n", "series": series})
    assert res["visualization"] == "categoricalBarChart"
    assert "summarize" in res["dql"] and "makeTimeseries" not in res["dql"]
    assert "sort count desc" in res["dql"]

    res, _ = tsvb({"type": "metric",
                   "series": [{"id": "a", "metrics": [{"type": "cardinality", "field": "user.id"}]}]})
    assert res["visualization"] == "singleValue"
    assert "countDistinct(user.id)" in res["dql"]


def test_tsvb_pipeline_metric_warns_not_silent():
    params = {"type": "timeseries",
              "series": [{"id": "a", "label": "rate",
                          "metrics": [{"id": "m1", "type": "max", "field": "bytes"},
                                      {"id": "m2", "type": "derivative", "field": "m1"}]}]}
    res, report = tsvb(params)
    # falls back to the input metric, loudly
    assert "max(bytes)" in res["dql"]
    assert any("derivative" in w.message for w in report.warnings)


def test_tsvb_markdown_and_empty_series():
    res, _ = tsvb({"type": "markdown", "markdown": "# hi"})
    assert res == {"kind": "markdown", "content": "# hi"}
    res, report = tsvb({"type": "timeseries", "series": []})
    assert res["kind"] == "markdown"
    assert any("no convertible series" in w.message for w in report.warnings)


def _dashboard_export(panels, attrs_extra=None, references=None, extra_objects=""):
    attrs = {"title": "T", "panelsJSON": json.dumps(panels)}
    attrs.update(attrs_extra or {})
    obj = {"id": "d1", "type": "dashboard", "attributes": attrs,
           "references": references or []}
    import tempfile, os
    text = json.dumps(obj) + ("\n" + extra_objects if extra_objects else "")
    fd, path = tempfile.mkstemp(suffix=".ndjson")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)
    return KibanaExport.load(path)


def test_tsvb_panel_converts_end_to_end():
    panels = [{"panelIndex": "1", "type": "visualization",
               "gridData": {"x": 0, "y": 0, "w": 24, "h": 15},
               "embeddableConfig": {"savedVis": {
                   "type": "metrics", "title": "Errors",
                   "params": {"type": "timeseries",
                              "series": [{"id": "a", "label": "err",
                                          "metrics": [{"type": "count"}],
                                          "filter": {"query": "level:ERROR", "language": "kuery"}}]}}}}]
    export = _dashboard_export(panels)
    dashboard, report = convert_dashboard(export.dashboards[0], export, MappingConfig())
    tile = dashboard["content"]["tiles"]["1"]
    assert tile["type"] == "data"
    assert "countIf" in tile["query"]
    # the old bug: TSVB silently became `fetch logs | limit 100`
    assert "limit 100" not in tile["query"]


# ---- controls -> variables ----------------------------------------------

def test_legacy_control_becomes_wired_variable():
    panels = [
        {"panelIndex": "1", "type": "visualization",
         "gridData": {"x": 0, "y": 0, "w": 12, "h": 8},
         "embeddableConfig": {"savedVis": {
             "type": "input_control_vis", "title": "ctl",
             "params": {"controls": [{"fieldName": "app_name.keyword", "label": "App",
                                      "options": {"multiselect": True}}]}}}},
        {"panelIndex": "2", "type": "visualization",
         "gridData": {"x": 0, "y": 8, "w": 24, "h": 15},
         "embeddableConfig": {"savedVis": {
             "type": "metrics", "title": "TS",
             "params": {"type": "timeseries",
                        "series": [{"id": "a", "metrics": [{"type": "count"}]}]}}}},
    ]
    export = _dashboard_export(panels)
    dashboard, report = convert_dashboard(export.dashboards[0], export, MappingConfig())
    variables = dashboard["content"]["variables"]
    assert len(variables) == 1
    v = variables[0]
    # skill rules: dedup (not summarize-by), empty-string filter, one field, all-selected default
    assert "dedup app_name" in v["input"] and "summarize" not in v["input"]
    assert 'app_name != ""' in v["input"]
    assert v["multiple"] is True
    assert v["defaultValue"].endswith("*")
    # and the variable is wired into the data tile, before the aggregation
    q = dashboard["content"]["tiles"]["2"]["query"]
    assert "filter in(app_name, array($App))" in q
    assert q.index("filter in(app_name") < q.index("makeTimeseries")


def test_control_group_input_becomes_variables():
    panels = []
    attrs_extra = {"controlGroupInput": {"panelsJSON": json.dumps({
        "c1": {"type": "optionsListControl",
               "explicitInput": {"fieldName": "service.name", "title": "Service"}},
        "c2": {"type": "timeSliderControl", "explicitInput": {}},
    })}}
    export = _dashboard_export(panels, attrs_extra=attrs_extra)
    dashboard, _ = convert_dashboard(export.dashboards[0], export, MappingConfig())
    keys = [v["key"] for v in dashboard["content"]["variables"]]
    assert keys == ["Service"]


def test_variable_reference_not_flagged_as_custom_field():
    from e2d.dashboards.field_audit import audit_dashboard_fields
    dashboard = {"content": {"tiles": {"t": {"type": "data", "query":
        "fetch logs\n| filter in(loglevel, array($App))\n| summarize c = count()"}}}}
    audit = audit_dashboard_fields(dashboard)
    assert "App" not in audit["custom"]


# ---- maps + layout -------------------------------------------------------

def test_map_panel_gets_manual_placeholder():
    panels = [{"panelIndex": "1", "type": "map",
               "gridData": {"x": 0, "y": 0, "w": 24, "h": 15},
               "embeddableConfig": {"attributes": {"title": "Geo"}}}]
    export = _dashboard_export(panels)
    dashboard, report = convert_dashboard(export.dashboards[0], export, MappingConfig())
    tile = dashboard["content"]["tiles"]["1"]
    assert tile["type"] == "markdown" and "choroplethMap" in tile["content"]
    assert report.has_blocking or report.needs_review  # flagged, not silent


def test_layout_scales_48_to_24_grid():
    from e2d.dashboards.converter import _scale_layout
    assert _scale_layout({"x": 24, "y": 10, "w": 24, "h": 15}) == \
        {"x": 12, "y": 5, "w": 12, "h": 8}
    # clamped at the right edge
    out = _scale_layout({"x": 40, "y": 0, "w": 16, "h": 8})
    assert out["x"] + out["w"] <= 24


# ---- end-to-end smoke test ---------------------------------------------

FIX_DASH = (Path(__file__).resolve().parents[1] / "examples" / "fixtures" /
            "elastic-fixtures" / "06-dashboards" / "complex_dashboard.ndjson")


@pytest.mark.skipif(not FIX_DASH.exists(), reason="fixture dashboard not present")
def test_lens_panels_convert_to_dql_tiles():
    export = KibanaExport.load(str(FIX_DASH))
    dashboard, report = convert_dashboard(export.dashboards[0], export, MappingConfig())
    data_tiles = [t for t in dashboard["content"]["tiles"].values() if t["type"] == "data"]
    queries = "\n".join(t["query"] for t in data_tiles)
    # lnsXY percentile-over-time -> makeTimeseries + lineChart
    assert any(t["visualization"] == "lineChart" for t in data_tiles)
    assert "makeTimeseries" in queries and "percentile(transaction.duration.ms, 95)" in queries
    # lnsDatatable filtered count -> table with countIf
    assert any(t["visualization"] == "table" for t in data_tiles)
    assert "countIf(" in queries
    # no Lens placeholder markdown left behind
    assert "rebuild manually" not in str(dashboard)


@pytest.mark.skipif(not EXPORT.exists(), reason="sample export not present")
def test_convert_all_dashboards_smoke():
    export = KibanaExport.load(str(EXPORT))
    assert len(export.dashboards) > 0
    total_tiles = 0
    for d in export.dashboards:
        dashboard, _report = convert_dashboard(d, export, MappingConfig())
        # structure is valid and tiles<->layouts are consistent
        content = dashboard["content"]
        assert set(content["tiles"].keys()) == set(content["layouts"].keys())
        json.dumps(dashboard)  # must be serializable
        total_tiles += len(content["tiles"])
    assert total_tiles > 100  # the export has hundreds of panels


@pytest.mark.skipif(not EXPORT.exists(), reason="sample export not present")
def test_cli_writes_ui_importable_content_files(tmp_path):
    """Regression: written files must be the bare content document — the
    `{name, type, content}` Document-API wrapper imports as a BLANK dashboard
    when uploaded through the Dashboards app UI."""
    import argparse
    from e2d.dashboards.converter import convert_dashboard_file

    args = argparse.Namespace(input=str(EXPORT), output=str(tmp_path),
                              config=None, title="Financials", terraform=False,
                              verbose=False)
    assert convert_dashboard_file(args) == 0
    files = list(tmp_path.glob("*.json"))
    assert files
    doc = json.loads(files[0].read_text(encoding="utf-8"))
    assert "content" not in doc and "type" not in doc
    assert doc["tiles"] and set(doc["tiles"]) == set(doc["layouts"])
    assert "version" in doc and "variables" in doc


def test_safe_filename_keeps_title_readable():
    from e2d.dashboards.converter import _safe_filename
    # the Dashboards app names an uploaded dashboard after its file
    assert _safe_filename("[PFK] Financials") == "[PFK] Financials"
    assert _safe_filename("REST DP - Global Dashboard") == "REST DP - Global Dashboard"
    assert _safe_filename("a/b\\c:d*e?") == "a_b_c_d_e_"
    assert _safe_filename("  .. ") == "dashboard"
