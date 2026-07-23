"""Track A: Query DSL JSON + Lucene -> DQL, exercised against the fixtures and
targeted unit cases."""

import json
from pathlib import Path

import pytest

from e2d.config import MappingConfig
from e2d.report import Report
from e2d.core.lucene import translate_lucene
from e2d.core.filter_ir import emit_filter, split_timeframe
from e2d.core.query_dsl import convert_query_dsl

FIX = Path(__file__).resolve().parents[1] / "examples" / "fixtures" / "elastic-fixtures" / "05-queries"

# Fixture exports are company data and not committed; guards the few tests that read them.
needs_fixtures = pytest.mark.skipif(not FIX.exists(), reason="company-data fixtures not present")


def lucene(q, do="logs"):
    node = translate_lucene(q, MappingConfig(), do, Report())
    return emit_filter(node, MappingConfig(), do, Report())


# ---- Lucene ----------------------------------------------------------------

def test_lucene_field_group_or_to_in():
    assert lucene("log.level:(ERROR OR FATAL)") == 'in(loglevel, {"ERROR", "FATAL"})'


def test_lucene_inclusive_range():
    assert lucene("status_code:[500 TO 599]") == "status_code >= 500 and status_code <= 599"


def test_lucene_open_range():
    assert lucene("response_time_ms:>2000") == "response_time_ms > 2000"


def test_lucene_regex():
    assert lucene("message:/.*deadlock.*/") == 'matchesRegex(content, ".*deadlock.*")'


def test_lucene_wildcard():
    assert lucene("service.name:sandpiper.*") == 'matchesValue(service.name, "sandpiper.*")'


def test_lucene_exclude_prefix():
    out = lucene(r"+opco:direct-assurance -url.path:\/health")
    assert 'opco == "direct-assurance"' in out
    assert 'not (url.path == "/health")' in out


def test_lucene_time_range_lifted():
    node = translate_lucene("@timestamp:[now-1h TO now]", MappingConfig(), "logs", Report())
    tf, remaining = split_timeframe(node)
    assert tf == "from:now()-1h, to:now()"
    assert remaining is None


# ---- Query DSL -------------------------------------------------------------

def dsl(doc, do="logs"):
    return convert_query_dsl(doc, MappingConfig(), do, Report())[0]


@needs_fixtures
def test_dsl_bool_flatten_and_timeframe():
    doc = json.loads((FIX / "simple_bool_range.json").read_text(encoding="utf-8"))
    out = dsl(doc)
    assert "from:now()-15m" in out
    assert 'loglevel == "ERROR"' in out
    assert 'opco == "direct-assurance"' in out
    assert "sort timestamp desc" in out


def test_dsl_terms_to_in():
    out = dsl({"query": {"terms": {"host.name": ["a", "b"]}}})
    assert 'in(host.name, {"a", "b"})' in out


@needs_fixtures
def test_dsl_nested_aggs_to_maketimeseries():
    doc = json.loads((FIX / "medium_histogram_terms_avg.json").read_text(encoding="utf-8"))
    out = dsl(doc)
    assert "makeTimeseries" in out
    assert "interval: 30m" in out
    assert 'errors = countIf(loglevel == "ERROR")' in out
    assert "by: {service.name}" in out
    # bucket_script ratio after makeTimeseries -> element-wise array division
    # (metrics are arrays here, so `errors / total` would be invalid DQL)
    assert "fieldsAdd error_rate = errors[] / total[]" in out


def test_dsl_bucket_script_ratio_scalar():
    # same ratio WITHOUT a date_histogram -> summarize (scalars), so the
    # divide-by-zero guard renders as a scalar if(), not element-wise arrays.
    doc = {"size": 0, "aggs": {"by_svc": {"terms": {"field": "service.name"},
        "aggs": {
            "total": {"value_count": {"field": "log.level"}},
            "errors": {"filter": {"term": {"log.level": "ERROR"}}},
            "error_rate": {"bucket_script": {
                "buckets_path": {"e": "errors>_count", "t": "total"},
                "script": "params.t == 0 ? 0 : (double)params.e / params.t"}},
        }}}}
    out = dsl(doc)
    assert "summarize" in out and "makeTimeseries" not in out
    assert "fieldsAdd error_rate = if(total == 0, 0, else: errors / total)" in out
    assert "[]" not in out  # no array access in the scalar context


def _hist_with(pipe_aggs):
    inner = {"c": {"value_count": {"field": "x"}}}
    inner.update(pipe_aggs)
    return {"size": 0, "aggs": {"h": {"date_histogram": {"field": "@timestamp",
            "fixed_interval": "5m"}, "aggs": inner}}}


def test_pipeline_derivative_to_arraydiff():
    out = dsl(_hist_with({"rate": {"derivative": {"buckets_path": "c"}}}))
    assert "fieldsAdd rate = arrayDiff(c)" in out
    assert "/*" not in out  # no block comment


def test_pipeline_cumulative_and_moving():
    out = dsl(_hist_with({"run": {"cumulative_sum": {"buckets_path": "c"}}}))
    assert "fieldsAdd run = arrayCumulativeSum(c)" in out
    out2 = dsl(_hist_with({"mv": {"moving_fn": {"buckets_path": "c", "window": 7,
                                                "script": "MovingFunctions.unweightedAvg(values)"}}}))
    assert "fieldsAdd mv = arrayMovingAvg(c, 7)" in out2


def test_pipeline_sibling_bucket_reducers():
    out = dsl(_hist_with({"peak": {"max_bucket": {"buckets_path": "h>c"}}}))
    assert "fieldsAdd peak = arrayMax(c)" in out


def test_pipeline_derivative_without_histogram_is_dropped():
    # no date_histogram -> can't compute a series delta; column dropped, flagged
    rep = Report()
    doc = {"size": 0, "aggs": {"t": {"terms": {"field": "service.name"}, "aggs": {
        "c": {"value_count": {"field": "x"}},
        "rate": {"derivative": {"buckets_path": "c"}}}}}}
    out = convert_query_dsl(doc, MappingConfig(), "logs", rep)[0]
    assert "arrayDiff" not in out and "rate =" not in out
    assert any("derivative" in w.format() and "WARN" in w.format() for w in rep.warnings)


def test_pipeline_unsupported_is_manual_not_broken():
    out = dsl(_hist_with({"nz": {"normalize": {"buckets_path": "c", "method": "percent_of_sum"}}}))
    assert "/*" not in out and "nz =" not in out  # no broken output


def test_scripted_metric_distinct_count_recognised():
    doc = {"size": 0, "aggs": {"t": {"terms": {"field": "service.name"}, "aggs": {
        "users": {"scripted_metric": {
            "init_script": "state.ids = new HashSet()",
            "map_script": "state.ids.add(doc['user.id'].value)",
            "combine_script": "return state.ids",
            "reduce_script": "Set all = new HashSet(); for (s in states) { all.addAll(s) } return all.size()"}}}}}}
    out = dsl(doc)
    assert "users = countDistinct(user.id)" in out


def test_dsl_percentiles_fan_out():
    doc = {"size": 0, "aggs": {"lat": {"percentiles": {"field": "d", "percents": [50, 95, 99]}}}}
    out = dsl(doc)
    assert "percentile(d, 50)" in out and "percentile(d, 95)" in out and "percentile(d, 99)" in out


@needs_fixtures
def test_dsl_complex_flags_manual():
    doc = json.loads((FIX / "complex_nested_aggs_painless.json").read_text(encoding="utf-8"))
    report = Report()
    convert_query_dsl(doc, MappingConfig(), "logs", report)
    msgs = report.format()
    assert "scripted_metric" in msgs   # flagged MANUAL
    assert "latency_bucket" not in msgs or "if(" in convert_query_dsl(
        doc, MappingConfig(), "logs", Report())[0]
