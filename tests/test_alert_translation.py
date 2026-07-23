"""Track E: Elastic Watchers / Kibana alerting rules -> DQL + alert plan."""

import json
from pathlib import Path

import pytest

from e2d.alerts import translate_alert, render_alert
from e2d.alerts.model import TARGET_ANOMALY_DETECTOR, TARGET_WORKFLOW
from e2d.alerts.tf import render_detectors_tf
from e2d.migrate import classify
from e2d.dql.validate import lint_dql

FIX = Path(__file__).resolve().parents[1] / "examples" / "fixtures" / "elastic-fixtures"
WATCH = FIX / "01-watchers"
RULES = FIX / "02-kibana-alerting-rules"

# The fixture exports contain company data and are deliberately not committed;
# every test here reads them, so the module skips as a whole where absent (CI).
pytestmark = pytest.mark.skipif(not FIX.exists(), reason="company-data fixtures not present")


def _spec(path):
    return translate_alert(path.read_text(encoding="utf-8"))


# --- classification -------------------------------------------------------- #

def test_classify_watcher_and_rule():
    assert classify(WATCH / "simple_error_threshold.json",
                    (WATCH / "simple_error_threshold.json").read_text(encoding="utf-8")) == "watcher"
    assert classify(RULES / "simple_log_threshold_rule.json",
                    (RULES / "simple_log_threshold_rule.json").read_text(encoding="utf-8")) == "alerting_rule"


# --- watchers -------------------------------------------------------------- #

def test_simple_watcher_count_threshold():
    res = _spec(WATCH / "simple_error_threshold.json")
    s = res.spec
    assert s.dql.startswith("fetch logs")
    assert 'filter loglevel == "ERROR"' in s.dql
    assert s.dql.strip().endswith("summarize count()")
    assert any(t.subject == "count" and t.comparator == ">" and t.value == "50" for t in s.thresholds)
    assert s.target == TARGET_ANOMALY_DETECTOR
    assert lint_dql(s.dql) == []   # emitted DQL is clean


def test_medium_watcher_threshold_from_painless():
    s = _spec(WATCH / "medium_latency_metric.json").spec
    # threshold pulled out of the Painless anyMatch condition
    assert any(t.subject == "avg_latency_ms" and t.comparator == ">" and t.value == "800"
               for t in s.thresholds)
    assert "service.name" in s.group_by
    assert s.target == TARGET_WORKFLOW   # has transform + multiple actions


def test_complex_watcher_chain_secrets_and_quantifier():
    res = _spec(WATCH / "complex_multiservice_array.json")
    s, notes = res.spec, [w.format() for w in res.report.warnings]
    # the search leg of the chain is extracted into DQL
    assert "host.name" in s.dql and "summarize" in s.dql
    # webhook credentials are flagged, never inlined
    assert any(a.secret for a in s.actions if a.kind == "webhook")
    # array_compare quantifier surfaced
    assert any("quantifier" in n for n in notes)
    assert s.target == TARGET_WORKFLOW
    assert lint_dql(s.dql) == []


# --- kibana rules ---------------------------------------------------------- #

def test_log_count_rule():
    s = _spec(RULES / "simple_log_threshold_rule.json").spec
    assert s.dql.startswith("fetch logs")
    assert "summarize count(), by: {service.name}" in s.dql
    assert any(t.subject == "count" for t in s.thresholds)
    assert s.target == TARGET_ANOMALY_DETECTOR
    assert lint_dql(s.dql) == []


def test_metric_threshold_rule_with_warning():
    s = _spec(RULES / "medium_metric_threshold_rule.json").spec
    assert s.dql.startswith("timeseries ")
    assert "avg(system.cpu.total.norm.pct)" in s.dql
    # filterQuery (KQL) translated into the timeseries filter:
    assert "filter:" in s.dql and 'service.environment == "production"' in s.dql
    # both critical and warning thresholds captured
    sev = {t.severity for t in s.thresholds}
    assert "critical" in sev and "warning" in sev
    assert s.target == TARGET_ANOMALY_DETECTOR


# --- deployable anomaly detector Terraform --------------------------------- #

def test_metric_rule_emits_anomaly_detector_tf():
    s = _spec(RULES / "medium_metric_threshold_rule.json").spec
    # one detector per threshold: cpu critical + cpu warning + mem critical
    assert len(s.detectors) == 3
    d = s.detectors[0]
    assert d.alert_condition == "ABOVE" and d.metric_key == "system.cpu.total.norm.pct"
    assert "interval: 1m" in d.query and d.query.startswith("timeseries ")
    tf = render_detectors_tf(s)
    assert tf.count('resource "dynatrace_davis_anomaly_detectors"') == 3
    assert 'name = "dt.statistics.ui.anomaly_detection.StaticThresholdAnomalyDetectionAnalyzer"' in tf
    assert 'key   = "threshold"' in tf and 'value = "0.85"' in tf


def test_count_alert_detector_is_per_minute_series():
    s = _spec(WATCH / "simple_error_threshold.json").spec
    assert len(s.detectors) == 1
    d = s.detectors[0]
    assert "makeTimeseries count = count(), interval: 1m" in d.query
    assert d.alert_condition == "ABOVE" and d.threshold == "50"
    assert lint_dql(d.query) == []   # the detector query is valid DQL


def test_missing_metric_check_and_openpipeline_creation():
    from e2d.alerts.metrics import missing_metrics, render_metric_creation, is_dynatrace_metric
    res = _spec(RULES / "medium_metric_threshold_rule.json")
    s = res.spec
    assert not is_dynatrace_metric("system.cpu.total.norm.pct")
    assert is_dynatrace_metric("dt.host.cpu.usage")
    miss = {m for m, _ in missing_metrics(s)}
    assert "system.cpu.total.norm.pct" in miss and "system.memory.actual.used.pct" in miss
    # the existence check is surfaced as a warning
    assert any("not a Dynatrace metric" in w.format() for w in res.report.warnings)
    # and a value_metric OpenPipeline processor is offered to create it
    md = render_metric_creation(s)
    assert 'type        = "valueMetric"' in md and "metric_key" in md


def test_dynamic_threshold_detector_applies_disabled():
    # the complex watcher's threshold is a mustache template -> non-numeric.
    # The TF must stay apply-able: numeric 0 placeholder + enabled = false.
    s = _spec(WATCH / "complex_multiservice_array.json").spec
    tf = render_detectors_tf(s)
    # the threshold field itself must be numeric (the dynamic text may remain in the title)
    assert 'value = "<dynamic' not in tf         # no non-numeric *threshold* value
    assert 'value = "0"' in tf                   # placeholder threshold
    assert "enabled     = false" in tf           # shipped disabled
    assert "set a real threshold" in tf          # tells the user why


def test_numeric_threshold_detector_enabled():
    s = _spec(RULES / "simple_log_threshold_rule.json").spec
    tf = render_detectors_tf(s)
    assert "enabled     = true" in tf and 'value = "25"' in tf


def test_complex_watcher_workflow_tf():
    from e2d.alerts.tf import render_workflow_tf, needs_workflow
    s = _spec(WATCH / "complex_multiservice_array.json").spec
    assert needs_workflow(s)
    tf = render_workflow_tf(s)
    assert 'resource "dynatrace_automation_workflow"' in tf
    assert "davis_event" in tf                       # triggered by the detector's event
    assert tf.count("task {") == len(s.actions)      # one task per action
    assert "REPLACE_WITH_DYNATRACE_CREDENTIAL_ID" in tf   # webhook secret referenced, not inlined
    assert "terraform {" not in tf                   # provider block lives in main.tf


def test_index_threshold_rule():
    # groupBy:"top" + termField (NOT a list); aggType(aggField) over a window
    doc = {"rule_type_id": ".index-threshold", "name": "r", "schedule": {"interval": "1m"},
           "params": {"aggType": "avg", "aggField": "sheet.version", "thresholdComparator": ">",
                      "threshold": [1000], "timeWindowSize": 5, "timeWindowUnit": "m",
                      "groupBy": "top", "termField": "name.keyword"}}
    s = translate_alert(doc).spec
    assert "makeTimeseries value = avg(sheet.version), interval: 1m" in s.dql
    assert s.group_by == ["name"]                       # "top"+termField, not split chars
    assert s.detectors[0].threshold == "1000" and s.detectors[0].alert_condition == "ABOVE"
    assert lint_dql(s.detectors[0].query) == []


def test_es_query_rule():
    doc = {"rule_type_id": ".es-query", "name": "r", "schedule": {"interval": "1m"},
           "params": {"searchType": "esQuery", "esQuery": '{"query":{"match":{"loglevel":"ERROR"}}}',
                      "index": ["logs"], "timeField": "@timestamp", "threshold": [100],
                      "thresholdComparator": ">", "timeWindowSize": 5, "timeWindowUnit": "m"}}
    s = translate_alert(doc).spec
    assert s.dql.startswith("fetch logs") and "summarize count()" in s.dql
    assert "makeTimeseries count = count(), interval: 1m" in s.detectors[0].query
    assert "| limit" not in s.dql                       # record-view limit stripped for a count rule
    assert s.detectors[0].threshold == "100"


def test_below_comparator_maps_to_below_condition():
    doc = {"rule_type_id": "metrics.alert.threshold", "name": "low throughput",
           "schedule": {"interval": "1m"},
           "params": {"criteria": [{"aggType": "avg", "metric": "throughput",
                                    "comparator": "<", "threshold": [10],
                                    "timeSize": 5, "timeUnit": "m"}]}}
    s = translate_alert(doc).spec
    assert s.detectors[0].alert_condition == "BELOW"


# --- rendering + end-to-end ------------------------------------------------ #

def test_render_plan_has_sections():
    plan = render_alert(_spec(WATCH / "simple_error_threshold.json").spec)
    for heading in ("Query it evaluates", "Firing logic", "How to build it in Dynatrace"):
        assert heading in plan


def test_migrate_includes_alerts(tmp_path):
    from e2d.migrate import run_migration
    summary = run_migration(str(FIX), str(tmp_path))
    assert any(it.category == "alert" for it in summary.items)
    assert (tmp_path / "alerts").exists()
    # a watcher with credentials surfaces a secret
    assert summary.secrets
