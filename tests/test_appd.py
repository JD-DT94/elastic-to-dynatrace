"""AppDynamics -> Dynatrace conversion.

The tests that matter here are the ones guarding against output that deploys
cleanly and is wrong: unit rescaling, baseline rules that must NOT become static
detectors, and ALL-criteria rules that must not be split into independent
detectors (which would turn an AND into an OR).
"""

import json
from pathlib import Path

from e2d.appd import metrics as appd_metrics
from e2d.appd.dashboards import convert_appd_dashboard
from e2d.appd.health_rules import translate_health_rule, render_health_rule
from e2d.appd.inventory import build_waves, translate_inventory, render_onboarding_plan
from e2d.appd.policies import translate_policies
from e2d.dql.validate import lint_dql
from e2d.migrate import classify, run_migration


def _rule(conditions, aggregation="ANY", name="rule", **kw):
    doc = {"name": name, "enabled": True,
           "affects": {"affectedEntityType": "BUSINESS_TRANSACTION_PERFORMANCE"},
           "evalCriterias": {"criticalCriteria": {
               "conditionAggregationType": aggregation, "conditions": conditions}}}
    doc.update(kw)
    return doc


def _static(metric_path, value, comparator="GREATER_THAN", name="c"):
    return {"name": name,
            "evalDetail": {"evalDetailType": "SINGLE_METRIC", "metricPath": metric_path,
                           "metricEvalDetail": {"metricEvalDetailType": "SPECIFIC_TYPE",
                                                "compareCondition": comparator,
                                                "compareValue": value}}}


def _baseline(metric_path, sigmas=3, name="c"):
    return {"name": name,
            "evalDetail": {"evalDetailType": "SINGLE_METRIC", "metricPath": metric_path,
                           "metricEvalDetail": {"metricEvalDetailType": "BASELINE_TYPE",
                                                "baselineCondition": "GREATER_THAN_BASELINE",
                                                "baselineName": "All Data",
                                                "compareValue": sigmas,
                                                "baselineUnit": "STANDARD_DEVIATIONS"}}}


# --- metric mapping -------------------------------------------------------- #

def test_response_time_rescales_ms_to_microseconds():
    mapping, reason = appd_metrics.resolve(
        "Business Transaction Performance|Business Transactions|web|/cart|Average Response Time (ms)")
    assert reason is None
    assert mapping.dt_metric == "dt.service.request.response_time"
    # the whole point: 2000 ms is 2000000 us, not 2000
    assert appd_metrics.convert_threshold(2000, mapping) == "2000000"
    assert mapping.rescales


def test_rate_metrics_do_not_rescale():
    mapping, _ = appd_metrics.resolve("Overall Application Performance|Calls per Minute")
    assert mapping.dt_metric == "dt.service.request.count"
    assert appd_metrics.convert_threshold(500, mapping) == "500"
    assert not mapping.rescales


def test_unknown_metric_is_refused_not_guessed():
    mapping, reason = appd_metrics.resolve("Custom|Made Up|Widget Frobnication Rate")
    assert mapping is None
    assert "no known Dynatrace equivalent" in reason


def test_known_unmappable_metric_explains_the_alternative():
    mapping, reason = appd_metrics.resolve("Business Transaction Performance|x|Error Percentage")
    assert mapping is None
    # element-wise array arithmetic is the actual DQL answer, and it must be named
    assert "failure_count[]" in reason


def test_scope_is_extracted_from_the_metric_path():
    scope = appd_metrics.scope_from_path(
        "Business Transaction Performance|Business Transactions|checkout|/cart|Average Response Time (ms)")
    assert scope["tier"] == "checkout"
    assert scope["business_transaction"] == "/cart"


# --- health rules ---------------------------------------------------------- #

def test_static_threshold_becomes_a_detector_with_scaled_threshold():
    res = translate_health_rule(_rule([_static(
        "Business Transaction Performance|Business Transactions|checkout|/cart|"
        "Average Response Time (ms)", 2000)], name="Checkout slow"))
    assert res.classification == "converted"
    assert len(res.spec.detectors) == 1
    det = res.spec.detectors[0]
    assert det.threshold == "2000000"
    assert det.alert_condition == "ABOVE"
    assert det.metric_key == "dt.service.request.response_time"
    assert lint_dql(det.query) == []
    # the rescale must be stated, not silent
    assert any("2000000 microseconds" in n for n in res.report.format_deduped())


def test_baseline_rule_produces_no_detector():
    res = translate_health_rule(_rule([_baseline("Average Response Time (ms)")],
                                      name="Slower than normal"))
    assert res.classification == "covered-by-davis"
    # inventing a static threshold here is the failure mode being guarded
    assert res.spec.detectors == []
    notes = " ".join(res.report.format_deduped())
    assert "no static threshold to carry across" in notes
    assert "Davis" in notes


def test_all_criteria_with_several_conditions_is_manual_not_split():
    res = translate_health_rule(_rule(
        [_static("Average Response Time (ms)", 1000, name="slow"),
         _static("Errors per Minute", 10, name="errors")],
        aggregation="ALL", name="Slow and erroring"))
    # splitting an AND into two independent detectors would alert far too often
    assert res.spec.detectors == []
    assert res.classification == "manual"
    assert res.report.has_blocking
    assert any("turn the AND into an OR" in n for n in res.report.format_deduped())


def test_any_criteria_with_several_conditions_becomes_several_detectors():
    res = translate_health_rule(_rule(
        [_static("Average Response Time (ms)", 1000, name="slow"),
         _static("Errors per Minute", 10, name="errors")],
        aggregation="ANY", name="Slow or erroring"))
    assert len(res.spec.detectors) == 2
    assert {d.threshold for d in res.spec.detectors} == {"1000000", "10"}


def test_unmappable_metric_makes_the_rule_manual():
    res = translate_health_rule(_rule([_static("Custom|Nonsense Metric", 5)]))
    assert res.spec.detectors == []
    assert res.report.has_blocking
    assert res.classification == "manual"


def test_detector_is_not_silently_entity_scoped():
    res = translate_health_rule(_rule([_static(
        "Business Transaction Performance|Business Transactions|checkout|/cart|"
        "Average Response Time (ms)", 2000)]))
    det = res.spec.detectors[0]
    # no invented filter — an entity filter guessed from an AppD tier name would
    # match nothing and the detector would never fire
    assert "filter" not in det.query
    notes = " ".join(res.report.format_deduped())
    assert "NOT scoped" in notes and "checkout" in notes


def test_metric_expression_condition_is_manual():
    cond = {"name": "expr", "evalDetail": {"evalDetailType": "METRIC_EXPRESSION",
                                           "metricExpression": "A/B*100"}}
    res = translate_health_rule(_rule([cond]))
    assert res.spec.detectors == []
    assert any("element-wise" in n for n in res.report.format_deduped())


def test_health_rule_renders_a_readable_note():
    res = translate_health_rule(_rule([_baseline("Average Response Time (ms)")], name="Baseline"))
    md = render_health_rule(res)
    assert "# Baseline" in md
    assert "No migration needed" in md


def test_non_always_schedule_is_flagged():
    res = translate_health_rule(_rule([_static("Average Response Time (ms)", 1000)],
                                      scheduleName="Business Hours"))
    assert any("maintenance window" in n for n in res.report.format_deduped())


# --- dashboards ------------------------------------------------------------ #

def _dash(widgets, **kw):
    doc = {"name": "D", "width": 1200, "widgetTemplates": widgets}
    doc.update(kw)
    return doc


def test_dashboard_widget_becomes_a_dql_tile():
    content, report, title = convert_appd_dashboard(_dash([
        {"widgetType": "GraphWidget", "title": "RT", "x": 0, "y": 0, "width": 600, "height": 240,
         "dataSeriesTemplates": [{"metricMatchCriteriaTemplate": {"metricExpressionTemplate": {
             "metricPath": "Overall Application Performance|web|Average Response Time (ms)"}}}]}]))
    assert title == "D"
    tile = content["tiles"]["0"]
    assert tile["type"] == "data"
    assert tile["visualization"] == "lineChart"
    assert "dt.service.request.response_time" in tile["query"]
    assert lint_dql(tile["query"]) == []
    # 600px of a 1200px canvas is half the 24-column grid
    assert content["layouts"]["0"]["w"] == 12


def test_metric_path_is_found_at_any_depth():
    deep = {"widgetType": "GraphWidget", "title": "deep", "width": 600,
            "a": {"b": [{"c": {"metricPath": "Overall Application Performance|Calls per Minute"}}]}}
    content, _, _ = convert_appd_dashboard(_dash([deep]))
    assert "dt.service.request.count" in content["tiles"]["0"]["query"]


def test_text_widget_becomes_markdown_without_html():
    content, _, _ = convert_appd_dashboard(_dash([
        {"widgetType": "TextWidget", "text": "<b>Owned</b> by payments", "width": 1200}]))
    tile = content["tiles"]["0"]
    assert tile["type"] == "markdown"
    assert tile["content"] == "Owned by payments"


def test_widget_with_no_dynatrace_equivalent_is_named_not_dropped():
    content, report, _ = convert_appd_dashboard(_dash([
        {"widgetType": "HealthListWidget", "title": "Health", "width": 600}]))
    assert content["tiles"]["0"]["type"] == "markdown"
    assert "Not migrated automatically" in content["tiles"]["0"]["content"]
    assert report.has_blocking


def test_unmappable_metric_tile_lists_the_paths():
    content, report, _ = convert_appd_dashboard(_dash([
        {"widgetType": "GraphWidget", "title": "Odd", "width": 600,
         "dataSeriesTemplates": [{"metricMatchCriteriaTemplate": {
             "metricExpressionTemplate": {"metricPath": "Custom|Nothing Like This"}}}]}]))
    assert content["tiles"]["0"]["type"] == "markdown"
    assert "Custom|Nothing Like This" in content["tiles"]["0"]["content"]
    assert report.has_blocking


def test_dashboard_export_without_widgets_is_manual():
    _, report, _ = convert_appd_dashboard({"name": "empty"})
    assert report.has_blocking
    assert any("No widgets found" in n for n in report.format_deduped())


# --- inventory ------------------------------------------------------------- #

NODES = [
    {"id": 11, "name": "n-a", "tierName": "web", "applicationName": "Checkout",
     "machineName": "host01", "appAgentVersion": "23.1"},
    {"id": 12, "name": "n-b", "tierName": "web", "applicationName": "Checkout",
     "machineName": "host01", "appAgentVersion": "23.1"},
    {"id": 13, "name": "n-c", "tierName": "api", "applicationName": "Checkout",
     "machineName": "host02", "appAgentVersion": "23.1"},
    {"id": 14, "name": "n-d", "tierName": "core", "applicationName": "Booking",
     "machineName": "host03", "appAgentVersion": "23.1"},
]


def test_nodes_dedupe_to_hosts():
    inv = translate_inventory(json.dumps(NODES)).inventory
    # 4 AppD nodes, but only 3 OneAgent installs — the number the plan is sized on
    assert inv.node_count == 4
    assert inv.host_count == 3
    assert inv.tier_count == 3


def test_waves_cover_every_host_smallest_first():
    inv = translate_inventory(json.dumps(NODES)).inventory
    waves = build_waves(inv, wave_size=2)
    covered = sum(w["hosts"] for w in waves)
    assert covered >= inv.host_count
    first_apps = [a["application"] for a in waves[0]["applications"]]
    assert first_apps[0] == "Booking"      # 1 host, goes first
    assert waves[0]["applications"][0]["host_group"] == "BOOKING"


def test_plan_states_the_host_versus_node_distinction():
    inv = translate_inventory(json.dumps(NODES)).inventory
    md = render_onboarding_plan(inv, build_waves(inv))
    assert "3 distinct host(s)" in md
    assert "the rollout is 3 installs, not 4" in md
    assert "dynatrace.oneagent" in md
    assert "cannot be backfilled" in md.lower() or "no backfill" in md.lower()


def test_inventory_without_machine_names_warns():
    res = translate_inventory(json.dumps(
        [{"id": 1, "name": "n", "tierName": "web", "appAgentVersion": "23.1"}]))
    assert any("machineName" in n for n in res.report.format_deduped())


# --- policies and actions -------------------------------------------------- #

def test_diagnostic_actions_need_no_equivalent():
    res = translate_policies(json.dumps([
        {"actionType": "THREAD_DUMP", "name": "threads"},
        {"actionType": "DIAGNOSTIC_SESSION", "name": "diag"}]))
    assert len(res.always_on) == 2
    assert any("captures method-level detail and snapshots continuously"
               in n for n in res.report.format_deduped())


def test_http_action_flags_credential_without_copying_it():
    res = translate_policies(json.dumps([
        {"actionType": "HTTP_REQUEST", "name": "hook", "credentialName": "slack-token"}]))
    assert res.actions[0].kind == "webhook"
    notes = " ".join(res.report.format_deduped())
    assert "NOT copied" in notes
    assert "slack-token" not in notes      # the value must never reach the output


# --- classification and end-to-end ----------------------------------------- #

def test_classify_recognises_each_appd_export(tmp_path):
    cases = {
        "hr.json": _rule([_static("Average Response Time (ms)", 1)]),
        "dash.json": _dash([{"widgetType": "GraphWidget", "width": 100}]),
        "nodes.json": NODES,
        "actions.json": [{"actionType": "EMAIL", "name": "e", "toAddress": ["a@b.c"]}],
    }
    expected = {"hr.json": "appd_health_rule", "dash.json": "appd_dashboard",
                "nodes.json": "appd_inventory", "actions.json": "appd_policies"}
    for fname, doc in cases.items():
        p = tmp_path / fname
        text = json.dumps(doc)
        p.write_text(text, encoding="utf-8")
        assert classify(p, text) == expected[fname], fname


def test_appd_probes_do_not_capture_elastic_artifacts(tmp_path):
    """The two products must never claim each other's files."""
    elastic = {
        "watcher.json": ({"trigger": {"schedule": {"interval": "1m"}},
                          "input": {"search": {"request": {"indices": ["logs-*"]}}},
                          "condition": {"compare": {}}}, "watcher"),
        "rule.json": ({"rule_type_id": ".index-threshold", "name": "r", "params": {}},
                      "alerting_rule"),
        "dsl.json": ({"query": {"bool": {"must": []}}}, "querydsl"),
        "ingest.json": ({"processors": [{"grok": {}}]}, "ingest"),
        "ilm.json": ({"policy": {"phases": {"delete": {"min_age": "30d"}}}}, "ilm_policy"),
    }
    for fname, (doc, kind) in elastic.items():
        p = tmp_path / fname
        text = json.dumps(doc)
        p.write_text(text, encoding="utf-8")
        assert classify(p, text) == kind, fname


def test_migrate_end_to_end_tags_products_and_sizes_the_rollout(tmp_path):
    indir = tmp_path / "in"
    indir.mkdir()
    (indir / "health_rules.json").write_text(json.dumps([
        _rule([_static("Average Response Time (ms)", 2000)], name="Slow"),
        _rule([_baseline("Average Response Time (ms)")], name="Baseline"),
    ]), encoding="utf-8")
    (indir / "nodes.json").write_text(json.dumps(NODES), encoding="utf-8")
    (indir / "actions.json").write_text(json.dumps(
        [{"actionType": "EMAIL", "name": "ops", "toAddress": ["ops@example.com"]}]),
        encoding="utf-8")
    out = tmp_path / "out"
    s = run_migration(str(indir), str(out))

    assert s.products == ["appdynamics"]
    assert all(it.product == "appdynamics" for it in s.items)
    assert s.appd_hosts == 3 and s.appd_nodes == 4
    assert s.appd_davis_covered == 1

    assert (out / "onboarding" / "ONBOARDING-PLAN.md").exists()
    assert (out / "onboarding" / "waves.json").exists()
    assert (out / "notifications" / "actions.notifications.md").exists()

    body = json.loads((out / "alerts" / "health_rules.detectors.json").read_text(encoding="utf-8"))
    assert len(body) == 1                     # only the static rule; the baseline one is covered
    inputs = {i["key"]: i["value"] for i in body[0]["value"]["analyzer"]["input"]}
    assert inputs["threshold"] == "2000000"

    report = (out / "MIGRATION_REPORT.md").read_text(encoding="utf-8")
    assert "AppDynamics → Dynatrace migration report" in report
    assert "AppDynamics rollout sizing" in report
    assert "1 health rule(s) need no migration" in report
    # OneAgent must be sequenced before anything that reads its data
    assert report.index("Deploy OneAgent") < report.index("Enable alerting last")


def test_mixed_estate_reports_both_products(tmp_path):
    indir = tmp_path / "in"
    indir.mkdir()
    (indir / "nodes.json").write_text(json.dumps(NODES), encoding="utf-8")
    (indir / "pipeline.conf").write_text(
        'input { beats { port => 5044 } }\n'
        'filter { mutate { add_field => { "env" => "prod" } } }\n'
        'output { elasticsearch { hosts => ["es:9200"] } }\n', encoding="utf-8")
    s = run_migration(str(indir), str(tmp_path / "out"))
    assert set(s.products) == {"appdynamics", "elastic"}
    report = (tmp_path / "out" / "MIGRATION_REPORT.md").read_text(encoding="utf-8")
    assert "AppDynamics" in report and "Elastic" in report
