"""Offline DQL linter rules."""

from e2d.dql.validate import lint_dql, lint_into_report
from e2d.report import Report, Severity


def codes(dql):
    return {f.code for f in lint_dql(dql)}


# --- clean DQL must not be flagged (no false positives) -------------------- #

def test_clean_timeseries_ratio_is_silent():
    dql = ('fetch logs, from:now()-24h\n'
           '| makeTimeseries {total = count(), errors = countIf(loglevel == "ERROR")}, '
           'interval: 30m, by: {service.name}\n'
           '| fieldsAdd error_rate = errors[] / total[]')
    assert lint_dql(dql) == []


def test_clean_summarize_is_silent():
    dql = 'fetch logs\n| filter loglevel == "ERROR"\n| summarize count(), by: {service.name}'
    assert lint_dql(dql) == []


def test_clean_static_in_braces_is_silent():
    assert codes('fetch logs | filter in(host.name, {"a", "b"})') == set()


# --- each rule fires on its bad pattern ------------------------------------ #

def test_array_arithmetic_flagged():
    dql = ('fetch logs\n| makeTimeseries {total = count(), errors = countIf(loglevel == "ERROR")}, '
           'interval: 30m\n| fieldsAdd error_rate = if(total == 0, 0, else: errors / total)')
    assert "array-arithmetic" in codes(dql)


def test_deprecated_entity_field_flagged():
    assert "deprecated-entity-field" in codes("fetch logs | summarize count(), by: {dt.entity.service.name}")


def test_static_list_brackets_flagged():
    assert "static-list-brackets" in codes('fetch logs | filter in(host.name, ["a", "b"])')


def test_by_without_braces_flagged():
    assert "by-without-braces" in codes("fetch logs | summarize count(), by: service.name")


def test_fetch_metric_flagged_manual():
    fs = lint_dql("fetch dt.metric | fields x")
    assert any(f.code == "fetch-metric" and f.severity is Severity.MANUAL for f in fs)


def test_percentile_needs_rollup_flagged():
    assert "percentile-needs-rollup" in codes("timeseries p95 = percentile(my.metric, 95), interval: 1h")
    # with rollup present, it is silent
    assert "percentile-needs-rollup" not in codes(
        "timeseries p95 = percentile(my.metric, 95), rollup: avg, interval: 1h")


def test_percentile_in_maketimeseries_not_flagged():
    # makeTimeseries percentiles raw events and has no rollup: — must NOT flag
    dql = ('fetch logs\n| makeTimeseries {p95 = percentile(transaction.duration.ms, 95)}, '
           'interval: 1m, by: {service.name}')
    assert "percentile-needs-rollup" not in codes(dql)


def test_wrong_function_names_flagged():
    assert "wrong-function-name" in codes("fetch logs | fieldsAdd x = toLowercase(content)")
    assert "wrong-function-name" in codes("fetch logs | fieldsAdd n = length(content)")


def test_block_comment_flagged_manual():
    fs = lint_dql("fetch logs | fieldsAdd x = /* TODO */ 0")
    assert any(f.code == "block-comment" and f.severity is Severity.MANUAL for f in fs)
    # // line comments are fine
    assert "block-comment" not in codes("fetch logs // a note\n| limit 1")


def test_assignment_in_filter_flagged():
    assert "assignment-in-filter" in codes('fetch logs | filter host.name = "A"')
    # '==' is fine
    assert "assignment-in-filter" not in codes('fetch logs | filter host.name == "A"')


# --- folding into a Report ------------------------------------------------- #

def test_lint_into_report_appends_warnings():
    report = Report()
    findings = lint_into_report("fetch logs | summarize count(), by: service.name", report)
    assert findings and report.needs_review
    assert any("DQL:by-without-braces" in w.message for w in report.warnings)
