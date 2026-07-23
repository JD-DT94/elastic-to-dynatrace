"""Behavioural tests for the ES|QL -> DQL translator.

These assert on the shape of the generated DQL (commands, operators, function
names) rather than exact whitespace, so the translator can evolve formatting
without churn.
"""

from e2d import translate_esql
from e2d.config import MappingConfig


def t(query, config=None):
    return translate_esql(query, config or MappingConfig())


def test_from_maps_index_to_data_object():
    r = t("FROM logs-app-prod-*")
    assert r.dql.startswith("fetch logs")


def test_from_traces_maps_to_spans():
    r = t("FROM traces-apm-2024")
    assert r.dql.startswith("fetch spans")


def test_where_equality_and_field_mapping():
    # log.level -> loglevel, message -> content (logs data object)
    r = t('FROM logs-* | WHERE log.level == "ERROR"')
    assert "filter loglevel == \"ERROR\"" in r.dql


def test_where_in_uses_curly_braces():
    r = t('FROM logs-* | WHERE service.name IN ("a", "b")')
    assert 'in(' in r.dql and '{"a", "b"}' in r.dql
    assert "[" not in r.dql  # static lists must not use []


def test_is_not_null():
    r = t("FROM logs-* | WHERE host.name IS NOT NULL")
    assert "isNotNull(host.name)" in r.dql


def test_stats_summarize_with_by():
    r = t("FROM logs-* | STATS c = COUNT(*) BY host.name")
    assert "summarize c = count()" in r.dql
    assert "by: {host.name}" in r.dql


def test_count_distinct_maps():
    r = t("FROM logs-* | STATS d = COUNT_DISTINCT(host.name)")
    assert "countDistinct(host.name)" in r.dql


def test_stats_bucket_routes_to_maketimeseries():
    r = t("FROM logs-* | STATS c = COUNT(*) BY bucket(@timestamp, 5 minutes)")
    assert "makeTimeseries" in r.dql
    assert "interval: 5m" in r.dql


def test_eval_becomes_fieldsadd():
    r = t('FROM logs-* | EVAL x = 1 + 2')
    assert "fieldsAdd x = 1 + 2" in r.dql


def test_case_becomes_nested_if():
    r = t('FROM logs-* | EVAL sev = CASE(log.level == "ERROR", "high", "low")')
    assert "if(loglevel == \"ERROR\", \"high\", else: \"low\")" in r.dql


def test_sort_and_limit():
    r = t("FROM logs-* | SORT host.name DESC | LIMIT 10")
    assert "sort host.name desc" in r.dql
    assert "limit 10" in r.dql


def test_keep_becomes_fields():
    r = t("FROM logs-* | KEEP host.name, log.level")
    assert "fields host.name, loglevel" in r.dql


def test_rename_as():
    r = t("FROM logs-* | RENAME host.name AS h")
    assert "fieldsRename h = host.name" in r.dql


def test_length_function_maps_to_stringlength():
    r = t('FROM logs-* | EVAL n = LENGTH(message)')
    assert "stringLength(content)" in r.dql


def test_cast_operator():
    r = t('FROM logs-* | EVAL n = some_field::long')
    assert "toLong(some_field)" in r.dql


def test_unsupported_command_flagged():
    r = t("FROM logs-* | LOOKUP foo")
    assert r.report.has_blocking
    assert "TODO" in r.dql


def test_like_wildcard_conversion():
    r = t('FROM logs-* | WHERE message LIKE "*timeout*"')
    assert "like(content, \"%timeout%\")" in r.dql


def test_rlike_to_matchesregex():
    r = t('FROM logs-* | WHERE host.name RLIKE "web.*"')
    assert "matchesRegex(host.name" in r.dql


def test_pipeline_structure():
    r = t('FROM logs-* | WHERE a == 1 | LIMIT 5')
    lines = r.dql.splitlines()
    assert lines[0].startswith("fetch")
    assert lines[1].startswith("| filter")
    assert lines[2].startswith("| limit")
