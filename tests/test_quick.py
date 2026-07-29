"""The paste-a-query converter behind both GUIs' quick panel."""

from e2d.quick import convert_query, detect_lang


def test_detect_lang():
    assert detect_lang('{"query": {"match_all": {}}}') == "dsl"
    assert detect_lang("FROM logs-* | LIMIT 10") == "esql"
    assert detect_lang("from logs-app\n| where status >= 500") == "esql"
    assert detect_lang('service.name: "checkout" and status >= 500') == "kql"


def test_esql_paste():
    r = convert_query("FROM logs-* | WHERE status >= 500 | STATS c = COUNT() BY host.name")
    assert r["lang"] == "esql"
    assert "fetch" in r["dql"] and "summarize" in r["dql"]
    assert r["status"] in ("OK", "REVIEW")
    assert "error" not in r


def test_query_dsl_paste():
    r = convert_query('{"query": {"term": {"status": 500}}}')
    assert r["lang"] == "dsl"
    assert r["dql"].startswith("fetch")


def test_kql_paste_carries_warnings():
    r = convert_query('service.name: "checkout"', lang="kql")
    assert "filter" in r["dql"]
    assert isinstance(r["notes"], list)


def test_bad_json_is_an_inline_error_not_a_crash():
    r = convert_query('{"query": broken', lang="dsl")
    assert r["status"] == "ERROR" and "error" in r and r["dql"] == ""


def test_empty_paste():
    r = convert_query("   ")
    assert r["status"] == "ERROR" and "Paste a query" in r["error"]
