"""Online DQL verify: response parsing, graceful degradation, artifact extraction."""

import json

from e2d.api.client import (_parse_verify_response, _iter_dql_artifacts, verify_dql)


def test_parse_valid_response():
    r = _parse_verify_response("fetch logs", 200, {"valid": True, "notifications": []})
    assert r.valid is True and r.errors == []


def test_parse_error_notification_marks_invalid():
    body = {"valid": False, "notifications": [
        {"severity": "ERROR", "message": "Parse error: unexpected token"},
        {"severity": "WARNING", "message": "deprecated field"},
    ]}
    r = _parse_verify_response("fetch logs | bad", 200, body)
    assert r.valid is False
    assert r.errors == ["Parse error: unexpected token"]
    assert r.warnings == ["deprecated field"]


def test_parse_error_notification_overrides_valid_true():
    # an ERROR notification makes it invalid even if `valid` is absent
    body = {"notifications": [{"severity": "ERROR", "message": "boom"}]}
    r = _parse_verify_response("x", 200, body)
    assert r.valid is False


def test_verify_dql_skips_without_creds():
    r = verify_dql("", None, "fetch logs")
    assert r.valid is None and r.skipped_reason


def test_iter_dql_artifacts(tmp_path):
    (tmp_path / "queries").mkdir()
    (tmp_path / "queries" / "q.dql").write_text("fetch logs | limit 1", encoding="utf-8")
    dash = {"name": "D", "content": {
        "tiles": {"t1": {"query": "fetch logs | summarize count()"}},
        "variables": [{"key": "svc", "input": "fetch logs | fields service.name"}],
    }}
    (tmp_path / "d.json").write_text(json.dumps(dash), encoding="utf-8")

    items = dict(_iter_dql_artifacts(str(tmp_path)))
    assert any(k.endswith("q.dql") for k in items)
    assert any("#tile:t1" in k for k in items)
    assert any("#var:svc" in k for k in items)
    assert items["d.json#tile:t1"] == "fetch logs | summarize count()"
