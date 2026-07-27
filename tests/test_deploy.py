"""Dynatrace deploy sink (Document API) + the web deploy flow."""

import io
import json
import zipfile

import e2d.sinks.dynatrace as dyn
from e2d.sinks import deploy_dashboards, push_dashboard
from e2d.web.server import Sessions

DASH = {"name": "My Dash", "content": {"tiles": {"a": {}, "b": {}}}}


def _zip(members):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for n, d in members.items():
            zf.writestr(n, d)
    return buf.getvalue()


def test_dry_run_does_not_call_out():
    r = push_dashboard("https://x", "tok", "My Dash", DASH["content"], apply=False)
    assert r.ok and r.dry_run and "2 tiles" in r.detail


def test_apply_without_creds_fails_gracefully():
    r = push_dashboard("", "", "D", {}, apply=True)
    assert not r.ok and "missing env URL or token" in r.detail


def test_apply_success_mocked(monkeypatch):
    class Resp:
        status_code = 201
        def json(self): return {"documentMetadata": {"id": "doc-123"}}
        text = ""
    captured = {}
    def fake_post(url, headers=None, data=None, files=None, timeout=None):
        captured["url"] = url; captured["auth"] = headers["Authorization"]; captured["name"] = data["name"]
        return Resp()
    import requests
    monkeypatch.setattr(requests, "post", fake_post)
    r = push_dashboard("https://env", "tok", "My Dash", DASH["content"], apply=True)
    assert r.ok and "doc-123" in r.detail
    assert captured["url"].endswith("/platform/document/v1/documents")
    assert captured["auth"] == "Bearer tok" and captured["name"] == "My Dash"


def test_deploy_dashboards_batch_dry_run():
    res = deploy_dashboards("https://x", "t", [("a.json", DASH), ("b.json", {"tiles": {}})], apply=False)
    assert len(res) == 2 and all(r.dry_run for r in res)
    # a wrapped doc keeps its embedded name; a bare content doc is named
    # after its file (converted files carry no name key)
    assert res[0].name == "My Dash" and res[1].name == "b"


def test_deploy_names_bare_content_from_filename():
    content = {"version": 21, "variables": [], "tiles": {}, "layouts": {}}
    res = deploy_dashboards("https://x", "t",
                            [("out/dashboards/[PFK] Financials.json", content)], apply=False)
    assert res[0].name == "[PFK] Financials"


def test_detector_settings_value_shape():
    from e2d.sinks.dynatrace import detector_settings_value, ANOMALY_SCHEMA
    from e2d.alerts.model import Detector
    det = Detector(title="count > 50", query="fetch logs | makeTimeseries count = count(), interval: 1m",
                   alert_condition="ABOVE", threshold="50")
    v = detector_settings_value("simple_error", det)
    assert v["enabled"] is True and v["title"].startswith("simple_error:")
    # analyzer.input and eventTemplate.properties are ARRAYS of {key,value}
    keys = {f["key"]: f["value"] for f in v["analyzer"]["input"]}
    assert keys["alertCondition"] == "ABOVE" and keys["threshold"] == "50"
    assert keys["query"].startswith("fetch logs")
    assert v["analyzer"]["name"].endswith("StaticThresholdAnomalyDetectionAnalyzer")
    assert any(p["key"] == "event.type" and p["value"] == "CUSTOM_ALERT"
               for p in v["eventTemplate"]["properties"])


def test_detector_dynamic_threshold_disabled():
    from e2d.sinks.dynatrace import detector_settings_value
    from e2d.alerts.model import Detector
    det = Detector(title="x", query="fetch logs | makeTimeseries count = count(), interval: 1m",
                   alert_condition="ABOVE", threshold='"<dynamic:{{x}}>"')
    v = detector_settings_value("a", det)
    assert v["enabled"] is False
    keys = {f["key"]: f["value"] for f in v["analyzer"]["input"]}
    assert keys["threshold"] == "0"


def test_deploy_detectors_dry_run():
    from e2d.sinks.dynatrace import deploy_detectors
    from e2d.alerts import translate_alert
    spec = translate_alert({"trigger": {"schedule": {"interval": "1m"}},
        "input": {"search": {"request": {"indices": ["logs"], "body": {"size": 0,
            "query": {"match": {"log.level": "ERROR"}}}}}},
        "condition": {"compare": {"ctx.payload.hits.total": {"gt": 5}}}}, name="w").spec
    res = deploy_detectors("https://x", "t", [spec], apply=False)
    assert res and all(r.dry_run for r in res)


def test_web_deploy_dry_run_lists_dashboards_and_tf():
    s = Sessions()
    try:
        sid = s.new()
        # a dashboard NDJSON fixture so migrate produces a dashboards/ output
        nd = json.dumps({"attributes": {"title": "T", "panelsJSON": "[]"}, "type": "dashboard",
                         "id": "d1", "references": []})
        s.add_file(sid, "dash.ndjson", nd.encode("utf-8"))
        s.migrate(sid)
        out = s.deploy(sid, {"apply": False})
        assert out["applied"] is False
        assert isinstance(out["dashboards"], list)
        assert "detectors" in out and "pipelines" in out["terraform"]
    finally:
        s.close()


def test_web_deploy_pushes_detectors_from_alert_input():
    s = Sessions()
    try:
        sid = s.new()
        watcher = json.dumps({"trigger": {"schedule": {"interval": "1m"}},
            "input": {"search": {"request": {"indices": ["logs"], "body": {"size": 0,
                "query": {"match": {"log.level": "ERROR"}}}}}},
            "condition": {"compare": {"ctx.payload.hits.total": {"gt": 5}}}})
        s.add_file(sid, "w.json", watcher.encode("utf-8"))
        s.migrate(sid)
        out = s.deploy(sid, {"apply": False})        # dry run
        assert out["detectors"] and out["detectors"][0]["ok"]
        assert "dry run" in out["detectors"][0]["detail"]
    finally:
        s.close()
