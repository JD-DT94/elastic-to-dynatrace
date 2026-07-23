"""Elastic/Kibana pull connector (mocked HTTP) + the web pull→convert flow."""

import json

import pytest

import e2d.sources.elastic as el
from e2d.sources import Connection, discover, pull
from e2d.web.server import Sessions


class FakeResp:
    def __init__(self, data, text=None):
        self._d = data
        self.text = text if text is not None else json.dumps(data)

    def json(self):
        return self._d

    def raise_for_status(self):
        pass


class FakeSession:
    """Routes are (method, url-substring) -> data/text. First match wins."""
    def __init__(self, routes):
        self.routes = routes
        self.headers = {}
        self.verify = True

    def _match(self, method, url):
        best = None  # longest (most specific) matching substring wins
        for (m, sub), val in self.routes.items():
            if m == method and sub in url and (best is None or len(sub) > len(best[0])):
                best = (sub, val)
        if best is None:
            raise Exception(f"404 {method} {url}")
        val = best[1]
        return FakeResp({}, text=val) if isinstance(val, str) else FakeResp(val)

    def get(self, url, timeout=30):
        return self._match("GET", url)

    def post(self, url, data=None, timeout=60):
        return self._match("POST", url)


CONN = Connection(kibana_url="https://kb:5601", es_url="https://es:9200", token="k")


def _patch(monkeypatch, routes):
    monkeypatch.setattr(el, "_session", lambda conn: FakeSession(routes))


def test_discover_aggregates_all_sources(monkeypatch):
    _patch(monkeypatch, {
        ("GET", "/api/saved_objects/_find"): {"saved_objects": [
            {"id": "d1", "attributes": {"title": "Dash One"}}]},
        ("GET", "/api/alerting/rules/_find"): {"data": [{"id": "r1", "name": "Rule One"}]},
        ("GET", "/_ingest/pipeline"): {"p1": {}, "p2": {}},
        ("GET", "/_watcher/_query/watches"): {"watches": [{"_id": "w1"}]},
    })
    res = discover(CONN)
    kinds = sorted(i["kind"] for i in res["items"])
    assert kinds == ["dashboard", "pipeline", "pipeline", "rule", "watcher"]
    assert res["errors"] == {}


def test_discover_partial_failure_is_reported(monkeypatch):
    _patch(monkeypatch, {  # only pipelines respond; the rest 404
        ("GET", "/_ingest/pipeline"): {"p1": {}},
    })
    res = discover(CONN)
    assert any(i["kind"] == "pipeline" for i in res["items"])
    assert "dashboards" in res["errors"] and "watchers" in res["errors"]


def test_pull_fetches_each_kind(monkeypatch):
    _patch(monkeypatch, {
        ("POST", "/api/saved_objects/_export"): '{"type":"dashboard","id":"d1"}\n',
        ("GET", "/api/alerting/rule/r1"): {"rule_type_id": "logs.alert.document.count"},
        ("GET", "/_ingest/pipeline/p1"): {"p1": {"processors": []}},
        ("GET", "/_watcher/watch/w1"): {"watch": {"trigger": {}, "input": {}}},
    })
    out = dict(pull(CONN, [
        {"kind": "dashboard", "id": "d1"}, {"kind": "rule", "id": "r1"},
        {"kind": "pipeline", "id": "p1"}, {"kind": "watcher", "id": "w1"}]))
    assert "d1.ndjson" in out and '"type":"dashboard"' in out["d1.ndjson"]
    assert json.loads(out["rule_r1.json"])["rule_type_id"] == "logs.alert.document.count"
    assert "processors" in out["p1.json"]
    assert "trigger" in out["watch_w1.json"]


def test_web_connect_discover_pull_convert(monkeypatch):
    _patch(monkeypatch, {
        ("GET", "/_ingest/pipeline"): {"app_access": {}},
        ("GET", "/_ingest/pipeline/app_access"): {"app_access": {
            "processors": [{"set": {"field": "env", "value": "prod"}}]}},
        ("GET", "/api/saved_objects/_find"): {"saved_objects": []},
        ("GET", "/api/alerting/rules/_find"): {"data": []},
        ("GET", "/_watcher/_query/watches"): {"watches": []},
    })
    s = Sessions()
    try:
        sid = s.new()
        s.connect(sid, {"kibana_url": "https://kb", "es_url": "https://es", "token": "k"})
        disc = s.discover(sid)
        assert any(i["kind"] == "pipeline" for i in disc["items"])
        n = s.pull(sid, [{"kind": "pipeline", "id": "app_access"}])
        assert n == 1
        res = s.migrate(sid)               # converts the pulled pipeline
        assert res["total"] >= 1
    finally:
        s.close()
