"""The emit selector: alerts/pipelines as Settings-API JSON, Terraform, or both.

The JSON files must be verbatim request bodies for
`POST {env}/api/v2/settings/objects` — schemaId + scope + value per object —
because "upload this file" is the whole point of the no-Terraform path.
"""

import json
from pathlib import Path

from e2d.migrate import run_migration

WATCHER = json.dumps({
    "trigger": {"schedule": {"interval": "1m"}},
    "input": {"search": {"request": {"indices": ["logs-*"], "body": {
        "query": {"bool": {"filter": [{"term": {"loglevel": "ERROR"}}]}}}}}},
    "condition": {"compare": {"ctx.payload.hits.total": {"gt": 50}}},
    "actions": {"notify": {"email": {"to": "ops@example.com"}}},
})

LOGSTASH = """
input { beats { port => 5044 } }
filter {
  grok { match => { "message" => "%{IPORHOST:clientip} %{WORD:verb}" } }
  mutate { add_field => { "env" => "prod" } }
}
output { elasticsearch { hosts => ["localhost:9200"] } }
"""


def _run(tmp_path, **kw):
    indir = tmp_path / "in"
    indir.mkdir()
    (indir / "watcher.json").write_text(WATCHER, encoding="utf-8")
    (indir / "web.conf").write_text(LOGSTASH, encoding="utf-8")
    out = tmp_path / "out"
    return run_migration(str(indir), str(out), **kw), out


def test_default_emits_both_formats(tmp_path):
    s, out = _run(tmp_path)
    assert s.emit == "both"
    assert (out / "alerts" / "watcher.detectors.json").exists()
    assert (out / "terraform" / "detectors.tf").exists()
    assert (out / "pipelines" / "web.pipeline.json").exists()
    assert (out / "terraform" / "pipelines.tf").exists()


def test_detectors_json_is_settings_api_body(tmp_path):
    _, out = _run(tmp_path)
    body = json.loads((out / "alerts" / "watcher.detectors.json").read_text(encoding="utf-8"))
    assert isinstance(body, list) and body
    obj = body[0]
    assert obj["schemaId"] == "builtin:davis.anomaly-detectors"
    assert obj["scope"] == "environment"
    inputs = {i["key"]: i["value"] for i in obj["value"]["analyzer"]["input"]}
    assert inputs["threshold"] == "50"
    assert "timeseries" in inputs["query"] or "fetch" in inputs["query"]
    # numeric threshold -> detector ships enabled
    assert obj["value"]["enabled"] is True


def test_pipeline_json_is_settings_api_body(tmp_path):
    _, out = _run(tmp_path)
    body = json.loads((out / "pipelines" / "web.pipeline.json").read_text(encoding="utf-8"))
    obj = body[0]
    assert obj["schemaId"] == "builtin:openpipeline.logs.pipelines"
    assert obj["scope"] == "environment"
    value = obj["value"]
    # distinct customId so a Terraform deploy of the same pipeline never collides
    assert value["customId"].endswith("_api")
    assert value["displayName"] == "web"
    assert value["metadataList"] == []
    procs = value["processing"]["processors"]
    assert procs, "the grok/mutate stages must appear as processors"
    for p in procs:
        assert p["type"] in ("dql", "drop")
        assert p["id"] and p["matcher"] and isinstance(p["enabled"], bool)
        if p["type"] == "dql":
            assert p["dql"]["script"]


def test_emit_json_skips_terraform(tmp_path):
    s, out = _run(tmp_path, emit="json")
    assert s.emit == "json"
    assert (out / "alerts" / "watcher.detectors.json").exists()
    assert (out / "pipelines" / "web.pipeline.json").exists()
    assert not (out / "terraform").exists()
    # the rollout plan tells the user to POST the settings bodies, not terraform apply
    from e2d.plan import build_plan
    plan = build_plan(s)
    hows = {st["title"]: st["how"] for st in plan["steps"]}
    assert "settings/objects" in hows["Deploy ingest pipelines"]
    assert "terraform" not in hows["Deploy ingest pipelines"]
    assert "settings/objects" in hows["Enable alerting last"]
    assert "terraform" not in hows["Enable alerting last"]


def test_emit_tf_skips_json(tmp_path):
    s, out = _run(tmp_path, emit="tf")
    assert s.emit == "tf"
    assert not (out / "alerts" / "watcher.detectors.json").exists()
    assert not (out / "pipelines" / "web.pipeline.json").exists()
    assert (out / "terraform" / "detectors.tf").exists()
    assert (out / "terraform" / "pipelines.tf").exists()


def test_unknown_emit_value_falls_back_to_both(tmp_path):
    s, out = _run(tmp_path, emit="yaml")
    assert s.emit == "both"
    assert (out / "terraform").exists()
    assert (out / "pipelines" / "web.pipeline.json").exists()
