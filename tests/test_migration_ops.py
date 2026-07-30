"""Migration-operations features: backfill, cutover planning, SLOs, Beats
shippers, Heartbeat synthetics, and parity checking."""

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from e2d.migrate import classify, run_migration


# --------------------------------------------------------------------------- #
# backfill: the 24h wall workaround
# --------------------------------------------------------------------------- #

def test_backfill_restamps_and_preserves_original_time():
    from e2d.backfill import to_log_record, parse_ts
    now = datetime(2026, 7, 29, 12, 0, tzinfo=timezone.utc)
    tmin = parse_ts("2026-01-01T00:00:00Z")
    tmax = parse_ts("2026-01-31T00:00:00Z")
    hit = {"_index": "logs-app-2026.01", "_source": {
        "@timestamp": "2026-01-15T12:00:00Z", "message": "boom",
        "service": {"name": "checkout"}}}
    rec = to_log_record(hit, now, "spread", tmin, tmax)
    assert rec["content"] == "boom"
    assert rec["original_timestamp"].startswith("2026-01-15T12:00:00")
    assert rec["backfilled"] == "true"
    assert rec["source.index"] == "logs-app-2026.01"
    assert rec["service.name"] == "checkout"
    # the new timestamp sits inside the accepted window (now-23h .. now)
    stamped = datetime.fromisoformat(rec["timestamp"])
    assert now - timedelta(hours=23, minutes=1) <= stamped <= now


def test_backfill_spread_preserves_order_and_now_mode_stamps_now():
    from e2d.backfill import restamp, parse_ts
    now = datetime(2026, 7, 29, 12, 0, tzinfo=timezone.utc)
    tmin, tmax = parse_ts("2026-01-01T00:00:00Z"), parse_ts("2026-01-31T00:00:00Z")
    early = restamp(parse_ts("2026-01-05T00:00:00Z"), now, "spread", tmin, tmax)
    late = restamp(parse_ts("2026-01-25T00:00:00Z"), now, "spread", tmin, tmax)
    assert early < late
    assert restamp(early, now, "now", tmin, tmax) == now


def test_backfill_batches_respect_both_limits():
    from e2d.backfill import make_batches
    small = [{"content": "x", "timestamp": "t"} for _ in range(7)]
    batches = list(make_batches(iter(small), max_records=3, max_bytes=10**6))
    assert [len(b) for b in batches] == [3, 3, 1]
    big = [{"content": "y" * 100} for _ in range(10)]
    by_bytes = list(make_batches(iter(big), max_records=100, max_bytes=250))
    assert all(len(b) <= 2 for b in by_bytes) and sum(len(b) for b in by_bytes) == 10


def test_backfill_skips_records_without_timestamps():
    from e2d.backfill import to_log_record
    now = datetime.now(timezone.utc)
    assert to_log_record({"_source": {"message": "no ts"}}, now, "now", now, now) is None


# --------------------------------------------------------------------------- #
# cutover planning
# --------------------------------------------------------------------------- #

def test_cutover_parses_retention_and_renders_plan():
    from e2d.cutover import parse_min_age_days, render_cutover_plan, bucket_definition
    assert parse_min_age_days("30d") == 30
    assert parse_min_age_days("720h") == 30
    assert parse_min_age_days("0ms") == 0
    assert parse_min_age_days(None) is None
    b = bucket_definition("Logs-Prod", 30)
    assert b["bucketName"] == "logs_prod_logs" and b["retentionDays"] == 30
    md = render_cutover_plan({"logs-prod": 30, "audit": None})
    assert "24 hours" in md and "read-only" in md
    assert "logs_prod_logs" in md and "no delete phase" in md
    assert "e2d backfill" in md and "Dual-ship" in md


def test_migrate_writes_cutover_plan_from_ilm(tmp_path):
    (tmp_path / "in").mkdir()
    (tmp_path / "in" / "policy.json").write_text(json.dumps(
        {"policy": {"phases": {"hot": {"min_age": "0ms", "actions": {}},
                               "delete": {"min_age": "30d", "actions": {"delete": {}}}}}}),
        encoding="utf-8")
    s = run_migration(str(tmp_path / "in"), str(tmp_path / "out"))
    assert s.ilm_policies == {"policy": 30}
    plan = (tmp_path / "out" / "CUTOVER-PLAN.md").read_text(encoding="utf-8")
    assert "30 d" in plan
    report = (tmp_path / "out" / "MIGRATION_REPORT.md").read_text(encoding="utf-8")
    assert "CUTOVER-PLAN.md" in report


# --------------------------------------------------------------------------- #
# SLOs
# --------------------------------------------------------------------------- #

SLO_DOC = {
    "name": "Checkout availability",
    "indicator": {"type": "sli.kql.custom",
                  "params": {"index": "logs-checkout-*",
                             "filter": 'service.name: "checkout"',
                             "good": "status < 500",
                             "total": "status >= 100"}},
    "objective": {"target": 0.995},
    "timeWindow": {"duration": "30d", "type": "rolling"},
    "budgetingMethod": "occurrences",
}


def test_slo_kql_custom_becomes_sli_dql(tmp_path):
    from e2d.slo import translate_slo
    res = translate_slo(json.dumps(SLO_DOC))
    assert res.target_pct == 99.5
    assert "countIf" in res.dql and "sli =" in res.dql
    assert 'service.name == "checkout"' in res.dql
    p = tmp_path / "slo.json"
    p.write_text(json.dumps(SLO_DOC), encoding="utf-8")
    assert classify(p) == "slo"


def test_slo_apm_indicator_is_flagged_manual():
    from e2d.slo import translate_slo
    res = translate_slo(json.dumps({
        "name": "latency", "objective": {"target": 0.99},
        "indicator": {"type": "sli.apm.transactionDuration", "params": {}}}))
    assert res.dql == "" and res.report.has_blocking


def test_migrate_converts_slo_file(tmp_path):
    (tmp_path / "in").mkdir()
    (tmp_path / "in" / "checkout_slo.json").write_text(json.dumps(SLO_DOC), encoding="utf-8")
    s = run_migration(str(tmp_path / "in"), str(tmp_path / "out"))
    assert [it.category for it in s.items] == ["slo"]
    assert (tmp_path / "out" / "slos" / "checkout_slo.dql").exists()
    md = (tmp_path / "out" / "slos" / "checkout_slo.slo.md").read_text(encoding="utf-8")
    assert "99.5" in md and "sli" in md


# --------------------------------------------------------------------------- #
# yamlite + Beats
# --------------------------------------------------------------------------- #

FILEBEAT = """filebeat.inputs:
  - type: filestream
    id: app-logs
    paths:
      - /var/log/app/*.log
    multiline.pattern: '^\\d{4}-'
    multiline.negate: true
    multiline.match: after
    fields:
      env: prod
output.elasticsearch:
  hosts: ["es:9200"]
"""

HEARTBEAT = """heartbeat.monitors:
  - type: http
    id: api-check
    name: API health
    schedule: '@every 60s'
    urls: ["https://api.example.com/health"]
    check.response.status: [200]
  - type: tcp
    id: db-check
    schedule: '@every 5m'
    hosts: ["db:5432"]
"""


def test_yamlite_parses_the_beats_subset():
    from e2d.yamlite import parse
    doc = parse(FILEBEAT)
    inp = doc["filebeat.inputs"][0]
    assert inp["paths"] == ["/var/log/app/*.log"]
    assert inp["multiline.negate"] is True
    assert doc["output.elasticsearch"]["hosts"] == ["es:9200"]


def test_filebeat_becomes_otel_collector_config():
    from e2d.yamlite import parse
    from e2d.beats import translate_filebeat, detect_beat
    doc = parse(FILEBEAT)
    assert detect_beat(doc) == "filebeat"
    res = translate_filebeat(doc)
    assert "filelog/app_logs:" in res.otel_yaml
    assert '"/var/log/app/*.log"' in res.otel_yaml
    assert "line_start_pattern" in res.otel_yaml
    assert "otlphttp/dynatrace" in res.otel_yaml
    assert "env" in res.otel_yaml  # fields carried as attributes


def test_heartbeat_http_becomes_synthetic_monitor_tcp_flagged():
    from e2d.yamlite import parse
    from e2d.beats import translate_heartbeat
    res = translate_heartbeat(parse(HEARTBEAT))
    assert len(res.monitors) == 1
    mon = res.monitors[0]
    assert mon["type"] == "HTTP" and mon["frequencyMin"] == 1
    assert mon["script"]["requests"][0]["url"] == "https://api.example.com/health"
    assert res.report.has_blocking  # the tcp monitor needs a human


def test_migrate_routes_beats_files(tmp_path):
    (tmp_path / "in").mkdir()
    (tmp_path / "in" / "filebeat.yml").write_text(FILEBEAT, encoding="utf-8")
    (tmp_path / "in" / "heartbeat.yml").write_text(HEARTBEAT, encoding="utf-8")
    s = run_migration(str(tmp_path / "in"), str(tmp_path / "out"))
    cats = sorted(it.category for it in s.items)
    assert cats == ["shipper", "synthetic"]
    assert (tmp_path / "out" / "shippers" / "filebeat.otel.yaml").exists()
    assert (tmp_path / "out" / "synthetics" / "heartbeat.monitors.json").exists()


# --------------------------------------------------------------------------- #
# parity
# --------------------------------------------------------------------------- #

def test_parity_count_dql_windows_and_wraps():
    from e2d.parity import count_dql
    out = count_dql("fetch logs\n| filter status >= 500", "2h")
    assert "from: now() - 2h" in out and "summarize parity_count = count()" in out
    agg = count_dql("fetch logs\n| summarize c = count(), by: {host}", "2h")
    assert agg.count("summarize") == 1  # already aggregated; not double-wrapped


def test_parity_compare_verdicts():
    from e2d.parity import compare, es_count_body
    assert compare(1000, 1000, "q").verdict == "MATCH"
    assert compare(1000, 1015, "q").verdict == "MATCH"      # within 2%
    assert compare(1000, 1500, "q").verdict == "DIFF"
    assert compare(None, 5, "q").verdict == "SKIP"
    body = es_count_body({"term": {"status": 500}}, "2h")
    assert body["query"]["bool"]["filter"][0]["range"]["@timestamp"]["gte"] == "now-2h"


# --------------------------------------------------------------------------- #
# backfill automation (driver + GUI job runner)
# --------------------------------------------------------------------------- #

def test_run_backfill_reports_progress_and_sample(monkeypatch):
    import e2d.backfill as bf

    hits = [{"_index": "logs-a", "_source": {"@timestamp": f"2026-01-0{i}T00:00:00Z",
                                             "message": f"m{i}"}} for i in range(1, 6)]
    monkeypatch.setattr(bf, "es_scan", lambda *a, **k: iter(hits))
    sent_batches = []
    monkeypatch.setattr(bf, "ingest_batch",
                        lambda env, tok, batch, classic=False, timeout=0:
                        sent_batches.append(len(batch)) or None)
    seen = []
    stats = bf.run_backfill(
        es_url="https://es:9200", es_token="", es_auth="ApiKey", index="logs-a",
        time_from="2026-01-01T00:00:00Z", time_to="2026-01-05T00:00:00Z",
        query=None, env_url="https://env", dt_token="tok", stamp="spread",
        apply=True, out=None, on_progress=lambda st: seen.append(st.sent))
    assert stats.scanned == 5 and stats.sent == 5 and not stats.errors
    assert stats.sample and stats.sample["content"] == "m1"
    assert seen and seen[-1] == 5
    assert sum(sent_batches) == 5


def test_sessions_backfill_job_runs_in_background(monkeypatch):
    import time
    import e2d.backfill as bf
    from e2d.backfill import BackfillStats
    from e2d.web.server import Sessions

    def fake_run(**kw):
        st = BackfillStats(scanned=7, prepared=7, sent=7, batches=1,
                           sample={"content": "x"})
        if kw.get("on_progress"):
            kw["on_progress"](st)
        return st
    monkeypatch.setattr(bf, "run_backfill", fake_run)

    s = Sessions()
    try:
        sid = s.new()
        out = s.backfill_start(sid, {"es_url": "https://es:9200", "selection": [
            {"index": "logs-a", "from": "2026-01-01", "to": "2026-02-01"}]})
        assert out["started"] == 1 and out["apply"] is False
        deadline = time.time() + 5
        job = s.backfill_status(sid)
        while job["state"] != "done" and time.time() < deadline:
            time.sleep(0.05)
            job = s.backfill_status(sid)
        assert job["state"] == "done"
        row = job["rows"][0]
        assert row["state"] == "done" and row["sent"] == 7
        assert row["sample"] == {"content": "x"}
    finally:
        s.close()


def test_backfill_status_without_job_is_a_404_keyerror():
    import pytest
    from e2d.web.server import Sessions
    s = Sessions()
    try:
        sid = s.new()
        with pytest.raises(KeyError):
            s.backfill_status(sid)
    finally:
        s.close()


# --------------------------------------------------------------------------- #
# CLI wiring
# --------------------------------------------------------------------------- #

def test_cli_parses_backfill_and_parity():
    from e2d.cli import build_parser
    p = build_parser()
    a = p.parse_args(["backfill", "--es-url", "https://es:9200", "--index", "logs-*",
                      "--from", "2026-01-01T00:00:00Z", "--to", "2026-02-01T00:00:00Z"])
    assert a.time_from.startswith("2026-01-01") and a.stamp == "spread" and not a.apply
    a = p.parse_args(["parity", "out", "--es-url", "https://es:9200", "--index", "logs-*"])
    assert a.window == "2h" and a.tolerance == 0.02
    a = p.parse_args(["backfill", "--es-url", "https://es:9200", "--discover"])
    assert a.discover and a.index is None
    a = p.parse_args(["backfill", "--es-url", "https://es:9200",
                      "--index", "logs-a-*, logs-b-*",
                      "--from", "2026-01-01", "--to", "2026-02-01"])
    assert [i.strip() for i in a.index.split(",")] == ["logs-a-*", "logs-b-*"]
