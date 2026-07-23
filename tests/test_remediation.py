"""Manual-remediation knowledge base + its surfacing in the web response."""

from e2d.remediation import remediations_for, remediations_for_notes, _REMEDIES
from e2d.web.server import Sessions


def test_each_remedy_matches_its_own_triggers():
    for r in _REMEDIES:
        for t in r.triggers:
            assert any(x.key == r.key for x in remediations_for(t)), f"{r.key} !match {t!r}"


def test_matches_real_finding_text():
    keys = {r.key for r in remediations_for(
        "`top_hits` agg `hits` has no scalar DQL equivalent; run a companion record query.")}
    assert "top_hits" in keys
    keys = {r.key for r in remediations_for(
        "Metric `system.cpu.total.norm.pct` is not a Dynatrace metric (no `dt.*`).")}
    assert "metric_missing" in keys


def test_notes_dedupe():
    notes = ["`scripted_metric` is arbitrary Painless", "Painless condition approximated"]
    out = remediations_for_notes(notes)
    keys = [r.key for r in out]
    assert len(keys) == len(set(keys))   # no duplicates


def test_web_migrate_attaches_remediation():
    s = Sessions()
    try:
        sid = s.new()
        # a watcher with a scripted_metric / Painless -> should attach a remedy
        watcher = b'''{"trigger":{"schedule":{"interval":"1m"}},
          "input":{"search":{"request":{"indices":["logs-*"],"body":{"size":0,
            "query":{"match":{"log.level":"ERROR"}},
            "aggs":{"u":{"scripted_metric":{"map_script":"x","reduce_script":"y"}}}}}}},
          "condition":{"compare":{"ctx.payload.hits.total":{"gt":1}}}}'''
        s.add_file(sid, "w.json", watcher)
        res = s.migrate(sid)
        item = res["items"][0]
        assert "remediation" in item
        assert any(r["title"] for r in item["remediation"])
    finally:
        s.close()
