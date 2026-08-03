"""Translation-logic fidelity: constructs whose naive translation is silently
wrong. Each test pins the semantically correct DQL, not just any output."""

import json

from e2d.quick import convert_query


def dql(lang, q):
    r = convert_query(q, lang)
    assert not r.get("error"), r.get("error")
    return r["dql"], r


# --------------------------------------------------------------------------- #
# existence checks
# --------------------------------------------------------------------------- #

def test_lucene_exists_forms_become_isnotnull():
    out, _ = dql("lucene", "_exists_:user.id")
    assert "isNotNull(user.id)" in out and "_exists_" not in out
    out, _ = dql("lucene", "user.id:*")
    assert "isNotNull(user.id)" in out and "matchesValue" not in out


# --------------------------------------------------------------------------- #
# scoring-only modifiers must not leak into values
# --------------------------------------------------------------------------- #

def test_lucene_scoring_suffixes_are_stripped_and_flagged():
    out, r = dql("lucene", "boost:term^2")
    assert 'boost == "term"' in out and "^" not in out
    out, r = dql("lucene", "name:smith~2")
    assert 'name == "smith"' in out and "~" not in out
    assert any("Fuzziness" in n for n in r["notes"])
    out, r = dql("lucene", 'title:"quick fox"~3')
    assert 'title == "quick fox"' in out
    assert "~3" not in out and "content" not in out
    assert any("proximity" in n.lower() for n in r["notes"])


# --------------------------------------------------------------------------- #
# analyzed matches on the log body: == would match nothing
# --------------------------------------------------------------------------- #

def test_log_body_matches_use_matchesphrase_everywhere():
    out, _ = dql("kql", 'message: "connection refused"')
    assert 'matchesPhrase(content, "connection refused")' in out
    out, _ = dql("lucene", "message:timeout")
    assert 'matchesPhrase(content, "timeout")' in out
    out, _ = dql("dsl", json.dumps(
        {"query": {"match_phrase": {"message": "connection refused"}}}))
    assert 'matchesPhrase(content, "connection refused")' in out
    # multi-word `match` is any-term in ES: converted but flagged for review
    out, r = dql("dsl", json.dumps(
        {"query": {"match": {"message": "connection refused"}}}))
    assert "matchesPhrase" in out
    assert any("ANY" in n for n in r["notes"])


def test_non_body_fields_keep_equality():
    out, _ = dql("kql", 'service.name: "checkout"')
    assert 'service.name == "checkout"' in out
    out, _ = dql("dsl", json.dumps({"query": {"match": {"service.keyword": "checkout"}}}))
    assert 'service == "checkout"' in out


# --------------------------------------------------------------------------- #
# bool.should semantics
# --------------------------------------------------------------------------- #

def test_should_next_to_must_is_optional_and_left_out():
    q = {"query": {"bool": {"must": [{"term": {"status": 500}}],
                            "should": [{"term": {"env": "prod"}},
                                       {"term": {"env": "staging"}}]}}}
    out, r = dql("dsl", json.dumps(q))
    assert "status == 500" in out and "env" not in out
    assert any("minimum_should_match" in n for n in r["notes"])


def test_should_with_msm_1_is_a_required_or_group():
    q = {"query": {"bool": {"must": [{"term": {"status": 500}}],
                            "should": [{"term": {"env": "prod"}},
                                       {"term": {"env": "staging"}}],
                            "minimum_should_match": 1}}}
    out, _ = dql("dsl", json.dumps(q))
    assert "status == 500" in out
    assert '(env == "prod" or env == "staging")' in out


def test_should_only_bool_still_ors():
    q = {"query": {"bool": {"should": [{"term": {"a": 1}}, {"term": {"b": 2}}]}}}
    out, _ = dql("dsl", json.dumps(q))
    assert "a == 1 or b == 2" in out


# --------------------------------------------------------------------------- #
# date math in ranges
# --------------------------------------------------------------------------- #

def test_range_date_math_converts_even_on_custom_time_fields():
    q = {"query": {"bool": {"filter": [{"range": {"ts": {"gte": "now-1h"}}},
                                       {"term": {"status": 500}}]}}}
    out, _ = dql("dsl", json.dumps(q))
    assert "ts >= now()-1h" in out and '"now-1h"' not in out


def test_numeric_ranges_stay_numeric():
    out, _ = dql("dsl", json.dumps({"query": {"range": {"bytes": {"gte": 100, "lt": 500}}}}))
    assert "bytes >= 100" in out and "bytes < 500" in out


# --------------------------------------------------------------------------- #
# negation and grouping still hold after the changes
# --------------------------------------------------------------------------- #

def test_negated_groups_and_exists():
    out, _ = dql("kql", "not (status: 500 or status: 503)")
    assert "not ((status == 500 or status == 503))" in out
    out, _ = dql("kql", "not user.id: *")
    assert "not (isNotNull(user.id))" in out
    out, _ = dql("lucene", "NOT (status:500 OR status:503)")
    assert "not (status == 500 or status == 503)" in out
