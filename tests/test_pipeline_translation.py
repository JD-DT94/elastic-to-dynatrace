"""Track D: Logstash .conf -> OpenPipeline DQL/DPL translation."""

from pathlib import Path

import pytest

import json

from e2d.report import Report, Severity
from e2d.pipelines.grok import grok_to_dpl, dissect_to_dpl
from e2d.pipelines.logstash import parse_logstash, tokenize, Plugin, Conditional
from e2d.pipelines.translate import (
    translate_condition, translate_pipeline, render_pipeline, plan_text,
)
from e2d.pipelines.ingest import translate_ingest, looks_like_ingest_json
from e2d.pipelines.tf import generate_openpipeline_tf

FIXDIR = Path(__file__).resolve().parents[1] / "examples" / "fixtures" / "elastic-fixtures"
FIX = FIXDIR / "03-logstash-pipelines"
INGEST = FIXDIR / "03b-ingest-pipelines" / "app_access_ingest.json"


# ---- grok / dissect -> DPL --------------------------------------------------

def test_grok_access_log_to_dpl():
    pat = (r'%{IPORHOST:client_ip} %{USER:ident} %{USER:auth} \[%{HTTPDATE:timestamp}\] '
           r'"%{WORD:http_method} %{DATA:request_uri} HTTP/%{NUMBER:http_version}" '
           r'%{NUMBER:status_code:int} (?:%{NUMBER:bytes:int}|-) %{NUMBER:response_time_ms:int}')
    dpl = grok_to_dpl(pat, Report())
    assert "IPADDR:client_ip" in dpl
    assert "TIMESTAMP('dd/MMM/yyyy:HH:mm:ss Z'):timestamp" in dpl
    assert "INT:status_code" in dpl                 # :int coercion overrides NUMBER
    assert "( INT:bytes | '-' )" in dpl             # alternation
    assert "DOUBLE:http_version" in dpl             # plain NUMBER -> DOUBLE


def test_grok_optional_group():
    dpl = grok_to_dpl(r"%{WORD:prog}(?:\[%{POSINT:pid}\])?", Report())
    assert "( '[' INT:pid ']' )?" in dpl            # optional non-capturing group


def test_grok_iso8601_has_no_inline_quotes():
    # ISO8601's literal 'T' would break a quoted DPL format, so it auto-detects.
    dpl = grok_to_dpl("%{TIMESTAMP_ISO8601:ts}", Report())
    assert dpl == "TIMESTAMP:ts"


def test_dissect_to_dpl():
    dpl = dissect_to_dpl("%{level} | %{component} | %{msg}", Report())
    assert dpl == "LD:level ' | ' LD:component ' | ' LD:msg"


# ---- condition translation --------------------------------------------------

def _cond(text):
    return translate_condition(tokenize(text), Report())


def test_condition_field_equals_string():
    assert _cond('[fields][log_type] == "corsyca"') == 'fields.log_type == "corsyca"'


def test_condition_in_array_and_tag_membership():
    assert _cond('[level] in ["error", "fatal"]') == 'in(level, {"error", "fatal"})'
    assert _cond('"_grokparsefailure" in [tags]') == 'matchesValue(tags, "_grokparsefailure")'


def test_condition_regex_strips_delimiters():
    out = _cond(r'[request_uri] =~ /^\/(health|ready|live)$/')
    assert out == 'matchesRegex(request_uri, "^/(health|ready|live)$")'


def test_condition_numeric_and_boolean():
    assert _cond("[status_code] >= 500") == "status_code >= 500"
    assert _cond('[a] == "x" and [b] == "y"') == 'a == "x" and b == "y"'


# ---- full fixtures ----------------------------------------------------------

@pytest.mark.skipif(not FIX.exists(), reason="logstash fixtures not present")
def test_simple_syslog_pipeline():
    res = translate_pipeline(parse_logstash((FIX / "simple_syslog.conf").read_text(encoding="utf-8")))
    body = plan_text(res)
    assert body.startswith("fetch logs")
    assert "parse content," in body
    assert "TIMESTAMP('MMM d HH:mm:ss'):syslog_timestamp" in body
    assert not res.report.has_blocking            # nothing MANUAL in the simple case


@pytest.mark.skipif(not FIX.exists(), reason="logstash fixtures not present")
def test_access_log_drop_and_mutate():
    res = translate_pipeline(parse_logstash((FIX / "medium_app_access_log.conf").read_text(encoding="utf-8")))
    body = plan_text(res)
    assert "filterOut matchesRegex(request_uri," in body     # drop {} health checks
    assert 'fieldsAdd geo = ipToGeolocation(client_ip)' in body
    assert "fieldsRemove ident, auth, http_version" in body
    assert 'opco = "direct-assurance"' in body


@pytest.mark.skipif(not FIX.exists(), reason="logstash fixtures not present")
def test_complex_pipeline_flags_manual():
    res = translate_pipeline(parse_logstash((FIX / "complex_multi_source_enrichment.conf").read_text(encoding="utf-8")))
    body = plan_text(res)
    # ruby + kafka are MANUAL; routing, lookup, masking are present
    assert res.report.has_blocking
    manual_sources = {w.source for w in res.report.warnings if w.severity is Severity.MANUAL}
    assert "ruby" in manual_sources and "kafka" in manual_sources
    assert "replacePattern(msg," in body            # gsub PII masking
    assert "lookup [fetch" in body                  # translate -> lookup
    assert "// when: fields.log_type ==" in body   # conditional routing


@pytest.mark.skipif(not FIX.exists(), reason="logstash fixtures not present")
def test_render_includes_notes_header():
    res = translate_pipeline(parse_logstash((FIX / "simple_syslog.conf").read_text(encoding="utf-8")))
    text = render_pipeline("simple_syslog.conf", res)
    assert text.startswith("// OpenPipeline processing stages generated from simple_syslog.conf")
    assert "// Review notes:" in text


# ---- Elasticsearch ingest-pipeline JSON -------------------------------------

def test_ingest_detection():
    assert looks_like_ingest_json('{"processors": [{"set": {"field": "a", "value": 1}}]}')
    assert not looks_like_ingest_json("filter { grok { } }")
    assert not looks_like_ingest_json('{"description": "no processors key"}')


def test_ingest_processor_translation():
    doc = {"processors": [
        {"grok": {"field": "message", "patterns": ["%{IPORHOST:client_ip} %{NUMBER:status_code:int}"]}},
        {"set": {"field": "application_name", "value": "acred-policy-mgmt-pa-v1"}},
        {"rename": {"field": "status_code", "target_field": "http.status"}},
        {"convert": {"field": "http.status", "type": "integer"}},
        {"remove": {"field": ["ua_string", "ident"]}},
    ]}
    res = translate_ingest(doc)
    body = plan_text(res)
    assert body.startswith("fetch logs")
    assert 'parse content, "IPADDR:client_ip' in body            # message -> content
    assert 'fieldsAdd application_name = "acred-policy-mgmt-pa-v1"' in body
    assert "fieldsRename http.status = status_code" in body
    assert "fieldsAdd http.status = toLong(http.status)" in body
    assert "fieldsRemove ua_string, ident" in body


def test_ingest_painless_if_and_drop():
    doc = {"processors": [
        {"drop": {"if": "ctx?.request_uri != null && ctx.request_uri.startsWith('/health')"}},
    ]}
    res = translate_ingest(doc)
    body = plan_text(res)
    # ctx?. stripped, && -> and, '...' -> "...", and the condition gates the drop
    assert 'filterOut request_uri != null and request_uri.startsWith("/health")' in body


def test_ingest_script_is_manual():
    res = translate_ingest({"processors": [{"script": {"source": "ctx.x = 1"}}]})
    assert res.report.has_blocking
    assert any(w.severity is Severity.MANUAL and w.source == "script" for w in res.report.warnings)


@pytest.mark.skipif(not INGEST.exists(), reason="ingest fixture not present")
def test_ingest_fixture_end_to_end():
    res = translate_ingest(json.loads(INGEST.read_text(encoding="utf-8")))
    body = plan_text(res)
    assert 'parse content, "IPADDR:client_ip' in body
    assert "LD:audit.logText" in body and "LD:tracking.transactionName" in body  # dissect
    assert "fieldsAdd geo = ipToGeolocation(client_ip)" in body
    assert "replacePattern(msg," in body
    assert res.report.has_blocking                                   # the script processor
    # on_failure surfaced as INFO
    assert any("on_failure" in w.message for w in res.report.warnings)


# ---- Terraform (dynatrace_openpipeline_v2_logs_pipelines) -------------------

@pytest.mark.skipif(not FIX.exists(), reason="logstash fixtures not present")
def test_terraform_generation_structure():
    res = translate_pipeline(parse_logstash((FIX / "medium_app_access_log.conf").read_text(encoding="utf-8")))
    files = generate_openpipeline_tf("medium_app_access_log.conf", res)
    assert set(files) == {"main.tf", "pipeline.tf"}
    tf = files["pipeline.tf"]
    # v2 resource: flat, display_name + custom_id, processors{} wrapper, type discriminator
    assert 'resource "dynatrace_openpipeline_v2_logs_pipelines"' in tf
    assert "custom_id    =" in tf and "processors {" in tf
    assert 'type        = "dql"' in tf and 'type        = "drop"' in tf
    assert "dql {" in tf and "script =" in tf and "matcher     =" in tf
    assert "dql_script" not in tf and "openpipeline_logs\"" not in tf   # no deprecated forms
    # the health-check drop became a drop processor whose matcher is the regex
    assert 'matchesRegex(request_uri' in tf
    assert tf.count("{") == tf.count("}")     # balanced braces


def test_terraform_escapes_quotes_in_dql():
    res = translate_ingest({"processors": [
        {"set": {"field": "application_name", "value": "acred-policy-mgmt-pa-v1"}},
    ]})
    tf = generate_openpipeline_tf("x.json", res)["pipeline.tf"]
    # the embedded double quotes from the DQL string literal must be HCL-escaped
    assert r'fieldsAdd application_name = \"acred-policy-mgmt-pa-v1\"' in tf


# ---- deploy wrapper ---------------------------------------------------------

def test_deploy_missing_env_detection():
    from e2d.pipelines.deploy import missing_env
    assert missing_env({}) == ["DT_CLIENT_ID", "DT_CLIENT_SECRET", "DT_ACCOUNT_ID", "DT_ENV_URL"]
    full = {"DT_CLIENT_ID": "a", "DT_CLIENT_SECRET": "b", "DT_ACCOUNT_ID": "c", "DYNATRACE_ENV_URL": "u"}
    assert missing_env(full) == []                       # env URL satisfied by either var name
    assert missing_env({**full, "DYNATRACE_ENV_URL": ""}) == ["DT_ENV_URL"]


def test_deploy_terraform_steps():
    from e2d.pipelines.deploy import terraform_steps
    assert terraform_steps(False) == [
        ["terraform", "init", "-input=false", "-no-color"],
        ["terraform", "plan", "-input=false", "-no-color"],
    ]
    assert terraform_steps(True)[1][:2] == ["terraform", "apply"]
