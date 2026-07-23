"""Elasticsearch ingest-pipeline JSON -> OpenPipeline processing stages.

An ingest pipeline is `{"processors": [ {"<name>": {...}}, ... ], "on_failure": [...]}`.
Each processor maps to the same OpenPipeline DQL/DPL stage as its Logstash cousin
(reusing `grok.py` + the stage helpers in `translate.py`), so the two front-ends
converge on one target. Per-processor `if` Painless conditions are translated
best-effort and flagged REVIEW; `script` processors are MANUAL.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional

from e2d.pipelines.grok import grok_to_dpl, dissect_to_dpl
from e2d.pipelines.translate import (
    PipelineResult, Stage, _dql, _dql_str, _field, _quote_lhs, _strip_brackets,
)
from e2d.report import Report

_CONVERT = {"integer": "toLong", "long": "toLong", "float": "toDouble",
            "double": "toDouble", "string": "toString", "boolean": "toBoolean"}


def _painless_to_dql(cond: str, report: Report) -> str:
    """Best-effort Painless `if` -> DQL condition (simple comparisons only)."""
    out = cond.strip()
    out = out.replace("ctx?.", "").replace("ctx.", "")
    out = out.replace("?.", ".")
    out = re.sub(r"'([^']*)'", lambda m: _dql_str(m.group(1)), out)
    out = out.replace("&&", " and ").replace("||", " or ")
    out = re.sub(r"!\s*(?=[A-Za-z(])", "not ", out)
    out = re.sub(r"\s+", " ", out).strip()
    report.warn("ingest `if` is a Painless expression; translated best-effort — verify.",
                source=cond[:50])
    return out


def _translate_processor(name: str, cfg: Dict[str, Any], out: List[Stage], report: Report) -> None:
    guard = cfg.get("if")
    matcher = _painless_to_dql(guard, report) if guard else "true"

    if name == "grok":
        patterns = cfg.get("patterns") or ([cfg["pattern"]] if cfg.get("pattern") else [])
        src = _field(cfg.get("field", "message"))
        if not patterns:
            report.warn("grok processor with no patterns; skipped.")
        else:
            _dql(out, f'parse {src}, "{grok_to_dpl(patterns[0], report)}"', matcher)
            if len(patterns) > 1:
                report.warn(f"grok has {len(patterns)} patterns; only the first was translated — "
                            "add the rest as DPL alternations.", source="grok")
    elif name == "dissect":
        src = _field(cfg.get("field", "message"))
        _dql(out, f'parse {src}, "{dissect_to_dpl(cfg.get("pattern", ""), report)}"', matcher)
    elif name == "kv":
        src = _field(cfg.get("field", "message"))
        fs, vs = cfg.get("field_split", " "), cfg.get("value_split", "=")
        report.warn(f"kv on `{src}` -> DPL KVP matcher (field_split={fs!r} value_split={vs!r}).",
                    source="kv")
        _dql(out, f'parse {src}, "KVP{{}}"', matcher, f"TODO DPL KVP: split on {fs!r}, kv on {vs!r}")
    elif name == "date":
        src = _field(cfg.get("field", "timestamp"))
        tgt = _field(cfg.get("target_field", "@timestamp"))
        _dql(out, f"fieldsAdd {tgt} = toTimestamp({src})", matcher)
        report.warn("date processor -> toTimestamp(): custom formats may need a DPL TIMESTAMP matcher.",
                    source="date")
    elif name in ("geoip", "geo"):
        src = _field(cfg.get("field", "ip"))
        tgt = _strip_brackets(cfg.get("target_field", "geo"))
        _dql(out, f"fieldsAdd {tgt} = ipToGeolocation({src})", matcher)
    elif name == "user_agent":
        src = _field(cfg.get("field", "user_agent"))
        tgt = _strip_brackets(cfg.get("target_field", "user_agent"))
        report.warn("user_agent processor -> UA parsing; confirm the OpenPipeline UA processor.",
                    source="user_agent")
        _dql(out, f"fieldsAdd {tgt} = parseUserAgent({src})", matcher, "TODO confirm UA processor")
    elif name == "set":
        f = _quote_lhs(cfg.get("field", "field"))
        val = cfg.get("value", "")
        if isinstance(val, str) and val.startswith("{{") and val.endswith("}}"):
            _dql(out, f"fieldsAdd {f} = {_field(val.strip('{} '))}", matcher)   # template copy
        else:
            rhs = _dql_str(str(val)) if isinstance(val, str) else val
            _dql(out, f"fieldsAdd {f} = {rhs}", matcher)
    elif name == "rename":
        _dql(out, f"fieldsRename {_strip_brackets(cfg.get('target_field', ''))} = "
                  f"{_field(cfg.get('field', ''))}", matcher)
    elif name == "remove":
        fields = cfg.get("field")
        flds = fields if isinstance(fields, list) else [fields]
        _dql(out, "fieldsRemove " + ", ".join(_field(_strip_brackets(str(x))) for x in flds), matcher)
    elif name == "convert":
        f = _field(cfg.get("field", ""))
        fn = _CONVERT.get(str(cfg.get("type")), "toString")
        tgt = _strip_brackets(cfg.get("target_field", cfg.get("field", "")))
        _dql(out, f"fieldsAdd {tgt} = {fn}({f})", matcher)
    elif name in ("lowercase", "uppercase"):
        f = _field(cfg.get("field", ""))
        _dql(out, f"fieldsAdd {f} = {'lower' if name == 'lowercase' else 'upper'}({f})", matcher)
    elif name == "gsub":
        f = _field(cfg.get("field", ""))
        _dql(out, f"fieldsAdd {f} = replacePattern({f}, {_dql_str(cfg.get('pattern', ''))}, "
                  f"{_dql_str(cfg.get('replacement', ''))})", matcher)
        report.warn("gsub regex -> replacePattern(): verify the RE2/DPL regex dialect.", source="gsub")
    elif name == "json":
        src = _field(cfg.get("field", "message"))
        tgt = _strip_brackets(cfg.get("target_field", cfg.get("field", "parsed")))
        _dql(out, f'fieldsAdd {tgt} = parse({src}, "JSON:obj")', matcher, "TODO confirm JSON parse")
        report.warn("json processor -> DPL JSON parse / jsonPath(); verify the target shape.", source="json")
    elif name == "split":
        f = _field(cfg.get("field", ""))
        tgt = _strip_brackets(cfg.get("target_field", cfg.get("field", "")))
        _dql(out, f"fieldsAdd {tgt} = splitString({f}, {_dql_str(cfg.get('separator', ' '))})", matcher)
    elif name == "fingerprint":
        fields = cfg.get("fields", [])
        tgt = _strip_brackets(cfg.get("target_field", "fingerprint"))
        joined = ", ".join(_field(_strip_brackets(str(x))) for x in fields)
        _dql(out, f"fieldsAdd {tgt} = hashSha256(concat({joined}))", matcher)
        report.info("fingerprint -> hashSha256(); Grail dedup differs, so often unnecessary.")
    elif name == "drop":
        out.append(Stage("drop", matcher=matcher, description="drop processor"))
    elif name == "pipeline":
        report.warn(f"`pipeline` calls sub-pipeline `{cfg.get('name')}`; inline or reference it "
                    "as a separate OpenPipeline.", source="pipeline")
        out.append(Stage("note", description=f"TODO call sub-pipeline: {cfg.get('name')}"))
    elif name == "enrich":
        report.warn("enrich processor -> a Grail lookup table + lookup() stage.", source="enrich")
        _dql(out, f"lookup [fetch <{cfg.get('policy_name', 'policy')}>], "
                  f"sourceField:{_field(cfg.get('field', 'key'))}, lookupField:key", matcher, "TODO")
    elif name in ("script", "foreach"):
        report.manual(f"`{name}` processor has no faithful DQL target; reimplement or drop.",
                      source=name)
        out.append(Stage("manual", matcher=matcher, enabled=False,
                         description=f"{name} processor — custom logic, no DPL target"))
    else:
        report.warn(f"Unsupported ingest processor `{name}`; emitted a comment stub.", source=name)
        out.append(Stage("note", description=f"TODO unsupported processor: {name}"))


def translate_ingest(doc: Dict[str, Any]) -> PipelineResult:
    res = PipelineResult()
    for proc in doc.get("processors", []) or []:
        if not isinstance(proc, dict) or not proc:
            continue
        name = next(iter(proc))
        cfg = proc[name] or {}
        _translate_processor(name, cfg if isinstance(cfg, dict) else {}, res.stages, res.report)
    if doc.get("on_failure"):
        res.report.info("Pipeline has an `on_failure` handler -> map to OpenPipeline default/catch handling.")
    return res


def looks_like_ingest_json(text: str) -> bool:
    t = text.lstrip()
    if not t.startswith("{"):
        return False
    try:
        doc = json.loads(text)
    except ValueError:
        return False
    return isinstance(doc, dict) and "processors" in doc
