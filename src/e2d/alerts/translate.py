"""Parse Watchers / Kibana alerting rules into an `AlertSpec`, then render the
DQL + a plain-English plan.

Reuses the query track for the hard part (the search body -> DQL) and the DQL
linter so the emitted query is validated like every other output.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from e2d.alerts.model import (Action, AlertSpec, Detector, Threshold,
                              TARGET_ANOMALY_DETECTOR, TARGET_WORKFLOW)
from e2d.config import MappingConfig
from e2d.core.query_dsl import convert_query_dsl
from e2d.dashboards.kql import translate_kql
from e2d.dql.validate import lint_into_report
from e2d.report import Report


@dataclass
class AlertResult:
    spec: AlertSpec
    report: Report


# --------------------------------------------------------------------------- #
# shared helpers
# --------------------------------------------------------------------------- #

_CMP = {
    "gt": ">", "gte": ">=", "lt": "<", "lte": "<=", "eq": "==", "not_eq": "!=",
    ">": ">", ">=": ">=", "<": "<", "<=": "<=", "==": "==", "!=": "!=",
    "more than": ">", "greater than": ">", "less than": "<", "fewer than": "<",
    "greater or equals": ">=", "less or equals": "<=", "equals": "==", "not equals": "!=",
    "is above": ">", "is below": "<",
}


def _cmp(op: Any) -> str:
    return _CMP.get(str(op).strip().lower(), str(op))


def _render_value(v: Any, report: Report) -> str:
    """Render a comparison value; flag dynamic mustache thresholds."""
    if isinstance(v, (int, float)):
        return str(v)
    s = str(v)
    if "{{" in s:
        report.warn(f"Threshold is dynamic (`{s}`); set a concrete value in Dynatrace or fetch it "
                    "in a Workflow task.")
        return f'"<dynamic:{s}>"'
    return s if re.fullmatch(r"-?\d+(\.\d+)?", s) else f'"{s}"'


def _san(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9_]", "_", str(name)).strip("_") or "v"


def _alert_condition(comparator: str) -> str:
    """Map a threshold comparator to the analyzer's alertCondition."""
    return "BELOW" if comparator in ("<", "<=") else "ABOVE"


def _find_metric_agg(aggs: Dict[str, Any], alias: str) -> Optional[Tuple[str, Optional[str]]]:
    """Recursively locate a metric aggregation named `alias`; return (dql_func, field)."""
    for name, body in (aggs or {}).items():
        if not isinstance(body, dict):
            continue
        if name == alias:
            for fn, dql in (("avg", "avg"), ("sum", "sum"), ("min", "min"), ("max", "max"),
                            ("value_count", "count"), ("cardinality", "countDistinct")):
                if fn in body:
                    return dql, body[fn].get("field")
        if "aggs" in body:
            found = _find_metric_agg(body["aggs"], alias)
            if found:
                return found
    return None


def is_watcher(doc: dict) -> bool:
    return isinstance(doc, dict) and "trigger" in doc and "input" in doc


def is_rule(doc: dict) -> bool:
    return isinstance(doc, dict) and "rule_type_id" in doc


# --------------------------------------------------------------------------- #
# Watcher
# --------------------------------------------------------------------------- #

def _watcher_search(inp: Dict[str, Any], report: Report) -> Optional[Dict[str, Any]]:
    """Find the search request in a watcher input (plain or chained)."""
    if "search" in inp:
        return inp["search"].get("request", {})
    if "http" in inp:
        report.manual("Watcher `input.http` pulls external config; rebuild as a Workflow HTTP task.")
        return None
    if "chain" in inp:
        request = None
        for item in inp["chain"].get("inputs", []):
            for _name, sub in item.items():
                if "search" in sub:
                    request = sub["search"].get("request", {})
                elif "http" in sub:
                    report.manual("Chained `input.http` pulls external config; rebuild as a Workflow "
                                  "HTTP task and pass its result to the query.")
        return request
    return None


def _data_object_for(indices: List[str], config: MappingConfig, report: Report) -> str:
    for idx in indices or []:
        do = config.resolve_data_object(idx)
        if do and do != "__metrics__":
            return do
    if indices:
        report.warn(f"Indices {indices} did not match a data-object rule; defaulting to `logs`.")
    return "logs"


def _watcher_window(body: Dict[str, Any]) -> Optional[str]:
    """Pull the evaluation window from a `range @timestamp gte now-Xunit`."""
    blob = str(body.get("query", {}))
    m = re.search(r"now-(\d+[smhdw])", blob)
    return m.group(1) if m else None


def _group_fields(body: Dict[str, Any], config: MappingConfig, data_object: str) -> List[str]:
    """Top-level terms aggregation fields become the alert's dimensions."""
    out: List[str] = []
    for _name, agg in (body.get("aggs") or {}).items():
        if isinstance(agg, dict) and "terms" in agg:
            f = agg["terms"].get("field")
            if f:
                out.append(config.resolve_field(f, data_object))
    return out


def _watcher_thresholds(cond: Dict[str, Any], report: Report) -> List[Threshold]:
    if "compare" in cond:
        out = []
        for path, ops in cond["compare"].items():
            subject = "count" if path.endswith(("hits.total", "hits.total.value")) \
                else path.split(".")[-2] if path.endswith(".value") else path.split(".")[-1]
            for op, val in ops.items():
                out.append(Threshold(subject, _cmp(op), _render_value(val, report)))
        return out
    if "script" in cond:
        return _threshold_from_painless(cond["script"], report)
    if "array_compare" in cond:
        out = []
        for _path, body in cond["array_compare"].items():
            metric = str(body.get("path", "value")).split(".")[0]
            for op, spec in body.items():
                if op == "path":
                    continue
                quant = (spec or {}).get("quantifier", "some") if isinstance(spec, dict) else "some"
                val = spec.get("value") if isinstance(spec, dict) else spec
                report.warn(f"`array_compare` quantifier `{quant}` -> fires if "
                            f"{'ANY' if quant == 'some' else 'ALL'} group(s) breach; in Dynatrace this "
                            "is the per-dimension event semantics (or MATCH on an array field) — review.")
                out.append(Threshold(metric, _cmp(op), _render_value(val, report)))
        return out
    report.warn("Watcher condition not recognised; set the threshold manually.")
    return []


_PAINLESS_CMP = re.compile(r"\.(\w+)\.value\s*(>=|<=|>|<|==|!=)\s*params\.(\w+)")


def _threshold_from_painless(script: Dict[str, Any], report: Report) -> List[Threshold]:
    src = script.get("source", "") if isinstance(script, dict) else str(script)
    params = script.get("params", {}) if isinstance(script, dict) else {}
    m = _PAINLESS_CMP.search(src)
    report.warn("Watcher `condition.script` (Painless) approximated; verify the comparison.")
    if m:
        alias, op, pname = m.groups()
        val = params.get(pname, pname)
        quant = "ANY" if "anymatch" in src.lower() else ("ALL" if "allmatch" in src.lower() else "ANY")
        report.info(f"Painless `{quant.lower()}Match` over buckets -> fires if {quant} group breaches "
                    f"`{alias} {op} {val}`.")
        return [Threshold(alias, op, _render_value(val, report))]
    report.manual("Could not extract a threshold from the Painless condition; set it manually.")
    return []


_SECRET_RE = re.compile(r"(password|secret|token|api[_-]?key|routing_key)", re.I)


def _actions_from_watcher(actions: Dict[str, Any], report: Report) -> List[Action]:
    out: List[Action] = []
    for name, body in (actions or {}).items():
        if "email" in body:
            to = ", ".join(body["email"].get("to", []) if isinstance(body["email"].get("to"), list)
                           else [body["email"].get("to", "")])
            out.append(Action("email", to or name))
        elif "webhook" in body:
            wh = body["webhook"]
            host = wh.get("host", name)
            secret = None
            auth = wh.get("auth", {})
            if "basic" in auth:
                secret = f"{name}.auth.basic.password"
            blob = str(wh.get("body", "")) + str(wh.get("headers", ""))
            if _SECRET_RE.search(blob):
                secret = secret or f"{name} (token in body/headers)"
            out.append(Action("webhook", host, secret))
        elif "index" in body:
            out.append(Action("index", body["index"].get("index", name)))
            report.info(f"Action `{name}` writes to an ES index; the Dynatrace event itself is the "
                        "record of history — usually drop this.")
        else:
            out.append(Action("unknown", name))
        if isinstance(body, dict) and "condition" in body:
            report.warn(f"Action `{name}` has its own condition; model it as a per-task condition in a "
                        "Workflow.")
    return out


def _from_watcher(doc: dict, config: MappingConfig, report: Report,
                  name_hint: Optional[str] = None) -> AlertSpec:
    spec = AlertSpec(name=doc.get("metadata", {}).get("name", "") or name_hint or "watcher",
                     source_kind="watcher")
    sched = doc.get("trigger", {}).get("schedule", {})
    spec.schedule = sched.get("interval") or sched.get("cron")
    if "cron" in sched:
        report.info(f"cron `{sched['cron']}` -> set the equivalent Workflow schedule / event interval.")
    spec.suppression = doc.get("throttle_period")

    request = _watcher_search(doc.get("input", {}), report)
    body = (request or {}).get("body", {})
    indices = (request or {}).get("indices", [])
    spec.data_object = _data_object_for(indices, config, report)
    spec.window = _watcher_window(body) or spec.schedule

    spec.thresholds = _watcher_thresholds(doc.get("condition", {}), report)

    if body:
        dql, _viz = convert_query_dsl(body, config, spec.data_object, report)
        if "summarize" not in dql and "makeTimeseries" not in dql and \
           any(t.subject == "count" for t in spec.thresholds):
            dql += "\n| summarize count()"
        spec.dql = dql
        if not spec.group_by:
            spec.group_by = _group_fields(body, config, spec.data_object)

    if "transform" in doc:
        report.warn("Watcher `transform` (Painless) builds a breaching list; in Dynatrace the event's "
                    "dimension split does this — usually unnecessary.")

    spec.detectors = _watcher_detectors(spec, body, report)
    spec.actions = _actions_from_watcher(doc.get("actions", {}), report)
    spec.target = _recommend_target(spec, doc)
    return spec


def _watcher_detectors(spec: AlertSpec, body: Dict[str, Any], report: Report) -> List[Detector]:
    """Turn each watcher threshold into a per-minute anomaly-detector query."""
    out: List[Detector] = []
    base = []  # the search query's own filter, re-expressed for the detector
    m = re.search(r"\| filter (.+?)(?:\n|$)", spec.dql)
    if m:
        base = [m.group(1)]
    for t in spec.thresholds:
        if t.subject == "count":
            out.append(_count_detector("count", base, spec.group_by, t.comparator, t.value,
                                       spec.data_object))
        else:
            agg = _find_metric_agg(body.get("aggs", {}), t.subject)
            if not agg:
                report.warn(f"Could not build an anomaly-detector series for `{t.subject}`; "
                            "set the query manually.")
                continue
            fn, fld = agg
            agg_expr = "count()" if fn == "count" else f"{fn}({fld})"   # count() takes no arg
            parts = [f"fetch {spec.data_object}"]
            if base:
                parts.append("filter " + base[0])
            mt = f"makeTimeseries {t.subject} = {agg_expr}, interval: 1m"
            if spec.group_by:
                mt += f", by: {{{', '.join(spec.group_by)}}}"
            parts.append(mt)
            query = parts[0] + "".join("\n| " + p for p in parts[1:])
            out.append(Detector(title=f"{t.subject} {t.comparator} {t.value}", query=query,
                                alert_condition=_alert_condition(t.comparator), threshold=t.value))
    return out


# --------------------------------------------------------------------------- #
# Kibana alerting rule
# --------------------------------------------------------------------------- #

def _rule_filters(params: Dict[str, Any], config: MappingConfig, data_object: str,
                  report: Report) -> List[str]:
    preds: List[str] = []
    for c in params.get("criteria", []):
        field = c.get("field") or c.get("metric")
        if field and "comparator" in c:
            val = c.get("value")
            rendered = val if isinstance(val, (int, float)) else f'"{val}"'
            preds.append(f"{config.resolve_field(field, data_object)} {_cmp(c['comparator'])} {rendered}")
    fq = params.get("filterQuery")
    if fq:
        kql = translate_kql(fq, config, data_object, report)
        if kql:
            preds.append(kql)
    return preds


def _count_detector(subject: str, base_dql_filter: List[str], group_by: List[str],
                    comparator: str, value: str, data_object: str = "logs") -> Detector:
    """A count threshold -> a per-minute makeTimeseries the detector can evaluate."""
    parts = [f"fetch {data_object}"]
    if base_dql_filter:
        parts.append("filter " + " and ".join(base_dql_filter))
    mt = f"makeTimeseries {subject} = count(), interval: 1m"
    if group_by:
        mt += f", by: {{{', '.join(group_by)}}}"
    parts.append(mt)
    query = parts[0] + "".join("\n| " + p for p in parts[1:])
    return Detector(title=f"{subject} {comparator} {value}", query=query,
                    alert_condition=_alert_condition(comparator), threshold=value)


def _rule_count_dql(params: Dict[str, Any], group_by: List[str], config: MappingConfig,
                    report: Report) -> Tuple[str, List[Threshold], List[Detector]]:
    preds = _rule_filters(params, config, "logs", report)
    lines = ["fetch logs"]
    if preds:
        lines.append("filter " + " and ".join(preds))
    summ = "summarize count()"
    if group_by:
        summ += f", by: {{{', '.join(group_by)}}}"
    lines.append(summ)
    dql = lines[0] + "".join("\n| " + ln for ln in lines[1:])
    cnt = params.get("count", {})
    detectors, thresholds = [], []
    if cnt:
        cmp_ = _cmp(cnt.get("comparator", ">"))
        val = _render_value(cnt.get("value", 0), report)
        thresholds.append(Threshold("count", cmp_, val))
        detectors.append(_count_detector("count", preds, group_by, cmp_, val))
    return dql, thresholds, detectors


def _rule_metric_dql(params: Dict[str, Any], group_by: List[str], config: MappingConfig,
                     report: Report) -> Tuple[str, List[Threshold], List[Detector]]:
    report.warn("Metric-threshold rule: Elastic metric names are passed through — verify each exists "
                "in Dynatrace (a non-`dt.*` key likely needs creating via OpenPipeline).")
    fq = params.get("filterQuery")
    filt = translate_kql(fq, config, None, report) if fq else ""
    by = f", by: {{{', '.join(group_by)}}}" if group_by else ""
    filt_clause = f", filter: {{{filt}}}" if filt else ""

    metrics, thresholds, detectors = [], [], []
    for i, c in enumerate(params.get("criteria", [])):
        metric = c.get("metric", f"metric_{i}")
        agg = c.get("aggType", "avg")
        alias = _san(metric) or f"m{i}"
        metrics.append(f"{alias} = {agg}({metric})")
        dquery = f"timeseries {alias} = {agg}({metric}){by}{filt_clause}, interval: 1m"
        for thr_val in c.get("threshold", []):
            cmp_ = _cmp(c.get("comparator", ">"))
            val = _render_value(thr_val, report)
            thresholds.append(Threshold(alias, cmp_, val))
            detectors.append(Detector(title=f"{metric} {cmp_} {val}", query=dquery,
                                      alert_condition=_alert_condition(cmp_), threshold=val,
                                      metric_key=metric))
        for wv in c.get("warningThreshold", []):
            cmp_ = _cmp(c.get("warningComparator", ">"))
            val = _render_value(wv, report)
            thresholds.append(Threshold(alias, cmp_, val, severity="warning"))
            detectors.append(Detector(title=f"{metric} {cmp_} {val} (warning)", query=dquery,
                                      alert_condition=_alert_condition(cmp_), threshold=val,
                                      severity="warning", metric_key=metric))
    head = f"timeseries {{{', '.join(metrics)}}}{by}{filt_clause}"
    return head, thresholds, detectors


def _actions_from_rule(actions: List[Dict[str, Any]], report: Report) -> List[Action]:
    out: List[Action] = []
    for a in actions or []:
        aid = a.get("id", "")
        params = a.get("params", {})
        kind = "slack" if "slack" in aid.lower() or "message" in params else \
               "email" if "email" in aid.lower() or "to" in params else \
               "webhook" if "webhook" in aid.lower() or "body" in params else "unknown"
        target = ", ".join(params["to"]) if isinstance(params.get("to"), list) else aid
        secret = f"{aid} (credential in the Kibana connector)" if kind == "webhook" else None
        out.append(Action(kind, target, secret))
    return out


def _rule_window(params: Dict[str, Any]) -> Optional[str]:
    ts = params.get("timeSize") or params.get("timeWindowSize")
    tu = params.get("timeUnit") or params.get("timeWindowUnit")
    if not ts:
        crit = (params.get("criteria") or [{}])[0]
        ts, tu = crit.get("timeSize"), crit.get("timeUnit")
    return f"{ts}{tu}" if ts and tu else None


def _rule_group_by(params: Dict[str, Any], config: MappingConfig, data_object: Optional[str]) -> List[str]:
    """Grouping fields, handling both a list (log/metric rules) and the
    `groupBy:"top"|"all"` + `termField` convention (.index-threshold)."""
    g = params.get("groupBy")
    if isinstance(g, str):
        if g == "top" and params.get("termField"):
            tf = params["termField"]
            tf = tf[:-len(".keyword")] if tf.endswith(".keyword") else tf
            return [config.resolve_field(tf, data_object)]
        return []
    return [config.resolve_field(x, data_object) for x in (g or [])]


def _rule_index_threshold(params: Dict[str, Any], group_by: List[str], config: MappingConfig,
                          report: Report) -> Tuple[str, List[Threshold], List[Detector]]:
    """`.index-threshold`: aggType(aggField) over a window, threshold-compared."""
    agg = params.get("aggType", "count")
    field = params.get("aggField")
    expr = "count()" if agg == "count" or not field else f"{agg}({config.resolve_field(field, 'logs')})"
    by = f", by: {{{', '.join(group_by)}}}" if group_by else ""
    dql = f"fetch logs\n| makeTimeseries value = {expr}, interval: 1m{by}"
    cmp_ = _cmp(params.get("thresholdComparator", ">"))
    thresholds, detectors = [], []
    for v in (params.get("threshold") or [])[:1]:
        val = _render_value(v, report)
        thresholds.append(Threshold("value", cmp_, val))
        detectors.append(Detector(title=f"value {cmp_} {val}", query=dql,
                                  alert_condition=_alert_condition(cmp_), threshold=val))
    return dql, thresholds, detectors


def _rule_es_query(params: Dict[str, Any], group_by: List[str], config: MappingConfig,
                   report: Report) -> Tuple[str, List[Threshold], List[Detector]]:
    """`.es-query`: a Query DSL or ES|QL search, count-thresholded over a window."""
    import json
    esql = (params.get("esqlQuery") or {}).get("esql")
    by = f", by: {{{', '.join(group_by)}}}" if group_by else ""
    if esql:
        from e2d.esql.translator import translate_esql
        res = translate_esql(esql, config)
        report.extend(res.report)
        display = res.dql + ("\n| summarize count()" if "summarize" not in res.dql else "")
        detector_q = res.dql + (f"\n| makeTimeseries count = count(), interval: 1m{by}"
                                if "makeTimeseries" not in res.dql else "")
    else:
        filt_clause = ""
        eq = params.get("esQuery")
        if eq:
            try:
                q = json.loads(eq) if isinstance(eq, str) else eq
                fetched, _ = convert_query_dsl(q, config, "logs", report)
                m = re.search(r"\| filter (.+)", fetched)
                filt_clause = ("\n| filter " + m.group(1)) if m else ""
            except Exception as e:
                report.warn(f"Could not parse `.es-query` esQuery ({e}); emitted a bare count.")
        display = f"fetch logs{filt_clause}\n| summarize count()"
        detector_q = f"fetch logs{filt_clause}\n| makeTimeseries count = count(), interval: 1m{by}"
    cmp_ = _cmp(params.get("thresholdComparator", ">"))
    thresholds, detectors = [], []
    for v in (params.get("threshold") or [])[:1]:
        val = _render_value(v, report)
        thresholds.append(Threshold("count", cmp_, val))
        detectors.append(Detector(title=f"count {cmp_} {val}", query=detector_q,
                                  alert_condition=_alert_condition(cmp_), threshold=val))
    return display, thresholds, detectors


def _from_rule(doc: dict, config: MappingConfig, report: Report,
               name_hint: Optional[str] = None) -> AlertSpec:
    spec = AlertSpec(name=doc.get("name") or name_hint or doc.get("id") or "rule", source_kind="rule")
    spec.schedule = doc.get("schedule", {}).get("interval")
    spec.suppression = doc.get("throttle")
    params = doc.get("params", {})
    spec.window = _rule_window(params)
    rtype = doc.get("rule_type_id", "")

    if "metric" in rtype:
        spec.data_object = "metrics"
        spec.group_by = _rule_group_by(params, config, None)
        spec.dql, spec.thresholds, spec.detectors = _rule_metric_dql(params, spec.group_by, config, report)
    elif rtype == ".index-threshold":
        spec.data_object = "logs"
        spec.group_by = _rule_group_by(params, config, "logs")
        spec.dql, spec.thresholds, spec.detectors = _rule_index_threshold(params, spec.group_by, config, report)
    elif rtype == ".es-query":
        spec.data_object = "logs"
        spec.group_by = _rule_group_by(params, config, "logs")
        spec.dql, spec.thresholds, spec.detectors = _rule_es_query(params, spec.group_by, config, report)
    else:  # logs.alert.document.count and similar
        spec.data_object = "logs"
        spec.group_by = _rule_group_by(params, config, "logs")
        spec.dql, spec.thresholds, spec.detectors = _rule_count_dql(params, spec.group_by, config, report)
    spec.actions = _actions_from_rule(doc.get("actions", []), report)
    spec.target = TARGET_ANOMALY_DETECTOR
    return spec


# --------------------------------------------------------------------------- #
# orchestration + recommendation + rendering
# --------------------------------------------------------------------------- #

def _recommend_target(spec: AlertSpec, doc: dict) -> str:
    """A plain threshold is an anomaly detector; orchestration (chained inputs,
    per-action conditions, scripted transforms) additionally needs a Workflow."""
    inp = doc.get("input", {})
    if "chain" in inp or "http" in inp or "transform" in doc or \
       any(a.kind == "webhook" for a in spec.actions):
        return TARGET_WORKFLOW
    return TARGET_ANOMALY_DETECTOR


def translate_alert(text_or_doc: Any, config: Optional[MappingConfig] = None,
                    name: Optional[str] = None) -> AlertResult:
    import json
    config = config or MappingConfig()
    report = Report()
    doc = text_or_doc if isinstance(text_or_doc, dict) else json.loads(text_or_doc)

    if is_rule(doc):
        spec = _from_rule(doc, config, report, name)
    elif is_watcher(doc):
        spec = _from_watcher(doc, config, report, name)
    else:
        report.manual("Not a recognised Watcher or Kibana alerting rule.")
        spec = AlertSpec(name=name or "unknown", source_kind="unknown")

    if spec.dql:
        lint_into_report(spec.dql, report, spec.data_object)
    for d in spec.detectors:        # the detector query is also real DQL — validate it
        lint_into_report(d.query, report, spec.data_object)
    from e2d.alerts.metrics import check_metrics
    check_metrics(spec, report)
    return AlertResult(spec, report)


def render_alert(spec: AlertSpec) -> str:
    L: List[str] = [f"# Alert: {spec.name}", ""]
    L.append(f"Source: **Elastic {spec.source_kind}**  ·  Suggested Dynatrace home: **{spec.target}**")
    L.append("")
    if spec.dql:
        L.append("## Query it evaluates")
        L.append("")
        L.append("```dql")
        L.append(spec.dql)
        L.append("```")
        L.append("")
    L.append("## Firing logic")
    L.append("")
    if spec.thresholds:
        for t in spec.thresholds:
            sev = "" if t.severity == "critical" else f"  _({t.severity})_"
            L.append(f"- Fire when **`{t.subject} {t.comparator} {t.value}`**{sev}")
    else:
        L.append("- _Threshold could not be derived automatically — set it manually._")
    if spec.group_by:
        L.append(f"- Evaluate **per** {', '.join(f'`{g}`' for g in spec.group_by)} (one alert per dimension value)")
    if spec.window:
        L.append(f"- Over a **{spec.window}** window" + (f", checked every **{spec.schedule}**"
                 if spec.schedule and spec.schedule != spec.window else ""))
    elif spec.schedule:
        L.append(f"- Checked every **{spec.schedule}**")
    if spec.suppression:
        L.append(f"- Suppress / dedup for **{spec.suppression}** after firing")
    L.append("")
    if spec.actions:
        L.append("## Notifications")
        L.append("")
        for a in spec.actions:
            line = f"- **{a.kind}** → `{a.target}`"
            if a.secret:
                line += f"  🔐 _credential `{a.secret}` — set a Dynatrace-side secret, never inline_"
            L.append(line)
        L.append("")
    if spec.detectors:
        L.append("## Deployable anomaly detector(s)")
        L.append("")
        L.append(f"`e2d alert --terraform` generates a **`dynatrace_davis_anomaly_detectors`** resource "
                 f"per threshold ({len(spec.detectors)} here). Each runs this 1-minute series:")
        L.append("")
        for d in spec.detectors:
            L.append(f"- **{d.title}** — `alertCondition: {d.alert_condition}`, threshold `{d.threshold}`"
                     + (f"  _({d.severity})_" if d.severity != "critical" else ""))
            L.append(f"  ```dql\n  {d.query.replace(chr(10), chr(10) + '  ')}\n  ```")
        L.append("")
    L.append("## How to build it in Dynatrace")
    L.append("")
    L.append("- Deploy the **Davis anomaly detector(s)** above with `e2d alert --terraform` (or "
             "`migrate` writes them under `alerts_tf/`). They run the DQL and fire on the threshold.")
    if spec.target == TARGET_WORKFLOW:
        L.append("- This alert also needs a **Workflow** (chained inputs / per-action conditions / "
                 "scripted logic): a scheduled DQL task + notification task(s); map webhook auth to a "
                 "stored Dynatrace credential.")
    if spec.actions:
        L.append("- Route notifications via an **alerting profile / Workflow** triggered by the event.")
    L.append("- Verify each item before relying on it.")
    return "\n".join(L) + "\n"
