"""Translate Kibana legacy-visualization aggregations + searchSource filters
into a DQL query body.

A legacy visualization is a list of `aggs`, each tagged with a `schema`:
  * metric  schema -> the value (count, cardinality, avg, ...)
  * bucket  schema (segment/group/bucket/split) -> grouping
    - terms          -> summarize ..., by:{field} | sort | limit
    - date_histogram -> makeTimeseries ..., interval:
    - filters        -> one countIf(<kql>) per labelled filter

The result is a structured `AggPlan` the converter turns into DQL command lines.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from e2d.config import MappingConfig
from e2d.dashboards.kql import translate_kql, translate_query_string
from e2d.report import Report


@dataclass
class AggPlan:
    mode: str = "summarize"          # summarize | makeTimeseries | single
    metrics: List[str] = field(default_factory=list)   # "alias = expr"
    by_fields: List[str] = field(default_factory=list)
    interval: Optional[str] = None
    sort: Optional[Tuple[str, str]] = None  # (alias, "desc"/"asc")
    limit: Optional[int] = None
    viz_hint: str = "table"          # structural hint -> Dynatrace visualization
    post: List[str] = field(default_factory=list)      # commands after the aggregation


_METRIC_FUNCS = {
    "avg": "avg", "sum": "sum", "min": "min", "max": "max", "median": "median",
    "std_dev": "stddev",
}

# Legacy pipeline aggregation -> DQL array function over the timeseries.
# `{r}` = referenced metric alias, `{w}` = moving window.
_PIPELINE_FN = {
    "cumulative_sum": "arrayCumulativeSum({r})",
    "derivative": "arrayDiff({r})",
    "serial_diff": "arrayDiff({r})",
    "moving_avg": "arrayMovingAvg({r}, {w})",
    "moving_fn": "arrayMovingAvg({r}, {w})",
}


def _q(field: str) -> str:
    if field and all(ch.isalnum() or ch in "._" for ch in field):
        return field
    return f"`{field}`"


def _sanitize_alias(label: str, fallback: str) -> str:
    label = (label or "").strip() or fallback
    out = []
    for ch in label:
        out.append(ch if (ch.isalnum() or ch == "_") else "_")
    s = "".join(out).strip("_")
    if not s or s[0].isdigit():
        s = "m_" + s
    return s


def _normalize_es_interval(params: Dict[str, Any], report: Report) -> str:
    raw = str(params.get("used_interval") or params.get("interval") or "1h").strip()
    units = {"ms": "ms", "s": "s", "m": "m", "h": "h", "d": "d", "w": "w"}
    if raw in ("auto", ""):
        report.info("date_histogram interval was 'auto'; defaulted to 1h.")
        return "1h"
    if raw in units:  # single unit letter = 1 of that unit
        return "1" + units[raw]
    if raw in ("M", "y"):
        report.warn(f"Calendar interval '{raw}' has no DQL duration; defaulted to 1d.")
        return "1d"
    # already like 10m / 1h
    return raw.lower()


def _metric_expr(agg: Dict[str, Any], config: MappingConfig, data_object: Optional[str],
                 report: Report, pred: Optional[str] = None) -> Tuple[str, str]:
    """Return (alias, dql_expression) for a metric agg. When `pred` is given the
    metric is restricted to matching records: count -> countIf(pred), field
    functions -> fn(if(pred, field)) (the aggregation ignores the nulls)."""
    atype = agg.get("type")
    params = agg.get("params", {})
    custom = params.get("customLabel")
    fid = str(agg.get("id", "1"))
    field_name = params.get("field")
    mapped = config.resolve_field(field_name, data_object) if field_name else None

    def arg() -> str:
        return f"if({pred}, {_q(mapped)})" if pred else _q(mapped)

    if atype == "count":
        return _sanitize_alias(custom, "count"), (f"countIf({pred})" if pred else "count()")
    if atype == "cardinality":
        alias = _sanitize_alias(custom, f"distinct_{field_name or fid}")
        return alias, f"countDistinct({arg()})"
    if atype in _METRIC_FUNCS:
        alias = _sanitize_alias(custom, f"{atype}_{field_name or fid}")
        return alias, f"{_METRIC_FUNCS[atype]}({arg()})"
    if atype == "percentiles":
        pcts = params.get("percents", [95])
        p = pcts[0] if pcts else 95
        alias = _sanitize_alias(custom, f"p{p}_{field_name or fid}")
        report.info("percentiles agg uses the first percentile; add more manually if needed.")
        return alias, f"percentile({arg()}, {p})"
    report.warn(f"Unsupported metric agg `{atype}`; emitted count() as a placeholder.")
    return _sanitize_alias(custom, f"metric_{fid}"), (f"countIf({pred})" if pred else "count()")


def _pipeline_metric(m: Dict[str, Any], atype: str, all_aggs: List[Dict[str, Any]],
                     plan: AggPlan, dh_present: bool, config: MappingConfig,
                     data_object: Optional[str], report: Report) -> None:
    """A pipeline metric (cumulative_sum, derivative, moving_avg, ...) reads
    another metric. Emit that input metric, then — when a date_histogram makes
    the series ordered — a `fieldsAdd` array function over it."""
    params = m.get("params", {})
    under = params.get("customMetric")
    if isinstance(under, str):
        try:
            under = json.loads(under)
        except ValueError:
            under = None
    if not isinstance(under, dict) or not under:
        ref = params.get("metricAgg")
        if ref and ref != "custom":
            under = next((a for a in all_aggs if str(a.get("id")) == str(ref)), None)
    if not isinstance(under, dict) or not under:
        under = {"type": "count", "id": m.get("id", "1"), "params": {}}

    ualias, uexpr = _metric_expr(under, config, data_object, report)
    entry = f"{_q(ualias)} = {uexpr}"
    if entry not in plan.metrics:
        plan.metrics.append(entry)
    if not dh_present:
        report.warn(f"Pipeline agg `{atype}` needs an ordered series (a date_histogram); "
                    "only its input metric was emitted — review.")
        return
    alias = _sanitize_alias(params.get("customLabel"), f"{atype}_{ualias}")
    window = params.get("window") or 5
    plan.post.append(f"fieldsAdd {_q(alias)} = "
                     + _PIPELINE_FN[atype].format(r=_q(ualias), w=window))
    report.info(f"Pipeline agg `{atype}` rendered as an array function over the timeseries.")


def build_agg_plan(aggs: List[Dict[str, Any]], config: MappingConfig,
                   data_object: Optional[str], report: Report) -> AggPlan:
    metrics = [a for a in aggs if a.get("schema") == "metric" and a.get("enabled", True)]
    buckets = [a for a in aggs
               if a.get("schema") in ("segment", "group", "bucket", "split")
               and a.get("enabled", True)]

    plan = AggPlan()
    if not metrics:
        metrics = [{"type": "count", "id": "1", "params": {}}]

    # --- filters bucket: one countIf per labelled filter --------------------
    filters_bucket = next((b for b in buckets if b.get("type") == "filters"), None)
    if filters_bucket:
        # one column per filter x metric: count -> countIf, others -> fn(if(pred, f))
        simple_metrics = [m for m in metrics if m.get("type") not in _PIPELINE_FN]
        for f in filters_bucket.get("params", {}).get("filters", []):
            inp = f.get("input", {})
            label = f.get("label") or inp.get("query") or "filter"
            pred = translate_query_string(inp.get("query", ""), inp.get("language"),
                                          config, data_object, report) or "true"
            flabel = _sanitize_alias(label, "filter")
            for m in simple_metrics or [{"type": "count", "id": "1", "params": {}}]:
                malias, mexpr = _metric_expr(m, config, data_object, report, pred=pred)
                alias = flabel if len(simple_metrics) <= 1 else f"{flabel}_{malias}"
                plan.metrics.append(f"{_q(alias)} = {mexpr}")
        plan.mode = "summarize"
        plan.viz_hint = "categorical"
        # any other (terms) buckets become by-fields
        buckets = [b for b in buckets if b is not filters_bucket]

    # --- metric expressions (when not already produced by filters) ----------
    dh_present = any(b.get("type") == "date_histogram" for b in buckets)
    if not plan.metrics:
        for m in metrics:
            atype = m.get("type")
            if atype in _PIPELINE_FN:
                _pipeline_metric(m, atype, aggs, plan, dh_present, config,
                                 data_object, report)
                continue
            alias, expr = _metric_expr(m, config, data_object, report)
            plan.metrics.append(f"{_q(alias)} = {expr}")
    if not plan.metrics:
        plan.metrics.append("count = count()")
    primary_alias = plan.metrics[0].split(" = ")[0]

    # --- date_histogram -> makeTimeseries -----------------------------------
    dh = next((b for b in buckets if b.get("type") == "date_histogram"), None)
    terms = [b for b in buckets if b.get("type") == "terms"]

    if dh is not None:
        plan.mode = "makeTimeseries"
        plan.interval = _normalize_es_interval(dh.get("params", {}), report)
        plan.viz_hint = "lineChart"
        for tb in terms:
            f = tb.get("params", {}).get("field")
            if f:
                plan.by_fields.append(_q(config.resolve_field(f, data_object)))
        return plan

    # --- terms -> summarize by + sort + limit -------------------------------
    if terms:
        for tb in terms:
            f = tb.get("params", {}).get("field")
            if f:
                plan.by_fields.append(_q(config.resolve_field(f, data_object)))
        first = terms[0].get("params", {})
        size = first.get("size")
        order = first.get("order", "desc")
        if size:
            plan.sort = (primary_alias, order)
            plan.limit = int(size)
        plan.mode = "summarize"
        plan.viz_hint = "categorical" if plan.viz_hint == "table" else plan.viz_hint
        return plan

    # --- no buckets ---------------------------------------------------------
    if plan.mode != "summarize" or not plan.by_fields:
        if not filters_bucket and not terms and not dh:
            plan.viz_hint = "single"
    return plan


# --------------------------------------------------------------------------- #
# searchSource filter[] (Elasticsearch filter DSL meta) -> DQL predicate
# --------------------------------------------------------------------------- #

def translate_search_filters(filters: List[Dict[str, Any]], config: MappingConfig,
                             data_object: Optional[str], report: Report) -> List[str]:
    preds: List[str] = []
    for fl in filters:
        meta = fl.get("meta", {})
        if meta.get("disabled"):
            continue
        key = meta.get("key")
        ftype = meta.get("type")
        negate = meta.get("negate", False)
        pred = None
        if key and key.endswith(".keyword"):
            key = key[: -len(".keyword")]
        mapped = config.resolve_field(key, data_object) if key else None
        if ftype == "exists":
            pred = f"isNotNull({_q(mapped)})"
        elif ftype == "phrase":
            val = meta.get("params", {}).get("query", meta.get("value"))
            pred = f"{_q(mapped)} == {_lit(val)}"
        elif ftype == "phrases":
            vals = meta.get("params", []) or []
            items = ", ".join(_lit(v) for v in vals)
            pred = f"in({_q(mapped)}, {{{items}}})"
        elif ftype == "range":
            rng = meta.get("params", {})
            parts = []
            if "gte" in rng:
                parts.append(f"{_q(mapped)} >= {_lit(rng['gte'])}")
            if "gt" in rng:
                parts.append(f"{_q(mapped)} > {_lit(rng['gt'])}")
            if "lte" in rng:
                parts.append(f"{_q(mapped)} <= {_lit(rng['lte'])}")
            if "lt" in rng:
                parts.append(f"{_q(mapped)} < {_lit(rng['lt'])}")
            pred = " and ".join(parts) if parts else None
        elif ftype == "combined":
            # Kibana 8 combined filter: meta.params is a list of sub-filters
            # joined by meta.relation (AND/OR).
            rel = str(meta.get("relation", "AND")).strip().lower()
            rel = rel if rel in ("and", "or") else "and"
            sub = translate_search_filters(meta.get("params") or [], config,
                                           data_object, report)
            pred = f" {rel} ".join(f"({p})" for p in sub) if sub else None
        elif ftype == "custom" or (ftype is None and fl.get("query")):
            # pinned/custom filter carrying raw Elasticsearch query DSL
            from e2d.core.filter_ir import emit_filter
            from e2d.core.query_dsl import parse_query
            node = parse_query(fl.get("query"), config, data_object, report)
            pred = emit_filter(node, config, data_object, report) if node is not None else None
            if pred is None:
                report.warn(f"Custom filter on `{key}` could not be translated; skipped.",
                            source=str(key))
        else:
            report.warn(f"Unsupported filter type `{ftype}` on `{key}`; skipped.", source=str(key))
            continue
        if pred is None:
            continue
        preds.append(f"not ({pred})" if negate else pred)
    return preds


def _lit(v: Any) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return str(v)
    s = str(v)
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'
