"""TSVB (Time Series Visual Builder, savedVis type ``metrics``) -> DQL tile.

TSVB stores its whole config in ``params`` (not ``aggs``): a panel ``type``
(timeseries / top_n / metric / gauge / table / markdown) and a list of
``series``, each carrying its own ``metrics[]``, ``filter`` (KQL), and a
``split_mode`` (everything / terms / filters). That maps onto DQL as one
aggregation expression per series — a filtered series becomes ``countIf(pred)``
(or ``fn(if(pred, field))`` for non-count metrics) so several differently
filtered series coexist in a single ``makeTimeseries``/``summarize``.

Pipeline metrics (derivative, moving_average, math, ...) have no direct DQL
translation and are flagged for review instead of silently dropped.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from e2d.config import MappingConfig
from e2d.dashboards.kql import translate_query_string
from e2d.report import Report

# TSVB metric type -> simple DQL aggregation function (field-taking)
_SIMPLE_FUNCS = {
    "avg": "avg", "sum": "sum", "min": "min", "max": "max",
    "std_deviation": "stddev",
}

# Pipeline metrics rendered as array functions over the series (`{r}` = input
# column, `{w}` = window) — timeseries panels only.
_PIPELINE_FN = {
    "derivative": "arrayDiff({r})",
    "serial_diff": "arrayDiff({r})",
    "cumulative_sum": "arrayCumulativeSum({r})",
    "moving_average": "arrayMovingAvg({r}, {w})",
}

# Pipeline / composite metrics with no direct DQL equivalent.
_PIPELINE_TYPES = set(_PIPELINE_FN) | {
    "positive_only", "positive_rate", "avg_bucket", "sum_bucket",
    "min_bucket", "max_bucket", "series_agg", "math", "filter_ratio",
    "static", "top_hit",
}


def _strip_keyword(field: Optional[str]) -> Optional[str]:
    if field and field.endswith(".keyword"):
        return field[: -len(".keyword")]
    return field


def _q(field: str) -> str:
    if field and all(ch.isalnum() or ch in "._" for ch in field):
        return field
    return f"`{field}`"


def _san(label: str, fallback: str) -> str:
    out = "".join(c if (c.isalnum() or c == "_") else "_" for c in (label or "")).strip("_")
    if not out:
        return fallback
    if out[0].isdigit():
        out = "s_" + out
    return out


def _filter_pred(flt: Any, config: MappingConfig, data_object: str,
                 report: Report, where: str) -> Optional[str]:
    """A TSVB filter is ``{query, language}`` (or a bare string, legacy=lucene)."""
    if not flt:
        return None
    if isinstance(flt, str):
        query, language = flt, "lucene"
    else:
        query = flt.get("query", "")
        language = flt.get("language", "kuery")
    return translate_query_string(query, language, config, data_object, report) or None


def _metric_expr(metric: Dict[str, Any], pred: Optional[str], config: MappingConfig,
                 data_object: str, report: Report) -> Optional[str]:
    """DQL aggregation expression for one TSVB metric, with the series filter
    folded in (countIf / fn(if(pred, field)))."""
    mtype = metric.get("type")
    field = _strip_keyword(metric.get("field"))
    mapped = _q(config.resolve_field(field, data_object)) if field else None

    if mtype == "count":
        return f"countIf({pred})" if pred else "count()"
    if mtype == "value_count":
        inner = f"isNotNull({mapped})" if mapped else "true"
        if pred:
            inner = f"({inner}) and ({pred})"
        return f"countIf({inner})"
    if mtype == "cardinality" and mapped:
        arg = f"if({pred}, {mapped})" if pred else mapped
        return f"countDistinct({arg})"
    if mtype in _SIMPLE_FUNCS and mapped:
        arg = f"if({pred}, {mapped})" if pred else mapped
        return f"{_SIMPLE_FUNCS[mtype]}({arg})"
    if mtype == "percentile" and mapped:
        pcts = metric.get("percentiles") or []
        val = pcts[0].get("value", 95) if pcts else 95
        try:
            val = float(val)
            val = int(val) if val == int(val) else val
        except (TypeError, ValueError):
            val = 95
        if len(pcts) > 1:
            report.info("TSVB percentile metric lists several percentiles; only the first "
                        f"({val}) was converted.")
        arg = f"if({pred}, {mapped})" if pred else mapped
        return f"percentile({arg}, {val})"
    return None


def _display_metric(metrics: List[Dict[str, Any]], report: Report, label: str
                    ) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
    """TSVB renders the LAST metric of a series; earlier ones feed pipeline aggs.
    Returns (input metric, pipeline metric or None)."""
    if not metrics:
        return None, None
    last = metrics[-1]
    if last.get("type") in _PIPELINE_FN:
        simple = next((m for m in metrics
                       if m.get("type") not in _PIPELINE_TYPES), None)
        if simple is not None:
            return simple, last
        report.warn(f"TSVB series `{label}` uses `{last.get('type')}` but names no input "
                    "metric; series skipped — rebuild manually.", source=label)
        return None, None
    if last.get("type") in _PIPELINE_TYPES:
        simple = next((m for m in metrics
                       if m.get("type") not in _PIPELINE_TYPES), None)
        report.warn(f"TSVB series `{label}` uses `{last.get('type')}`, which has no DQL "
                    "equivalent; "
                    + ("its input metric was charted instead — compare the tile with "
                       "the original." if simple else "series skipped — rebuild manually."),
                    source=label)
        return simple, None
    return last, None


def _interval(params: Dict[str, Any], report: Report) -> Optional[str]:
    """TSVB interval: '', 'auto' -> omit (DQL auto-bins); '>=1m' -> '1m'."""
    raw = str(params.get("interval") or "").strip()
    if raw in ("", "auto"):
        return None
    if raw.startswith(">="):
        raw = raw[2:]
    units = {"ms": "ms", "s": "s", "m": "m", "h": "h", "d": "d", "w": "w"}
    if raw in units:
        return "1" + units[raw]
    if raw in ("M", "y"):
        report.warn(f"TSVB calendar interval '{raw}' has no DQL duration; defaulted to 1d.")
        return "1d"
    return raw.lower()


def _series_plan(series: List[Dict[str, Any]], config: MappingConfig, data_object: str,
                 report: Report) -> Tuple[List[str], List[str], Dict[str, str], List[str]]:
    """Return (metric expressions 'alias = expr', by-fields, series colors,
    post-aggregation lines) across all series."""
    exprs: List[str] = []
    by_fields: List[str] = []
    colors: Dict[str, str] = {}
    posts: List[str] = []
    seen_aliases: set = set()

    for i, s in enumerate(series):
        if s.get("hidden"):
            continue
        label = s.get("label") or f"series_{i + 1}"
        pred = _filter_pred(s.get("filter"), config, data_object, report,
                           f"series `{label}`")
        metric, pipe = _display_metric(s.get("metrics") or [], report, label)
        if metric is None:
            continue

        split_mode = s.get("split_mode") or "everything"
        if split_mode == "filters":
            if pipe is not None:
                report.warn(f"TSVB series `{label}` combines `{pipe.get('type')}` with split "
                            "filters; the input metric was charted instead.", source=label)
            for j, f in enumerate(s.get("split_filters") or []):
                fpred = _filter_pred(f.get("filter"), config, data_object, report,
                                     f"series `{label}` split filter")
                parts = [p for p in (pred, fpred) if p]
                combined = " and ".join(f"({p})" if len(parts) > 1 else p for p in parts) or None
                expr = _metric_expr(metric, combined, config, data_object, report)
                if expr is None:
                    report.warn(f"TSVB metric `{metric.get('type')}` in series `{label}` is not "
                                "supported; split filter skipped — review.", source=label)
                    continue
                flabel = f.get("label") or f"{label}_{j + 1}"
                exprs.append(f"{_uniq(_san(flabel, f'f_{j + 1}'), seen_aliases)} = {expr}")
            continue

        if split_mode == "terms":
            tf = _strip_keyword(s.get("terms_field"))
            if tf:
                bf = _q(config.resolve_field(tf, data_object))
                if bf not in by_fields:
                    by_fields.append(bf)
            else:
                report.info(f"TSVB series `{label}` splits by terms but names no field; "
                            "treated as unsplit.")

        expr = _metric_expr(metric, pred, config, data_object, report)
        if expr is None:
            report.warn(f"TSVB metric `{metric.get('type')}` in series `{label}` has no DQL "
                        "translation; series skipped — review.", source=label)
            continue
        alias = _uniq(_san(label, f'series_{i + 1}'), seen_aliases)
        if pipe is not None:
            # chart the pipeline result under the series label, computed from
            # a source column via the matching array function
            src = _uniq(f"{alias}_src", seen_aliases)
            exprs.append(f"{src} = {expr}")
            window = (pipe.get("window") or 5)
            posts.append(f"fieldsAdd {alias} = "
                         + _PIPELINE_FN[pipe["type"]].format(r=src, w=window))
            report.info(f"TSVB `{pipe.get('type')}` in series `{label}` rendered as an "
                        "array function over the timeseries.")
        else:
            exprs.append(f"{alias} = {expr}")
        # an explicit series color survives only for unsplit series — split
        # series take their names from the dimension values, not the label
        if split_mode != "terms" and s.get("color"):
            colors[alias] = s["color"]

    return exprs, by_fields, colors, posts


def _uniq(alias: str, seen: set) -> str:
    out, n = alias, 2
    while out in seen:
        out = f"{alias}_{n}"
        n += 1
    seen.add(out)
    return out


def _timeseries_viz(series: List[Dict[str, Any]]) -> str:
    first = next((s for s in series if not s.get("hidden")), None) or {}
    chart = first.get("chart_type", "line")
    if chart == "bar":
        return "barChart"
    try:
        fill = float(first.get("fill", 0) or 0)
    except (TypeError, ValueError):
        fill = 0.0
    return "areaChart" if fill >= 0.5 else "lineChart"


def convert_tsvb(params: Dict[str, Any], config: MappingConfig, report: Report,
                 index_title: Optional[str] = None) -> Dict[str, Any]:
    """Convert a TSVB ``params`` block.

    Returns either ``{"kind": "markdown", "content": ...}`` or
    ``{"kind": "data", "dql": ..., "visualization": ..., "settings": {...}}``.
    """
    ptype = params.get("type", "timeseries")

    if ptype == "markdown":
        return {"kind": "markdown", "content": params.get("markdown", "") or ""}

    data_object = "logs"
    if index_title:
        do = config.resolve_data_object(index_title)
        if do and do != "__metrics__":
            data_object = do
        elif do is None:
            report.warn(f"TSVB index `{index_title}` matched no data-object rule; "
                        "defaulting to `logs`. Add an index_map rule.", source=index_title)
    else:
        report.warn("TSVB panel has no resolvable index pattern; defaulting to `logs`.")

    lines = [f"fetch {data_object}"]
    panel_pred = _filter_pred(params.get("filter"), config, data_object, report, "panel")
    if panel_pred:
        lines.append(f"filter {panel_pred}")

    series = params.get("series") or []
    exprs, by_fields, colors, posts = _series_plan(series, config, data_object, report)
    if not exprs:
        report.warn("TSVB panel had no convertible series; emitted a placeholder.")
        return {"kind": "markdown",
                "content": "_TSVB panel — no convertible series; rebuild manually._"}
    if posts and ptype != "timeseries":
        report.warn(f"A derivative/moving-average metric needs a time axis; this `{ptype}` "
                    "panel charts its input metric instead — compare with the original.")
        posts = []
    metrics = ", ".join(exprs)
    settings: Dict[str, Any] = {}
    if ptype in ("timeseries", "top_n") and colors:
        from e2d.dashboards.colors import apply_series_colors
        apply_series_colors(settings, colors)

    if ptype == "timeseries":
        body = f"makeTimeseries {{{metrics}}}"
        interval = _interval(params, report)
        if interval:
            body += f", interval: {interval}"
        if by_fields:
            body += f", by: {{{', '.join(by_fields)}}}"
        lines.append(body)
        lines.extend(posts)
        viz = _timeseries_viz(series)

    elif ptype == "top_n":
        body = f"summarize {metrics}"
        if by_fields:
            body += f", by: {{{', '.join(by_fields)}}}"
        lines.append(body)
        alias = exprs[0].split(" = ")[0]
        if by_fields:
            lines.append(f"sort {alias} desc")
            lines.append("limit 10")
        viz = "categoricalBarChart"

    elif ptype in ("metric", "gauge"):
        if by_fields:
            report.info("TSVB metric/gauge panel had a terms split; the split was dropped to "
                        "keep a single value.")
        lines.append(f"summarize {metrics}")
        viz = "gauge" if ptype == "gauge" else "singleValue"
        if ptype == "gauge":
            gmax = params.get("gauge_max")
            if gmax not in (None, ""):
                try:
                    settings = {"valueBoundaries": {
                        "min": {"mode": "custom", "value": 0},
                        "max": {"mode": "custom", "value": float(gmax)}}}
                except (TypeError, ValueError):
                    pass

    elif ptype == "table":
        pivot = _strip_keyword(params.get("pivot_id"))
        if pivot:
            bf = _q(config.resolve_field(pivot, data_object))
            if bf not in by_fields:
                by_fields.insert(0, bf)
        body = f"summarize {metrics}"
        if by_fields:
            body += f", by: {{{', '.join(by_fields)}}}"
        lines.append(body)
        viz = "table"

    else:
        report.warn(f"TSVB panel type `{ptype}` is not supported; converted as a table — review.")
        body = f"summarize {metrics}"
        if by_fields:
            body += f", by: {{{', '.join(by_fields)}}}"
        lines.append(body)
        viz = "table"

    dql = lines[0] + "".join("\n| " + ln for ln in lines[1:])
    return {"kind": "data", "dql": dql, "visualization": viz, "settings": settings,
            "data_object": data_object}
