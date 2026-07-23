"""Lens saved-object -> DQL-backed tile.

Lens stores its config as `attributes.state.datasourceStates.formBased.layers[].columns`.
Each column is an `operationType` that is either a *bucket* (date_histogram, terms)
or a *metric* (count, avg, sum, percentile, unique_count, ...). That is exactly the
`AggTree` shape, so Lens reuses the shared aggregation core; this module is mostly a
column reader + a visualizationType -> Dynatrace visualization map.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

from e2d.config import MappingConfig
from e2d.core.agg_tree import AggTree, Bucket, Metric, Pipeline, PostExpr, apply_to_query
from e2d.core.dql_builder import Query
from e2d.dashboards.kql import translate_kql, translate_query_string
from e2d.report import Report

# Lens column operationType -> our metric function (None = it is a bucket / special)
_METRIC_OPS = {
    "count": "count",
    "unique_count": "countDistinct",
    "avg": "avg", "average": "avg",
    "sum": "sum", "min": "min", "max": "max", "median": "median",
    "percentile": "percentile",
    "last_value": "takeLast",
}
_BUCKET_OPS = {"date_histogram", "terms"}

# Lens reference-based (pipeline) columns -> agg-tree Pipeline op.
_LENS_PIPELINE = {
    "moving_average": "moving_avg",
    "cumulative_sum": "cumulative_sum",
    "differences": "derivative",
    "counter_rate": "derivative",
}

_VIZ = {
    "lnsMetric": "singleValue",
    "lnsDatatable": "table",
    "lnsPie": "pieChart",
    "lnsLegacyMetric": "singleValue",
}


def _interval(params: Dict[str, Any], report: Report) -> str:
    raw = str(params.get("interval", "auto"))
    if raw == "auto":
        report.info("Lens date_histogram interval was 'auto'; defaulted to 1h.")
        return "1h"
    units = {"ms": "ms", "s": "s", "m": "m", "h": "h", "d": "d", "w": "w"}
    if raw in units:
        return "1" + units[raw]
    return raw.lower()


def _columns(state: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    layers = state.get("datasourceStates", {}).get("formBased", {}).get("layers", {})
    cols: Dict[str, Dict[str, Any]] = {}
    for layer in layers.values():
        cols.update(layer.get("columns", {}))
    return cols


def _alias(col: Dict[str, Any], col_id: str) -> str:
    label = col.get("label") or col_id
    out = "".join(c if (c.isalnum() or c == "_") else "_" for c in label).strip("_")
    if not out or out[0].isdigit():
        out = "m_" + out
    return out


def lens_to_agg_tree(state: Dict[str, Any], config: MappingConfig, data_object: str,
                     report: Report) -> AggTree:
    from e2d.core.filter_ir import Raw

    cols = _columns(state)
    tree = AggTree()
    alias_by_id = {cid: _alias(c, cid) for cid, c in cols.items()}

    # A formula column compiles into hidden helper columns (`<id>X0`, `<id>X1`, …)
    # holding its parts; we translate the formula string itself, so skip those.
    formula_ids = {cid for cid, c in cols.items()
                   if c.get("operationType") == "formula"}
    helper = re.compile("^(?:" + "|".join(re.escape(f) for f in formula_ids) + r")X\d+$") \
        if formula_ids else None

    filter_metrics: List[Metric] = []      # from `filters` columns -> countIf per label
    plain_metrics: List[Metric] = []

    for cid, col in cols.items():
        if helper is not None and helper.match(cid):
            continue
        op = col.get("operationType")
        params = col.get("params", {}) or {}
        field = col.get("sourceField")
        if op == "date_histogram":
            tree.buckets.append(Bucket("dateHistogram", field=field, interval=_interval(params, report)))
        elif op == "terms":
            order_alias, order_dir = _terms_order(params, alias_by_id)
            tree.buckets.append(Bucket("terms", field=field, size=params.get("size"),
                                       order_alias=order_alias, order_dir=order_dir))
        elif op == "filters":
            # a labelled-filter split (same shape as the legacy `filters` agg)
            for f in params.get("filters", []):
                inp = f.get("input", {}) or {}
                label = f.get("label") or inp.get("query") or "filter"
                pred = translate_query_string(inp.get("query", ""), inp.get("language"),
                                              config, data_object, report) or "true"
                filter_metrics.append(Metric(alias=_san(label), func="countIf", predicate=Raw(pred)))
        elif op in _METRIC_OPS:
            fn = _METRIC_OPS[op]
            field_arg = None if (field in (None, "___records___")) else field
            metric = Metric(alias=alias_by_id[cid], func=fn, field=field_arg)
            if fn == "percentile":
                metric.arg = params.get("percentile", 95)
            if fn == "takeLast":
                metric.note = ("Lens last_value maps to takeLast(); DQL takes the last record "
                               "in scan order, not by the Lens sort field — review.")
            flt = col.get("filter")                       # column-level filtered metric
            if flt and flt.get("query"):
                pred = translate_query_string(flt["query"], flt.get("language"),
                                              config, data_object, report)
                if fn == "count":
                    metric.func = "countIf"
                    metric.predicate = Raw(pred)
                elif pred:
                    # fn(if(pred, field)) — the aggregation ignores nulls
                    metric.predicate = Raw(pred)
            plain_metrics.append(metric)
        elif op in _LENS_PIPELINE:
            refs = col.get("references") or []
            ref_alias = alias_by_id.get(refs[0]) if refs else None
            if ref_alias:
                note = ("Lens counter_rate approximated with arrayDiff() (no rate "
                        "normalisation); review." if op == "counter_rate" else None)
                tree.post.append(PostExpr(
                    alias=alias_by_id[cid],
                    pipeline=Pipeline(op=_LENS_PIPELINE[op], ref=ref_alias,
                                      window=params.get("window"), note=note)))
            else:
                report.warn(f"Lens `{op}` column references no source column; skipped.")
        elif op == "formula":
            from e2d.dashboards.lens_formula import FormulaError, translate_formula
            f = str(params.get("formula") or "")
            try:
                ms, posts = translate_formula(f, alias_by_id[cid], config, data_object, report)
                plain_metrics.extend(ms)
                tree.post.extend(posts)
                report.info(f"Lens formula `{f}` translated to DQL.")
            except FormulaError as e:
                report.warn(f"Lens formula `{f}` could not be translated ({e}); emitted a "
                            "count() placeholder — rewrite the expression in DQL.")
                plain_metrics.append(Metric(alias=alias_by_id[cid], func="count"))
        elif op == "static_value":
            val = params.get("value")
            try:
                val = float(val)
                val = int(val) if val == int(val) else val
            except (TypeError, ValueError):
                val = 0
            tree.post.append(PostExpr(alias=alias_by_id[cid], expr=str(val)))
            report.info(f"Lens static value column rendered as `fieldsAdd {alias_by_id[cid]} = {val}`.")
        elif op == "math":
            report.warn(f"Lens `math` column `{alias_by_id[cid]}` outside a formula needs a "
                        "manual DQL expression; emitted count() placeholder.")
            plain_metrics.append(Metric(alias=alias_by_id[cid], func="count"))
        else:
            report.warn(f"Unsupported Lens operationType `{op}`; column skipped.")

    # A `filters` split becomes one column per filter (x metric). A plain count
    # folds into countIf(pred); any other metric becomes fn(if(pred, field)).
    if filter_metrics:
        others = [m for m in plain_metrics if not (m.func == "count" and m.predicate is None)]
        if not others:
            tree.metrics.extend(filter_metrics)
        else:
            for fm in filter_metrics:
                for pm in plain_metrics:
                    alias = fm.alias if len(plain_metrics) == 1 \
                        else _san(f"{fm.alias}_{pm.alias}")
                    if m_is_countlike(pm):
                        pred = _and_preds(fm.predicate, pm.predicate)
                        tree.metrics.append(Metric(alias=alias, func="countIf", predicate=pred))
                    else:
                        pred = _and_preds(fm.predicate, pm.predicate)
                        tree.metrics.append(Metric(alias=alias, func=pm.func, field=pm.field,
                                                   arg=pm.arg, predicate=pred, note=pm.note))
            report.info("Lens filters split combined with its metrics as one column per "
                        "filter (fn(if(pred, field)) for non-count metrics).")
    else:
        tree.metrics.extend(plain_metrics)
    return tree


def m_is_countlike(m: Metric) -> bool:
    return m.func in ("count", "countIf")


def _and_preds(a, b):
    from e2d.core.filter_ir import Raw
    if a is None:
        return b
    if b is None:
        return a
    return Raw(f"({_raw(a)}) and ({_raw(b)})")


def _raw(node) -> str:
    return getattr(node, "dql", None) or str(node)


def _san(label: str) -> str:
    out = "".join(c if (c.isalnum() or c == "_") else "_" for c in (label or "")).strip("_")
    if not out or out[0].isdigit():
        out = "f_" + out
    return out


def _terms_order(params: Dict[str, Any], alias_by_id: Dict[str, str]) -> Tuple[Optional[str], str]:
    ob = params.get("orderBy", {})
    direction = params.get("orderDirection", "desc")
    if isinstance(ob, dict) and ob.get("type") == "column":
        return alias_by_id.get(ob.get("columnId"), None), direction
    return None, direction


def dt_visualization(visualization_type: str) -> str:
    if visualization_type in _VIZ:
        return _VIZ[visualization_type]
    if visualization_type == "lnsXY":
        return "lineChart"  # refined by series type in convert_lens
    return "table"


def _lens_series_colors(state: Dict[str, Any]) -> Dict[str, str]:
    """Explicit per-series colors from lnsXY layer yConfig -> {alias: color}."""
    cols = _columns(state)
    alias_by_id = {cid: _alias(c, cid) for cid, c in cols.items()}
    out: Dict[str, str] = {}
    for layer in (state.get("visualization", {}) or {}).get("layers", []) or []:
        for yc in layer.get("yConfig", []) or []:
            color = yc.get("color")
            alias = alias_by_id.get(yc.get("forAccessor"))
            if color and alias:
                out[alias] = color
    return out


def convert_lens(lens_attrs: Dict[str, Any], references: List[Dict[str, Any]],
                 index_title: Optional[str], config: MappingConfig, report: Report
                 ) -> Tuple[str, str, str, Dict[str, Any]]:
    """Return (dql, dt_visualization, title, visualizationSettings)."""
    state = lens_attrs.get("state", {}) or {}
    title = lens_attrs.get("title", "") or ""
    vtype = lens_attrs.get("visualizationType", "")

    data_object = "logs"
    if index_title:
        do = config.resolve_data_object(index_title)
        if do and do != "__metrics__":
            data_object = do
        elif do is None:
            report.warn(f"Lens index `{index_title}` matched no data-object rule; defaulting to logs.")

    query = Query(data_object=data_object)
    # base filter: state.query (kuery) + state.filters
    q = state.get("query", {})
    if isinstance(q, dict) and q.get("query"):
        query.add_filter(translate_kql(q["query"], config, data_object, report))

    tree = lens_to_agg_tree(state, config, data_object, report)
    viz_hint = apply_to_query(tree, query, config, data_object, report)

    visualization = dt_visualization(vtype)
    if vtype == "lnsXY":
        if viz_hint == "lineChart":   # has a time bucket -> genuine time series
            series = state.get("visualization", {}).get("preferredSeriesType", "line")
            visualization = {"bar": "barChart", "bar_stacked": "barChart", "bar_horizontal": "barChart",
                             "area": "areaChart", "area_stacked": "areaChart"}.get(series, "lineChart")
        else:                         # categorical (no time axis) -> bar by category
            report.info("lnsXY without a date histogram is categorical; using categoricalBarChart "
                        "(a time-axis chart would fail to render).")
            visualization = "categoricalBarChart"
    elif vtype == "lnsMetric":
        visualization = "singleValue"

    viz_settings: Dict[str, Any] = {}
    if visualization in ("lineChart", "areaChart", "barChart", "categoricalBarChart"):
        colors = _lens_series_colors(state)
        if colors:
            from e2d.dashboards.colors import apply_series_colors
            apply_series_colors(viz_settings, colors)
    return query.render(), visualization, title, viz_settings
