"""Dialect-neutral aggregation model + translation to DQL.

Elasticsearch `aggs`, Lens `columns`, watcher `input.search` aggs and transform
`pivot` all describe the same thing: a set of metrics computed over a set of
buckets. Front-ends build an `AggTree`; `apply_to_query` turns it into the right
DQL (`summarize` vs `makeTimeseries`) on a `Query`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from e2d.config import MappingConfig
from e2d.core.dql_builder import Query, quote_field
from e2d.core.filter_ir import Node, emit_filter
from e2d.report import Report


@dataclass
class Metric:
    alias: str
    func: str                      # count|countDistinct|countIf|avg|sum|min|max|median|percentile
    field: Optional[str] = None
    arg: Optional[float] = None    # e.g. percentile rank
    predicate: Optional[Node] = None   # for countIf
    note: Optional[str] = None


@dataclass
class Bucket:
    kind: str                      # "terms" | "dateHistogram"
    field: Optional[str] = None
    interval: Optional[str] = None     # for dateHistogram (DQL duration)
    size: Optional[int] = None         # for terms
    order_alias: Optional[str] = None  # metric alias to sort by
    order_dir: str = "desc"


@dataclass
class Pipeline:
    """An Elasticsearch *pipeline* aggregation (derivative, moving_fn, *_bucket …)
    reduced to its DQL shape. `kind` is `parent` (operates along an ordered series
    — needs a date_histogram/makeTimeseries) or `sibling` (collapses a series to a
    scalar). `op` selects the DQL array function; `ref` is the metric alias it
    reads."""
    op: str                        # derivative|cumulative_sum|moving_avg|avg_bucket|…
    ref: str                       # referenced metric alias (resolved buckets_path)
    kind: str = "parent"           # parent | sibling
    window: Optional[int] = None   # moving_* window size
    percent: Optional[float] = None  # percentiles_bucket
    note: Optional[str] = None     # extra caveat to surface


@dataclass
class PostExpr:
    """A derived column computed after aggregation (e.g. bucket_script ratio or a
    pipeline aggregation).

    `ratio` carries (numerator_alias, denominator_alias) when the source was a
    divide-by-zero-guarded ratio, so it can be rendered correctly in either
    context: a scalar `if()` after `summarize`, or element-wise `num[] / den[]`
    after `makeTimeseries` (where the metrics are arrays, not scalars).
    `refs` lists every metric alias the fallback `expr` references, so a non-ratio
    expression can still be made element-wise in the timeseries case.
    `pipeline`, when set, renders via the array-function map below.
    """
    alias: str
    expr: str = ""                 # already-DQL scalar expression (fallback)
    refs: List[str] = field(default_factory=list)
    ratio: Optional[Tuple[str, str]] = None
    pipeline: Optional[Pipeline] = None


@dataclass
class AggTree:
    metrics: List[Metric] = field(default_factory=list)
    buckets: List[Bucket] = field(default_factory=list)
    post: List[PostExpr] = field(default_factory=list)

    @property
    def viz_hint(self) -> str:
        if any(b.kind == "dateHistogram" for b in self.buckets):
            return "lineChart"
        if self.buckets:
            return "categorical"
        return "single"


def _metric_dql(m: Metric, emit, report: Report) -> str:
    fq = quote_field(m.field) if m.field else None
    # A predicate on a field-taking function renders as fn(if(pred, field)):
    # the aggregation ignores the nulls if() yields for non-matching records.
    if fq and m.predicate is not None:
        fq = f"if({emit(m.predicate)}, {fq})"
    if m.func == "count":
        body = "count()"
    elif m.func == "countIf":
        pred = emit(m.predicate) if m.predicate is not None else "true"
        body = f"countIf({pred})"
    elif m.func == "countDistinct":
        body = f"countDistinct({fq})"
    elif m.func == "percentile":
        body = f"percentile({fq}, {int(m.arg) if m.arg is not None else 95})"
    elif m.func in ("avg", "sum", "min", "max", "median", "stddev",
                    "takeFirst", "takeLast", "takeAny"):
        body = f"{m.func}({fq})"
    else:
        report.warn(f"Unknown metric function `{m.func}`; emitted count().")
        body = "count()"
    if m.note:
        report.info(m.note)
    return f"{quote_field(m.alias)} = {body}"


def apply_to_query(tree: AggTree, query: Query, config: MappingConfig,
                   data_object: Optional[str], report: Report) -> str:
    """Populate `query` from `tree`; return the structural viz hint."""
    emit = lambda node: emit_filter(node, config, data_object, report)

    if not tree.metrics:
        tree.metrics = [Metric(alias="count", func="count")]
    for m in tree.metrics:
        if m.field:
            # strip .keyword and apply the field map (idempotent for buckets
            # already resolved by the front-end)
            m.field = config.resolve_field(m.field, data_object)
    metrics_dql = ", ".join(_metric_dql(m, emit, report) for m in tree.metrics)

    dh = next((b for b in tree.buckets if b.kind == "dateHistogram"), None)
    terms = [b for b in tree.buckets if b.kind == "terms"]
    by_fields = [quote_field(config.resolve_field(b.field, data_object))
                 for b in terms if b.field]

    if dh is not None:
        body = f"makeTimeseries {{{metrics_dql}}}, interval: {dh.interval or '1h'}"
        if by_fields:
            body += f", by: {{{', '.join(by_fields)}}}"
        query.add(body)
    else:
        body = f"summarize {metrics_dql}"
        if by_fields:
            body += f", by: {{{', '.join(by_fields)}}}"
        query.add(body)
        # terms ordering -> sort + limit. Fall back to a real metric alias if the
        # requested order column doesn't exist (e.g. it was dropped/renamed).
        first = terms[0] if terms else None
        if first and first.size:
            aliases = {m.alias for m in tree.metrics}
            alias = first.order_alias if first.order_alias in aliases else tree.metrics[0].alias
            query.add(f"sort {quote_field(alias)} {first.order_dir}")
            query.add(f"limit {first.size}")

    is_timeseries = dh is not None
    for p in tree.post:
        rendered = _post_expr_dql(p, is_timeseries, report)
        if rendered is not None:
            query.add(f"fieldsAdd {quote_field(p.alias)} = {rendered}")

    return tree.viz_hint


# ES pipeline aggregation -> DQL array function.
# Parent ops walk an ordered series (need a date_histogram); sibling ops collapse
# a series to a scalar. `{r}` = referenced array, `{w}` = window, `{p}` = percent.
_PARENT_FN = {
    "derivative": "arrayDiff({r})",
    "serial_diff": "arrayDiff({r})",
    "cumulative_sum": "arrayCumulativeSum({r})",
    "moving_avg": "arrayMovingAvg({r}, {w})",
    "moving_sum": "arrayMovingSum({r}, {w})",
    "moving_min": "arrayMovingMin({r}, {w})",
    "moving_max": "arrayMovingMax({r}, {w})",
}
_SIBLING_FN = {
    "avg_bucket": "arrayAvg({r})",
    "sum_bucket": "arraySum({r})",
    "min_bucket": "arrayMin({r})",
    "max_bucket": "arrayMax({r})",
    "percentiles_bucket": "arrayPercentile({r}, {p})",
}


def _pipeline_dql(pl: Pipeline, is_timeseries: bool, report: Report) -> Optional[str]:
    r = quote_field(pl.ref)
    if pl.note:
        report.warn(pl.note)
    if pl.kind == "parent":
        tmpl = _PARENT_FN.get(pl.op)
        if tmpl is None:
            report.manual(f"`{pl.op}` pipeline aggregation has no DQL array equivalent; rewrite manually.")
            return None
        if not is_timeseries:
            report.warn(f"`{pl.op}` needs an ordered series (a date_histogram); the source query "
                        f"has none, so `{pl.op}` was dropped — add a time bucket if you need it.")
            return None
        return tmpl.format(r=r, w=pl.window or 5)
    # sibling: collapse a series to a scalar
    tmpl = _SIBLING_FN.get(pl.op)
    if tmpl is None:
        report.manual(f"`{pl.op}` pipeline aggregation has no direct DQL equivalent; rewrite manually.")
        return None
    if not is_timeseries:
        report.warn(f"`{pl.op}` aggregates across buckets; emitted as an array reducer over the "
                    "series — review for a non-timeseries source.")
    return tmpl.format(r=r, p=pl.percent if pl.percent is not None else 95)


def _post_expr_dql(p: PostExpr, is_timeseries: bool, report: Report) -> Optional[str]:
    """Render a derived column for the right context, or None to drop it (the
    reason is reported). After `makeTimeseries` the metrics are arrays, so
    arithmetic must be element-wise (`a[] / b[]`); after `summarize` they are
    scalars and a divide-by-zero guard reads naturally as `if(b == 0, 0, else: a / b)`.
    """
    if p.pipeline:
        return _pipeline_dql(p.pipeline, is_timeseries, report)
    if p.ratio:
        num, den = quote_field(p.ratio[0]), quote_field(p.ratio[1])
        if is_timeseries:
            # element-wise; empty buckets divide to null and render as a gap
            return f"{num}[] / {den}[]"
        return f"if({den} == 0, 0, else: {num} / {den})"
    if not p.expr:
        return None
    if is_timeseries and p.refs:
        # generic fallback: make every referenced metric element-wise
        expr = p.expr
        for alias in sorted(p.refs, key=len, reverse=True):
            expr = re.sub(rf"{re.escape(quote_field(alias))}\b", quote_field(alias) + "[]", expr)
        report.info(f"The calculated column `{p.alias}` was adapted to time-series data "
                    "(element-wise arithmetic). Open the tile once and sanity-check the numbers.")
        return expr
    return p.expr
