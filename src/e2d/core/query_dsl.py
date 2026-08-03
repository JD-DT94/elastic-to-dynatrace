"""Elasticsearch Query DSL (JSON) -> DQL.

* `query`  block -> filter IR (bool/term/terms/match/range/exists/wildcard/regexp,
  query_string -> Lucene front-end).
* `aggs`   tree  -> AggTree (terms/date_histogram/filters/value_count/cardinality/
  avg/.../percentiles/filter; bucket_script -> post fieldsAdd; runtime_mappings
  Painless emit-chains -> pre-aggregation fieldsAdd). top_hits / scripted_metric /
  derivative are flagged (MANUAL/REVIEW).
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

from e2d.config import MappingConfig
from e2d.core.agg_tree import AggTree, Bucket, Metric, Pipeline, PostExpr, apply_to_query
from e2d.core.dql_builder import Query, quote_field
from e2d.core.filter_ir import (
    And, Compare, Exists, In, Node, Not, Or, Phrase, Regex, TimeRange, Wildcard,
    TIME_FIELDS, emit_filter, split_timeframe, strip_keyword,
)
from e2d.core.lucene import translate_lucene
from e2d.report import Report


# --------------------------------------------------------------------------- #
# query -> filter IR
# --------------------------------------------------------------------------- #

def parse_query(q: Optional[Dict[str, Any]], config, data_object, report) -> Optional[Node]:
    if not q:
        return None
    if len(q) != 1:
        # a clause object should have exactly one key; tolerate by AND-ing
        return And([n for n in (parse_query({k: v}, config, data_object, report)
                                for k, v in q.items()) if n])
    (kind, body), = q.items()
    if kind == "bool":
        return _parse_bool(body, config, data_object, report)
    if kind in ("term", "match", "match_phrase", "match_phrase_prefix"):
        field, val = _single(body)
        value = _val(val)
        if kind != "term":
            resolved = config.resolve_field(strip_keyword(field), data_object)
            if resolved == "content":
                # ES matches analyzed text (the value occurring IN the message);
                # == would require the whole log line to equal the value
                report.info(f"`{kind}` on the log body mapped to "
                            "matchesPhrase(content, ...).")
                if kind == "match" and isinstance(value, str) and " " in value:
                    report.warn("`match` matches records containing ANY of the "
                                "analyzed terms; matchesPhrase requires the words "
                                "together. Split into OR'd matchesPhrase() calls "
                                "if any-term behavior was intended.")
                return Phrase(str(value), field=field)
            report.info(f"`{kind}` on `{field}` mapped to ==; analyzed-match "
                        "semantics may differ. If it is an analyzed text field, "
                        "use matchesPhrase() instead.")
        return Compare(field, "==", value)
    if kind == "terms":
        field, vals = _single(body)
        return In(field, [_val(v) for v in (vals or [])])
    if kind == "range":
        field, spec = _single(body)
        return _range(field, spec)
    if kind == "exists":
        return Exists(body.get("field", ""))
    if kind in ("wildcard", "prefix"):
        field, val = _single(body)
        pat = _val(val)
        pat = f"{pat}*" if kind == "prefix" else str(pat)
        return Wildcard(field, str(pat))
    if kind == "regexp":
        field, val = _single(body)
        return Regex(field, str(_val(val)))
    if kind in ("query_string", "simple_query_string"):
        return translate_lucene(body.get("query", ""), config, data_object, report)
    if kind == "match_all":
        return None
    report.warn(f"Unsupported query clause `{kind}`; skipped.")
    return None


def _parse_bool(b: Dict[str, Any], config, data_object, report) -> Optional[Node]:
    def many(key):
        v = b.get(key, [])
        v = v if isinstance(v, list) else [v]
        return [n for n in (parse_query(c, config, data_object, report) for c in v) if n]

    parts: List[Node] = many("must") + many("filter")
    should = many("should")
    msm = b.get("minimum_should_match")
    if should:
        if parts and not msm:
            # With sibling must/filter clauses, minimum_should_match defaults to
            # 0: should only affects scoring. AND-ing it in would silently narrow
            # the result set, so it is left out of the filter.
            report.warn("bool.should next to must/filter is optional in "
                        "Elasticsearch (minimum_should_match defaults to 0), so "
                        "the should clauses were left out of the filter. If they "
                        "were meant to restrict results, set "
                        "minimum_should_match: 1 in the source and re-convert.")
        else:
            if msm not in (None, 1, "1") and len(should) > 1:
                report.warn(f"bool.should minimum_should_match={msm} approximated "
                            "as any-of (OR); at-least-{msm}-of has no direct DQL "
                            "equivalent.")
            parts.append(Or(should) if len(should) > 1 else should[0])
    for mn in many("must_not"):
        parts.append(Not(mn))
    if not parts:
        return None
    return And(parts) if len(parts) > 1 else parts[0]


_DATE_MATH = re.compile(r"^now([-+/]|$)")


def _range(field: str, spec: Dict[str, Any]) -> Node:
    is_time = strip_keyword(field) in TIME_FIELDS
    bounds = [spec.get(k) for k in ("gte", "gt", "lte", "lt")
              if spec.get(k) is not None]
    # a range using ES date math (now-1h) is temporal regardless of the field
    # name; emitting the raw string would compare against a literal "now-1h"
    has_math = any(isinstance(v, str) and _DATE_MATH.match(v.strip())
                   for v in bounds)
    if is_time or has_math:
        return TimeRange(field=field, gte=spec.get("gte"), gt=spec.get("gt"),
                         lte=spec.get("lte"), lt=spec.get("lt"))
    parts: List[Node] = []
    for key, op in (("gte", ">="), ("gt", ">"), ("lte", "<="), ("lt", "<")):
        if key in spec:
            parts.append(Compare(field, op, _val(spec[key])))
    return And(parts) if len(parts) > 1 else (parts[0] if parts else And([]))


def _single(body: Dict[str, Any]) -> Tuple[str, Any]:
    (k, v), = body.items()
    return k, v


def _val(v: Any) -> Any:
    if isinstance(v, dict) and "value" in v:   # {value:.., boost:..}
        return v["value"]
    return v


# --------------------------------------------------------------------------- #
# aggs -> AggTree
# --------------------------------------------------------------------------- #

_SIMPLE_METRICS = {"avg": "avg", "sum": "sum", "min": "min", "max": "max"}


def parse_aggs(aggs: Dict[str, Any], config, data_object, report,
               tree: Optional[AggTree] = None) -> AggTree:
    tree = tree or AggTree()
    for name, body in aggs.items():
        if "date_histogram" in body:
            dh = body["date_histogram"]
            tree.buckets.append(Bucket("dateHistogram", field=dh.get("field"),
                                       interval=_es_interval(dh, report)))
            if "aggs" in body:
                parse_aggs(body["aggs"], config, data_object, report, tree)
        elif "terms" in body:
            t = body["terms"]
            order_alias, order_dir = _terms_order(t)
            tree.buckets.append(Bucket("terms", field=t.get("field"), size=t.get("size"),
                                       order_alias=order_alias, order_dir=order_dir))
            if "aggs" in body:
                parse_aggs(body["aggs"], config, data_object, report, tree)
        elif "filters" in body:
            for label, fq in body["filters"].get("filters", {}).items():
                pred = parse_query(fq, config, data_object, report)
                tree.metrics.append(Metric(alias=label, func="countIf", predicate=pred))
            if "aggs" in body:
                report.warn(f"`filters` agg `{name}` has nested sub-aggregations; the per-filter "
                            "split is approximated as countIf columns — review.")
                parse_aggs(body["aggs"], config, data_object, report, tree)
        else:
            _parse_metric(name, body, config, data_object, report, tree)
    return tree


def _parse_metric(name, body, config, data_object, report, tree: AggTree) -> None:
    if "value_count" in body:
        tree.metrics.append(Metric(alias=name, func="count",
                                   note=f"value_count({body['value_count'].get('field')}) -> count()."))
    elif "cardinality" in body:
        tree.metrics.append(Metric(alias=name, func="countDistinct", field=body["cardinality"].get("field")))
    elif "percentiles" in body:
        pf = body["percentiles"]
        for pct in pf.get("percents", [95]):
            alias = f"{name}_p{str(pct).replace('.', '_')}"
            tree.metrics.append(Metric(alias=alias, func="percentile", field=pf.get("field"), arg=pct))
    elif "filter" in body:
        pred = parse_query(body["filter"], config, data_object, report)
        tree.metrics.append(Metric(alias=name, func="countIf", predicate=pred))
    elif "bucket_script" in body:
        tree.post.append(_bucket_script(name, body["bucket_script"], report))
    elif any(k in body for k in _PIPELINE_KEYS):
        pe = _pipeline_agg(name, body, report)
        if pe is not None:
            tree.post.append(pe)
    elif "top_hits" in body:
        report.manual(f"`top_hits` agg `{name}` has no scalar DQL equivalent; run a companion record query.")
    elif "scripted_metric" in body:
        _scripted_metric(name, body["scripted_metric"], report, tree)
    else:
        for mtype, fn in _SIMPLE_METRICS.items():
            if mtype in body:
                tree.metrics.append(Metric(alias=name, func=fn, field=body[mtype].get("field")))
                return
        report.warn(f"Unsupported metric agg `{name}` ({list(body.keys())}); skipped.")


def _terms_order(t: Dict[str, Any]) -> Tuple[Optional[str], str]:
    order = t.get("order")
    if isinstance(order, dict) and order:
        (alias, direction), = order.items()
        if alias in ("_count", "_key"):
            return None, direction
        return alias, direction
    return None, "desc"


def _es_interval(dh: Dict[str, Any], report: Report) -> str:
    raw = dh.get("fixed_interval") or dh.get("calendar_interval") or dh.get("interval") or "1h"
    raw = str(raw)
    units = {"ms": "ms", "s": "s", "m": "m", "h": "h", "d": "d", "w": "w"}
    if raw in units:
        return "1" + units[raw]
    if raw in ("M", "y", "1M", "1y"):
        report.warn(f"Calendar interval `{raw}` has no DQL duration; defaulted to 1d.")
        return "1d"
    return raw.lower()


# --------------------------------------------------------------------------- #
# Painless helpers (bucket_script ternary + runtime_mappings emit-chain)
# --------------------------------------------------------------------------- #

_RATIO_RE = re.compile(r"params\.(\w+)\s*/\s*params\.(\w+)")


def _bucket_script(alias: str, bs: Dict[str, Any], report: Report) -> PostExpr:
    """Translate a `bucket_script` into a derived `PostExpr`.

    Keeps enough structure for `apply_to_query` to render it correctly whether
    the aggregation became a `summarize` (scalars) or a `makeTimeseries` (arrays):
    `refs` is every metric alias referenced; `ratio` is (numerator, denominator)
    when the script is a guarded `a / b`.
    """
    paths = bs.get("buckets_path", {})
    script = bs.get("script", "")
    if isinstance(script, dict):
        script = script.get("source", "")
    # param name -> referenced metric alias (strip the ">_count" path suffix)
    refs = {k: str(path).split(">")[0] for k, path in paths.items()}

    ratio = None
    rm = _RATIO_RE.search(script)
    if rm and rm.group(1) in refs and rm.group(2) in refs:
        ratio = (refs[rm.group(1)], refs[rm.group(2)])

    # scalar fallback expression (params.x -> alias), used outside the timeseries case
    scalar = script
    for k, a in refs.items():
        scalar = re.sub(rf"params\.{re.escape(k)}\b", quote_field(a), scalar)
    scalar = _painless_ternary_to_dql(scalar, report)
    return PostExpr(alias=alias, expr=scalar, refs=sorted(set(refs.values())), ratio=ratio)


# --------------------------------------------------------------------------- #
# pipeline aggregations -> DQL array functions  (see agg_tree._PARENT_FN/_SIBLING_FN)
# --------------------------------------------------------------------------- #

_PARENT_PIPE = {"derivative", "cumulative_sum", "serial_diff", "moving_fn", "moving_avg"}
_SIBLING_PIPE = {"avg_bucket", "sum_bucket", "min_bucket", "max_bucket", "percentiles_bucket"}
_MANUAL_PIPE = {"cumulative_cardinality", "moving_percentiles", "normalize", "inference",
                "bucket_sort", "bucket_selector", "stats_bucket", "extended_stats_bucket"}
_PIPELINE_KEYS = _PARENT_PIPE | _SIBLING_PIPE | _MANUAL_PIPE


def _ref_alias(path: Any) -> str:
    """Resolve an ES `buckets_path` to the referenced metric alias.
    `errors>_count` -> `errors`; `services>c` -> `c`; `c` -> `c`."""
    if not isinstance(path, str):
        return "ref"
    segs = [s for s in path.split(">") if s not in ("_count", "_value")]
    return segs[-1] if segs else "ref"


def _moving_op(spec: Dict[str, Any]) -> str:
    """Pick the array moving-window function from a moving_fn script."""
    script = str(spec.get("script", "")).lower()
    for needle, op in (("sum", "moving_sum"), ("min", "moving_min"), ("max", "moving_max")):
        if f".{needle}(" in script:
            return op
    return "moving_avg"  # unweightedAvg / linearWeightedAvg / ewma / holt / default


def _pipeline_agg(name: str, body: Dict[str, Any], report: Report) -> Optional[PostExpr]:
    key = next(k for k in body if k in _PIPELINE_KEYS)
    spec = body[key] if isinstance(body[key], dict) else {}
    ref = _ref_alias(spec.get("buckets_path", ""))

    if key in _MANUAL_PIPE:
        report.manual(f"`{key}` pipeline aggregation `{name}` has no direct DQL equivalent; "
                      "rewrite manually.")
        return None

    if key in _SIBLING_PIPE:
        percent = (spec.get("percents") or [95])[0] if key == "percentiles_bucket" else None
        return PostExpr(alias=name, pipeline=Pipeline(op=key, ref=ref, kind="sibling", percent=percent))

    # parent (walks an ordered series)
    op, window, note = key, None, None
    if key in ("moving_fn", "moving_avg"):
        op = _moving_op(spec)
        window = int(spec.get("window", 5))
    if key == "serial_diff" and int(spec.get("lag", 1)) != 1:
        note = (f"`serial_diff` lag={spec.get('lag')} approximated as a lag-1 `arrayDiff` — "
                "review if you need a wider lag.")
    if key == "derivative" and spec.get("unit"):
        note = f"`derivative` unit `{spec.get('unit')}` normalisation dropped; emitted a plain delta."
    return PostExpr(alias=name, pipeline=Pipeline(op=op, ref=ref, kind="parent", window=window, note=note))


def _scripted_metric(name: str, spec: Dict[str, Any], report: Report, tree: AggTree) -> None:
    """Recognise the ubiquitous HashSet distinct-count Painless idiom and emit a
    real `countDistinct`; otherwise flag MANUAL (arbitrary script)."""
    blob = " ".join(str(spec.get(k, "")) for k in
                    ("init_script", "map_script", "combine_script", "reduce_script")).lower()
    m = re.search(r"add\(\s*doc\[\s*['\"]([\w.]+)['\"]", blob)
    if m and "size()" in blob and ("hashset" in blob or "new set" in blob or "distinct" in blob):
        field = m.group(1)
        tree.metrics.append(Metric(alias=name, func="countDistinct", field=field,
                                   note=f"scripted_metric `{name}` recognised as a distinct count -> "
                                        f"countDistinct({field}); verify it matches intent."))
        return
    report.manual(f"`scripted_metric` agg `{name}` is arbitrary Painless; rewrite manually.")


def _painless_ternary_to_dql(expr: str, report: Report) -> str:
    e = expr.strip().rstrip(";")
    e = re.sub(r"\((?:double|long|int|float)\)", "", e)  # drop casts
    # single ternary: COND ? A : B
    qpos = e.find("?")
    cpos = e.rfind(":")
    if qpos != -1 and cpos != -1 and cpos > qpos:
        cond = e[:qpos].strip()
        a = e[qpos + 1:cpos].strip()
        b = e[cpos + 1:].strip()
        return f"if({cond}, {a}, else: {b})"
    report.info("bucket_script was not a simple ternary; emitted as-is for review.")
    return e


_EMIT_IF = re.compile(r"if\s*\((?P<cond>[^)]+)\)\s*emit\(\s*'(?P<val>[^']*)'\s*\)")


def runtime_field_expr(script_src: str, field_for: Optional[str], report: Report) -> Optional[str]:
    """Best-effort Painless emit-chain -> nested DQL if(). Returns None if unparseable."""
    src = script_src
    # resolve the doc['x'].value reference to a bare field name
    docref = re.search(r"doc\['([^']+)'\]\.value", src)
    var_field = docref.group(1) if docref else None
    if var_field:
        # replace the local variable usage (e.g. `v`) — find `<type> v = doc[...]`
        decl = re.search(r"\b(\w+)\s*=\s*doc\['" + re.escape(var_field) + r"'\]\.value", src)
        if decl:
            src = re.sub(rf"\b{decl.group(1)}\b", quote_field(var_field), src)
    branches = _EMIT_IF.findall(src)
    default = re.search(r"else\s+emit\(\s*'([^']*)'\s*\)", src)
    if not branches:
        report.manual("runtime_mapping Painless could not be parsed; rewrite as fieldsAdd manually.")
        return None
    result = f'"{default.group(1)}"' if default else "null"
    for cond, val in reversed(branches):
        result = f'if({cond.strip()}, "{val}", else: {result})'
    report.info("runtime_mapping emit-chain translated to nested if(); review the conditions.")
    return result


# --------------------------------------------------------------------------- #
# top-level
# --------------------------------------------------------------------------- #

def convert_query_dsl(doc: Dict[str, Any], config: MappingConfig, data_object: str,
                      report: Report) -> Tuple[str, str]:
    """Return (dql, viz_hint) for a full Query DSL document."""
    query = Query(data_object=data_object)

    # filter (+ timeframe lifting)
    filt = parse_query(doc.get("query"), config, data_object, report)
    timeframe, remaining = split_timeframe(filt)
    if timeframe:
        query.timeframe = timeframe
    pred = emit_filter(remaining, config, data_object, report)
    query.add_filter(pred)

    # runtime_mappings -> pre-aggregation fieldsAdd (must precede summarize)
    for name, rm in (doc.get("runtime_mappings") or {}).items():
        src = (rm.get("script") or {}).get("source", "")
        expr = runtime_field_expr(src, name, report)
        if expr:
            query.add(f"fieldsAdd {quote_field(name)} = {expr}")

    aggs = doc.get("aggs") or doc.get("aggregations")
    if aggs:
        tree = parse_aggs(aggs, config, data_object, report)
        viz = apply_to_query(tree, query, config, data_object, report)
        return query.render(), viz

    # no aggs: a plain search -> records
    size = doc.get("size")
    if size == 0:
        report.info("Query has size:0 and no aggregations; emitted a count().")
        query.add("summarize count()")
        return query.render(), "single"
    for cmd in _sort_commands(doc.get("sort"), config, data_object):
        query.add(cmd)
    query.add(f"limit {size if isinstance(size, int) else 100}")
    return query.render(), "table"


def _sort_commands(sort: Any, config: MappingConfig, data_object: str) -> List[str]:
    """ES `sort` (list of field / {field:dir} / {field:{order:dir}}) -> DQL sort."""
    if not sort:
        return []
    items = sort if isinstance(sort, list) else [sort]
    terms: List[str] = []
    for it in items:
        if isinstance(it, str):
            field, direction = it, "asc"
        elif isinstance(it, dict):
            (field, spec), = it.items()
            direction = spec.get("order", "asc") if isinstance(spec, dict) else str(spec)
        else:
            continue
        if field in ("_score", "_doc"):
            continue
        terms.append(f"{quote_field(config.resolve_field(strip_keyword(field), data_object))} {direction}")
    return [f"sort {', '.join(terms)}"] if terms else []
