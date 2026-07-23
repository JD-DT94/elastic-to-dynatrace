"""Lens formula strings -> DQL aggregations + a derived-column expression.

A Lens `formula` column like

    count(kql='status:error') / count()
    average(response_time) * 1000
    (sum(bytes) - sum(cached_bytes)) / sum(bytes)

is arithmetic over aggregation calls. That maps cleanly onto the agg-tree:
each aggregation call becomes a metric column; the arithmetic becomes a
`PostExpr` rendered as `fieldsAdd` after the aggregation (element-wise over
timeseries arrays, scalar with a divide-by-zero guard otherwise — the agg-tree
already knows how).

Unsupported constructs (time_shift, moving_average inside a formula, unknown
functions) raise `FormulaError`; the caller falls back to the old count()
placeholder + warning, so a formula never converts silently wrong.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional, Tuple

from e2d.config import MappingConfig
from e2d.core.agg_tree import Metric, Pipeline, PostExpr
from e2d.core.filter_ir import Raw
from e2d.dashboards.kql import translate_query_string
from e2d.report import Report

# Pipeline functions supported as the OUTERMOST call only: they walk an ordered
# series, so they render as an array function over the inner result.
_TOP_PIPELINE = {"moving_average": "moving_avg", "cumulative_sum": "cumulative_sum",
                 "differences": "derivative"}


class FormulaError(ValueError):
    pass


# Lens formula function -> our metric function
_FUNCS = {
    "count": "count",
    "sum": "sum",
    "average": "avg", "avg": "avg",
    "min": "min", "max": "max", "median": "median",
    "unique_count": "countDistinct",
    "standard_deviation": "stddev",
    "percentile": "percentile",
    "last_value": "takeLast",
}
# math wrappers we pass through by dropping (cosmetic precision only)
_PASSTHROUGH = {"round", "clamp", "floor", "ceil", "abs"}
# constructs with no DQL equivalent inside a derived column
_UNSUPPORTED = {"moving_average", "cumulative_sum", "differences", "counter_rate",
                "normalize_by_unit", "time_range", "interval", "now", "overall_sum",
                "overall_average", "overall_min", "overall_max"}

_TOKEN = re.compile(r"""
    \s*(?:
      (?P<num>\d+(?:\.\d+)?)
    | (?P<name>[A-Za-z_][\w.\-]*)
    | (?P<str>'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*")
    | (?P<op>[+\-*/(),=])
    )""", re.X)


def _tokenize(s: str) -> List[Tuple[str, str]]:
    toks, i = [], 0
    while i < len(s):
        m = _TOKEN.match(s, i)
        if not m:
            raise FormulaError(f"unexpected character {s[i]!r}")
        i = m.end()
        for kind in ("num", "name", "str", "op"):
            v = m.group(kind)
            if v is not None:
                if kind == "str":
                    v = v[1:-1]
                toks.append((kind, v))
                break
        if not m.group(0).strip() and i < len(s):
            i += 1
    return toks


@dataclass
class _Ctx:
    config: MappingConfig
    data_object: str
    report: Report
    metrics: List[Metric]
    aliases: dict


class _Parser:
    def __init__(self, toks: List[Tuple[str, str]], ctx: _Ctx):
        self.toks = toks
        self.pos = 0
        self.ctx = ctx

    def _peek(self):
        return self.toks[self.pos] if self.pos < len(self.toks) else (None, None)

    def _next(self):
        t = self._peek()
        self.pos += 1
        return t

    def _expect(self, value: str):
        kind, v = self._next()
        if v != value:
            raise FormulaError(f"expected {value!r}, got {v!r}")

    # expr := term (('+'|'-') term)*
    def expr(self) -> str:
        out = self.term()
        while self._peek() == ("op", "+") or self._peek() == ("op", "-"):
            _, op = self._next()
            out = f"{out} {op} {self.term()}"
        return out

    def term(self) -> str:
        out = self.factor()
        while self._peek() == ("op", "*") or self._peek() == ("op", "/"):
            _, op = self._next()
            out = f"{out} {op} {self.factor()}"
        return out

    def factor(self) -> str:
        kind, v = self._peek()
        if (kind, v) == ("op", "("):
            self._next()
            inner = self.expr()
            self._expect(")")
            return f"({inner})"
        if (kind, v) == ("op", "-"):
            self._next()
            return f"-{self.factor()}"
        if kind == "num":
            self._next()
            return v
        if kind == "name":
            return self.call()
        raise FormulaError(f"unexpected token {v!r}")

    # call := NAME '(' [args] ')'
    def call(self) -> str:
        _, name = self._next()
        lname = name.lower()
        if self._peek() != ("op", "("):
            raise FormulaError(f"bare identifier {name!r} (fields must be inside a function)")
        self._next()  # (

        if lname in _UNSUPPORTED:
            raise FormulaError(f"`{name}` has no DQL equivalent inside a formula")
        if lname in _PASSTHROUGH:
            inner = self.expr()
            # swallow any precision/limit arguments
            while self._peek() == ("op", ","):
                self._next()
                self.expr()
            self._expect(")")
            self.ctx.report.info(f"Lens formula `{name}()` wrapper dropped "
                                 "(display precision only).")
            return inner
        if lname not in _FUNCS:
            raise FormulaError(f"unknown formula function `{name}`")

        field: Optional[str] = None
        pred: Optional[str] = None
        arg_val: Optional[float] = None
        while self._peek() != ("op", ")"):
            kind, v = self._next()
            if kind == "name" and self._peek() == ("op", "="):
                self._next()  # =
                akind, aval = self._next()
                key = v.lower()
                if key in ("kql", "lucene"):
                    pred = translate_query_string(
                        aval, "lucene" if key == "lucene" else "kuery",
                        self.ctx.config, self.ctx.data_object, self.ctx.report) or None
                elif key == "percentile":
                    try:
                        arg_val = float(aval)
                    except (TypeError, ValueError):
                        arg_val = 95
                elif key == "shift":
                    raise FormulaError("time_shift (`shift=`) has no DQL equivalent")
                # other named args (e.g. reducedTimeRange) are ignored below
                else:
                    self.ctx.report.info(f"Lens formula argument `{key}=` ignored.")
            elif kind in ("name", "str"):
                field = v
            if self._peek() == ("op", ","):
                self._next()
        self._expect(")")

        return self._metric_alias(lname, field, pred, arg_val)

    def _metric_alias(self, lname: str, field: Optional[str], pred: Optional[str],
                      arg_val: Optional[float]) -> str:
        func = _FUNCS[lname]
        if field:
            if field.endswith(".keyword"):
                field = field[: -len(".keyword")]
            field = self.ctx.config.resolve_field(field, self.ctx.data_object)
        if func != "count" and not field:
            raise FormulaError(f"`{lname}` needs a field")

        base = func if func != "count" else ("countIf" if pred else "count")
        alias = _san("_".join(x for x in (base, field, pred and "f") if x))
        n = 2
        while alias in self.ctx.aliases and self.ctx.aliases[alias] != (func, field, pred, arg_val):
            alias = f"{alias}_{n}"
            n += 1
        if alias not in self.ctx.aliases:
            self.ctx.aliases[alias] = (func, field, pred, arg_val)
            if func == "count":
                m = (Metric(alias=alias, func="countIf", predicate=Raw(pred)) if pred
                     else Metric(alias=alias, func="count"))
            else:
                m = Metric(alias=alias, func=func, field=field, arg=arg_val,
                           predicate=Raw(pred) if pred else None)
            self.ctx.metrics.append(m)
        return alias


def _san(s: str) -> str:
    out = "".join(c if (c.isalnum() or c == "_") else "_" for c in s).strip("_")
    if not out or out[0].isdigit():
        out = "m_" + out
    return out


def translate_formula(formula: str, alias: str, config: MappingConfig, data_object: str,
                      report: Report) -> Tuple[List[Metric], List[PostExpr]]:
    """Translate one Lens formula. Returns (metrics to add, post expressions).

    When the whole formula is a single aggregation call, the metric itself takes
    the column's alias and no post expression is needed. Raises FormulaError
    for anything it cannot translate faithfully.
    """
    toks = _tokenize(formula)
    if not toks:
        raise FormulaError("empty formula")

    # outermost pipeline wrapper: moving_average(<inner>, window=N) etc.
    pipe_op = window = None
    if len(toks) > 2 and toks[0][0] == "name" and toks[0][1].lower() in _TOP_PIPELINE \
            and toks[1] == ("op", "("):
        pipe_op = _TOP_PIPELINE[toks[0][1].lower()]
        toks = toks[2:]
        if toks and toks[-1] == ("op", ")"):
            toks = toks[:-1]
        # trailing `, window=N`
        if len(toks) >= 4 and toks[-4] == ("op", ",") and toks[-3][1] == "window" \
                and toks[-2] == ("op", "="):
            try:
                window = int(float(toks[-1][1]))
            except (TypeError, ValueError):
                window = None
            toks = toks[:-4]

    ctx = _Ctx(config, data_object, report, [], {})
    parser = _Parser(toks, ctx)
    expr = parser.expr()
    if parser.pos < len(parser.toks):
        raise FormulaError(f"trailing input at token {parser.toks[parser.pos][1]!r}")

    refs = list(ctx.aliases.keys())
    posts: List[PostExpr] = []
    is_single = len(ctx.metrics) == 1 and expr == ctx.metrics[0].alias

    if pipe_op is not None:
        if is_single:
            src = ctx.metrics[0].alias
        else:
            src = _san(f"{alias}_src")
            posts.append(PostExpr(alias=src, expr=expr, refs=refs))
        posts.append(PostExpr(alias=alias,
                              pipeline=Pipeline(op=pipe_op, ref=src, window=window)))
        return ctx.metrics, posts

    if is_single:
        ctx.metrics[0].alias = alias
        return ctx.metrics, []

    ratio = None
    m = re.fullmatch(r"(\w+) / (\w+)", expr)
    if m and m.group(1) in refs and m.group(2) in refs:
        ratio = (m.group(1), m.group(2))
    return ctx.metrics, [PostExpr(alias=alias, expr=expr, refs=refs, ratio=ratio)]
