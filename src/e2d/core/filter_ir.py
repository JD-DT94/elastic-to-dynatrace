"""Dialect-neutral boolean filter IR + a single DQL emitter.

KQL, Lucene, the Elasticsearch filter DSL and `bool` queries all translate into
these nodes; the emitter is the only place that knows DQL operator/function
syntax. Field resolution (config field map + `.keyword` stripping) and timeframe
lifting also live here so every front-end behaves identically.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional, Tuple, Union

from e2d.config import MappingConfig
from e2d.core.dql_builder import quote_field, quote_string
from e2d.report import Report


# --------------------------------------------------------------------------- #
# IR nodes
# --------------------------------------------------------------------------- #

@dataclass
class Node:
    pass


@dataclass
class And(Node):
    children: List[Node]


@dataclass
class Or(Node):
    children: List[Node]


@dataclass
class Not(Node):
    child: Node


@dataclass
class Compare(Node):
    field: str
    op: str                       # == != < > <= >=
    value: Union[str, int, float, bool]


@dataclass
class In(Node):
    field: str
    values: List[Union[str, int, float, bool]]
    negated: bool = False


@dataclass
class Exists(Node):
    field: str
    negated: bool = False


@dataclass
class Wildcard(Node):
    field: str                    # KQL/Lucene * and ? wildcards -> matchesValue
    pattern: str


@dataclass
class Regex(Node):
    field: str
    pattern: str


@dataclass
class Phrase(Node):
    """Full-text term with no explicit field -> matchesPhrase against the body."""
    text: str
    field: Optional[str] = None


@dataclass
class TimeRange(Node):
    """A range on a time field; lifted to the query timeframe, not a filter."""
    field: str
    gte: Optional[str] = None
    gt: Optional[str] = None
    lte: Optional[str] = None
    lt: Optional[str] = None


@dataclass
class Raw(Node):
    dql: str                      # escape hatch for already-formed DQL


# --------------------------------------------------------------------------- #
# field + value helpers
# --------------------------------------------------------------------------- #

TIME_FIELDS = {"@timestamp", "timestamp"}


def strip_keyword(name: str) -> str:
    return name[:-8] if name.endswith(".keyword") else name


def _fmt_value(value: Union[str, int, float, bool]) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    return quote_string(str(value))


class FilterEmitter:
    def __init__(self, config: MappingConfig, data_object: Optional[str], report: Report):
        self.config = config
        self.data_object = data_object
        self.report = report

    def field(self, raw: str) -> str:
        name = self.config.resolve_field(strip_keyword(raw), self.data_object)
        return quote_field(name)

    def emit(self, node: Optional[Node]) -> str:
        if node is None:
            return ""
        m = getattr(self, "_" + type(node).__name__, None)
        if m is None:
            self.report.warn(f"Cannot emit filter node {type(node).__name__}.")
            return ""
        return m(node)

    def _And(self, n: And) -> str:
        parts = [self.emit(c) for c in n.children if c is not None]
        parts = [p for p in parts if p]
        if not parts:
            return ""
        return " and ".join(f"({p})" if _has_top_or(p) else p for p in parts)

    def _Or(self, n: Or) -> str:
        parts = [self.emit(c) for c in n.children if c is not None]
        parts = [p for p in parts if p]
        if not parts:
            return ""
        if len(parts) == 1:
            return parts[0]
        return " or ".join(f"({p})" if _has_top_and(p) else p for p in parts)

    def _Not(self, n: Not) -> str:
        inner = self.emit(n.child)
        return f"not ({inner})" if inner else ""

    def _Compare(self, n: Compare) -> str:
        return f"{self.field(n.field)} {n.op} {_fmt_value(n.value)}"

    def _In(self, n: In) -> str:
        items = ", ".join(_fmt_value(v) for v in n.values)
        expr = f"in({self.field(n.field)}, {{{items}}})"
        return f"not {expr}" if n.negated else expr

    def _Exists(self, n: Exists) -> str:
        fn = "isNull" if n.negated else "isNotNull"
        return f"{fn}({self.field(n.field)})"

    def _Wildcard(self, n: Wildcard) -> str:
        self.report.info(f"Wildcard `{n.pattern}` -> matchesValue() (supports leading/trailing *).")
        return f"matchesValue({self.field(n.field)}, {quote_string(n.pattern)})"

    def _Regex(self, n: Regex) -> str:
        return f"matchesRegex({self.field(n.field)}, {quote_string(n.pattern)})"

    def _Phrase(self, n: Phrase) -> str:
        target = n.field or ("content" if self.data_object in (None, "logs") else "content")
        if not n.field:
            self.report.warn(
                f"Bare term `{n.text}` -> matchesPhrase({target}, ...); verify target field.")
        return f"matchesPhrase({quote_field(target) if not n.field else self.field(target)}, {quote_string(n.text)})"

    def _Raw(self, n: Raw) -> str:
        return n.dql

    def _TimeRange(self, n: TimeRange) -> str:
        # If a TimeRange survives to emit (not lifted), express as comparisons.
        f = self.field(n.field)
        parts = []
        if n.gte is not None:
            parts.append(f"{f} >= {es_time_to_dql(n.gte)}")
        if n.gt is not None:
            parts.append(f"{f} > {es_time_to_dql(n.gt)}")
        if n.lte is not None:
            parts.append(f"{f} <= {es_time_to_dql(n.lte)}")
        if n.lt is not None:
            parts.append(f"{f} < {es_time_to_dql(n.lt)}")
        return " and ".join(parts)


def _has_top_or(pred: str) -> bool:
    return " or " in pred and not (pred.startswith("(") and pred.endswith(")"))


def _has_top_and(pred: str) -> bool:
    return " and " in pred and not (pred.startswith("(") and pred.endswith(")"))


# --------------------------------------------------------------------------- #
# Elasticsearch relative/absolute time -> DQL
# --------------------------------------------------------------------------- #

_REL_RE = re.compile(r"^now(?:([-+])(\d+)([smhdwMy]))?(?:/([smhdwMy]))?$")


def es_time_to_dql(expr: str) -> str:
    """`now-15m` -> `now()-15m`; `now` -> `now()`; ISO -> a quoted timestamp.

    DQL durations use the same s/m/h/d/w letters; `M`(month)/`y`(year) have no
    duration literal so they pass through (caller may warn).
    """
    s = str(expr).strip()
    m = _REL_RE.match(s)
    if m:
        sign, num, unit, align = m.groups()
        out = "now()"
        if sign and num and unit:
            out += f"{sign}{num}{unit}"
        if align:
            out += f"@{align}"
        return out
    # absolute timestamp (ISO 8601) or numeric epoch
    return quote_string(s)


def split_timeframe(node: Optional[Node]) -> Tuple[Optional[str], Optional[Node]]:
    """Lift a top-level TimeRange on a time field into a DQL timeframe string.

    Returns (timeframe_or_None, remaining_filter_or_None). Only pulls TimeRange
    nodes that sit at the top level (directly, or inside a top-level And).
    """
    if node is None:
        return None, None
    if isinstance(node, TimeRange) and strip_keyword(node.field) in TIME_FIELDS:
        return _timeframe_of(node), None
    if isinstance(node, And):
        tf = None
        remaining: List[Node] = []
        for c in node.children:
            if isinstance(c, TimeRange) and strip_keyword(c.field) in TIME_FIELDS and tf is None:
                tf = _timeframe_of(c)
            else:
                remaining.append(c)
        if tf is None:
            return None, node
        if not remaining:
            return tf, None
        return tf, (remaining[0] if len(remaining) == 1 else And(remaining))
    return None, node


def _timeframe_of(tr: TimeRange) -> str:
    frm = tr.gte if tr.gte is not None else tr.gt
    to = tr.lte if tr.lte is not None else tr.lt
    parts = []
    if frm is not None:
        parts.append(f"from:{es_time_to_dql(frm)}")
    if to is not None:
        parts.append(f"to:{es_time_to_dql(to)}")
    return ", ".join(parts)


def emit_filter(node: Optional[Node], config: MappingConfig, data_object: Optional[str],
                report: Report) -> str:
    return FilterEmitter(config, data_object, report).emit(node)
