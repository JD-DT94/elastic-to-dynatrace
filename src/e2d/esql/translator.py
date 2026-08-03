"""ES|QL -> DQL translator.

Both languages are pipeline-based (commands chained with `|`), so translation is
command-by-command. Each ES|QL command maps to one (occasionally zero or two)
DQL commands. Expressions inside WHERE/EVAL/STATS are parsed into a small AST and
re-emitted as DQL.

Entry point: ``translate_esql(query, config=None) -> EsqlTranslationResult``.
"""

from __future__ import annotations

from dataclasses import dataclass, field as dc_field
from typing import List, Optional, Tuple

from e2d.config import MappingConfig, METRICS_SENTINEL
from e2d.report import Report
from e2d.esql import functions as fns
from e2d.esql.tokenizer import (
    Token,
    TT_IDENT,
    TT_NUMBER,
    TT_OP,
    TT_PUNCT,
    TT_STRING,
    split_pipes,
    split_top_level,
    tokenize,
)


@dataclass
class EsqlTranslationResult:
    dql: str
    report: Report = dc_field(default_factory=Report)
    # Per-source-command tracking, useful for dashboards that embed many queries.
    source: str = ""

    @property
    def warnings(self) -> List[str]:
        return [w.format() for w in self.report.warnings]

    @property
    def needs_review(self) -> bool:
        return self.report.needs_review


# --------------------------------------------------------------------------- #
# Expression AST
# --------------------------------------------------------------------------- #

@dataclass
class Node:
    pass


@dataclass
class Lit(Node):
    text: str  # already DQL-ready literal text


@dataclass
class FieldRef(Node):
    name: str  # already DQL-mapped


@dataclass
class Star(Node):
    pass


@dataclass
class FuncCall(Node):
    name: str  # original esql name, lowercased
    args: List[Node]


@dataclass
class Unary(Node):
    op: str
    operand: Node


@dataclass
class Binary(Node):
    op: str
    left: Node
    right: Node


@dataclass
class Cast(Node):
    operand: Node
    type_name: str


@dataclass
class InExpr(Node):
    target: Node
    items: List[Node]
    negated: bool = False


@dataclass
class IsNull(Node):
    operand: Node
    negated: bool


@dataclass
class LikeExpr(Node):
    target: Node
    pattern: Node
    regex: bool


@dataclass
class CaseExpr(Node):
    pairs: List[Tuple[Node, Node]]
    default: Optional[Node]


@dataclass
class Paren(Node):
    inner: Node


# --------------------------------------------------------------------------- #
# Expression parser
# --------------------------------------------------------------------------- #

_KEYWORD_VALUES = {"true", "false", "null"}


class ExprParser:
    """Recursive-descent parser over the flat token stream from ``tokenize``."""

    def __init__(self, tokens: List[Token], config: MappingConfig,
                 data_object: Optional[str], report: Report):
        self.toks = tokens
        self.pos = 0
        self.config = config
        self.data_object = data_object
        self.report = report

    # -- token helpers ----------------------------------------------------
    def _peek(self) -> Optional[Token]:
        return self.toks[self.pos] if self.pos < len(self.toks) else None

    def _next(self) -> Optional[Token]:
        t = self._peek()
        if t is not None:
            self.pos += 1
        return t

    def _at_keyword(self, *words: str) -> bool:
        t = self._peek()
        return t is not None and t.type == TT_IDENT and t.value.lower() in words

    def _eat_keyword(self, word: str) -> bool:
        if self._at_keyword(word):
            self._next()
            return True
        return False

    def _at_op(self, *ops: str) -> bool:
        t = self._peek()
        return t is not None and t.type == TT_OP and t.value in ops

    def _at_punct(self, ch: str) -> bool:
        t = self._peek()
        return t is not None and t.type == TT_PUNCT and t.value == ch

    # -- grammar ----------------------------------------------------------
    def parse(self) -> Node:
        node = self._or()
        return node

    def _or(self) -> Node:
        node = self._and()
        while self._at_keyword("or"):
            self._next()
            node = Binary("or", node, self._and())
        return node

    def _and(self) -> Node:
        node = self._not()
        while self._at_keyword("and"):
            self._next()
            node = Binary("and", node, self._not())
        return node

    def _not(self) -> Node:
        if self._at_keyword("not"):
            self._next()
            return Unary("not", self._not())
        return self._comparison()

    def _comparison(self) -> Node:
        left = self._additive()
        # IS [NOT] NULL
        if self._at_keyword("is"):
            self._next()
            negated = bool(self._eat_keyword("not"))
            if not self._eat_keyword("null"):
                self.report.warn("Malformed IS [NOT] NULL expression.")
            return IsNull(left, negated)
        # [NOT] IN ( ... )
        negated_in = False
        if self._at_keyword("not") and self._peek_is_in_after_not():
            self._next()
            negated_in = True
        if self._at_keyword("in"):
            self._next()
            items = self._paren_list()
            return InExpr(left, items, negated_in)
        # LIKE / RLIKE
        if self._at_keyword("like"):
            self._next()
            return LikeExpr(left, self._additive(), regex=False)
        if self._at_keyword("rlike"):
            self._next()
            return LikeExpr(left, self._additive(), regex=True)
        # comparison operators
        if self._at_op("==", "!=", "<", ">", "<=", ">=", "=~"):
            op = self._next().value
            right = self._additive()
            if op == "=~":
                self.report.warn(
                    "ES|QL `=~` (case-insensitive equality) translated to lower()==lower(); review.")
                return Binary("==", FuncCall("to_lower", [left]), FuncCall("to_lower", [right]))
            return Binary(op, left, right)
        return left

    def _peek_is_in_after_not(self) -> bool:
        nxt = self.toks[self.pos + 1] if self.pos + 1 < len(self.toks) else None
        return nxt is not None and nxt.type == TT_IDENT and nxt.value.lower() == "in"

    def _additive(self) -> Node:
        node = self._multiplicative()
        while self._at_op("+", "-"):
            op = self._next().value
            node = Binary(op, node, self._multiplicative())
        return node

    def _multiplicative(self) -> Node:
        node = self._cast()
        while self._at_op("*", "/", "%"):
            op = self._next().value
            node = Binary(op, node, self._cast())
        return node

    def _cast(self) -> Node:
        node = self._unary()
        while self._at_op("::"):
            self._next()
            t = self._next()
            type_name = t.value.lower() if t else ""
            node = Cast(node, type_name)
        return node

    def _unary(self) -> Node:
        if self._at_op("-"):
            self._next()
            return Unary("-", self._unary())
        if self._at_op("+"):
            self._next()
            return self._unary()
        return self._primary()

    def _primary(self) -> Node:
        t = self._peek()
        if t is None:
            return Lit("")
        if self._at_punct("("):
            self._next()
            inner = self._or()
            if self._at_punct(")"):
                self._next()
            return Paren(inner)
        if self._at_op("*"):
            self._next()
            return Star()
        if t.type == TT_NUMBER:
            self._next()
            return Lit(t.value)
        if t.type == TT_STRING:
            self._next()
            return Lit(t.value)
        if t.type == TT_IDENT:
            low = t.value.lower()
            if low in _KEYWORD_VALUES:
                self._next()
                return Lit(low)
            if low == "case":
                return self._case()
            # function call?
            nxt = self.toks[self.pos + 1] if self.pos + 1 < len(self.toks) else None
            if nxt is not None and nxt.type == TT_PUNCT and nxt.value == "(":
                return self._func_call()
            return self._field_ref()
        # unexpected
        self._next()
        self.report.warn(f"Unexpected token `{t.value}` in expression.")
        return Lit(t.value)

    def _func_call(self) -> Node:
        name = self._next().value.lower()
        self._next()  # consume '('
        args = self._arg_list()
        return FuncCall(name, args)

    def _case(self) -> Node:
        self._next()  # 'case'
        if not self._at_punct("("):
            self.report.warn("Malformed CASE expression.")
            return Lit("null")
        self._next()  # '('
        args = self._arg_list()
        pairs: List[Tuple[Node, Node]] = []
        default: Optional[Node] = None
        i = 0
        while i + 1 < len(args):
            pairs.append((args[i], args[i + 1]))
            i += 2
        if i < len(args):  # odd trailing arg = default
            default = args[i]
        return CaseExpr(pairs, default)

    def _arg_list(self) -> List[Node]:
        """Parse comma-separated args until the matching ')'."""
        args: List[Node] = []
        if self._at_punct(")"):
            self._next()
            return args
        while True:
            args.append(self._or())
            if self._at_punct(","):
                self._next()
                continue
            if self._at_punct(")"):
                self._next()
                break
            # ran out of tokens
            break
        return args

    def _paren_list(self) -> List[Node]:
        items: List[Node] = []
        if not self._at_punct("("):
            self.report.warn("Expected '(' after IN.")
            return items
        self._next()
        return self._arg_list()

    def _field_ref(self) -> Node:
        parts: List[str] = []
        # first ident
        parts.append(self._strip_ident(self._next().value))
        # dotted continuation
        while self._at_punct(".") and self._next_is_ident_after_dot():
            self._next()  # '.'
            parts.append(self._strip_ident(self._next().value))
        raw = ".".join(parts)
        mapped = self.config.resolve_field(raw, self.data_object)
        return FieldRef(mapped)

    def _next_is_ident_after_dot(self) -> bool:
        nxt = self.toks[self.pos + 1] if self.pos + 1 < len(self.toks) else None
        return nxt is not None and nxt.type in (TT_IDENT, TT_NUMBER)

    @staticmethod
    def _strip_ident(value: str) -> str:
        return value.strip("`")


# --------------------------------------------------------------------------- #
# Expression emitter
# --------------------------------------------------------------------------- #

class Emitter:
    def __init__(self, config: MappingConfig, report: Report, is_stats: bool = False):
        self.config = config
        self.report = report
        self.is_stats = is_stats  # aggregation context (STATS) vs row context

    def emit(self, node: Node) -> str:
        m = getattr(self, f"_emit_{type(node).__name__}", None)
        if m is None:
            self.report.warn(f"Cannot emit node {type(node).__name__}.")
            return ""
        return m(node)

    def _emit_Lit(self, n: Lit) -> str:
        return n.text

    def _emit_Star(self, n: Star) -> str:
        return "*"

    def _emit_FieldRef(self, n: FieldRef) -> str:
        return _quote_field_if_needed(n.name)

    def _emit_Paren(self, n: Paren) -> str:
        return f"({self.emit(n.inner)})"

    def _emit_Unary(self, n: Unary) -> str:
        if n.op == "not":
            return f"not {self.emit(n.operand)}"
        return f"{n.op}{self.emit(n.operand)}"

    def _emit_Binary(self, n: Binary) -> str:
        return f"{self.emit(n.left)} {n.op} {self.emit(n.right)}"

    def _emit_Cast(self, n: Cast) -> str:
        dql_fn = fns.CAST_TYPES.get(n.type_name)
        if not dql_fn:
            self.report.warn(f"Unknown cast type `{n.type_name}`; left as toString().")
            dql_fn = "toString"
        return f"{dql_fn}({self.emit(n.operand)})"

    def _emit_IsNull(self, n: IsNull) -> str:
        fn = "isNotNull" if n.negated else "isNull"
        return f"{fn}({self.emit(n.operand)})"

    def _emit_InExpr(self, n: InExpr) -> str:
        # DQL static list uses {} not []; the in() function form is robust here.
        items = ", ".join(self.emit(it) for it in n.items)
        expr = f"in({self.emit(n.target)}, {{{items}}})"
        return f"not {expr}" if n.negated else expr

    def _emit_LikeExpr(self, n: LikeExpr) -> str:
        if n.regex:
            return f"matchesRegex({self.emit(n.target)}, {self.emit(n.pattern)})"
        # ES|QL LIKE wildcards (* ?) -> DQL like() SQL wildcards (% _)
        pat = n.pattern
        if isinstance(pat, Lit) and pat.text[:1] in ('"', "'"):
            q = pat.text[0]
            body = pat.text[1:-1]
            converted = body.replace("%", r"\%").replace("_", r"\_").replace("*", "%").replace("?", "_")
            self.report.info("ES|QL LIKE wildcards (*, ?) converted to DQL like() wildcards (%, _).")
            return f"like({self.emit(n.target)}, {q}{converted}{q})"
        self.report.warn("LIKE pattern is not a string literal; wildcard conversion skipped.")
        return f"like({self.emit(n.target)}, {self.emit(n.pattern)})"

    def _emit_CaseExpr(self, n: CaseExpr) -> str:
        # Build nested if(cond, val, else: ...)
        result = self.emit(n.default) if n.default is not None else "null"
        for cond, val in reversed(n.pairs):
            result = f"if({self.emit(cond)}, {self.emit(val)}, else: {result})"
        return result

    def _emit_FuncCall(self, n: FuncCall) -> str:
        name = n.name
        # COUNT(*) / COUNT() -> count()
        table = fns.AGG_FUNCTIONS if self.is_stats and name in fns.AGG_FUNCTIONS else fns.SCALAR_FUNCTIONS
        if name in fns.AGG_FUNCTIONS and (self.is_stats or name == "count"):
            table = fns.AGG_FUNCTIONS
        mapping = table.get(name)
        if mapping is None:
            self.report.manual(
                f"No DQL mapping for function `{name.upper()}(...)`; left as-is for manual review.")
            args = ", ".join(self.emit(a) for a in n.args)
            return f"{name}({args})"
        if mapping.note:
            self.report.warn(mapping.note, source=f"{name.upper()}(...)")
        if not mapping.dql:
            self.report.manual(
                f"`{name.upper()}(...)` has no direct DQL equivalent.", source=f"{name.upper()}(...)")
            args = ", ".join(self.emit(a) for a in n.args)
            return f"{name}({args})"   # passthrough (flagged MANUAL); keeps the expression valid
        # count(*) special-case
        if mapping.dql == "count":
            non_star = [a for a in n.args if not isinstance(a, Star)]
            if not non_star:
                return "count()"
        args = ", ".join(self.emit(a) for a in n.args if not isinstance(a, Star))
        return f"{mapping.dql}({args})"


def _quote_field_if_needed(name: str) -> str:
    # DQL needs backticks around field names containing special characters.
    if name and all(c.isalnum() or c in "._" for c in name):
        return name
    return f"`{name}`"


def translate_expr(expr: str, config: MappingConfig, data_object: Optional[str],
                   report: Report, is_stats: bool = False) -> str:
    tokens = tokenize(expr)
    if not tokens:
        return ""
    parser = ExprParser(tokens, config, data_object, report)
    node = parser.parse()
    return Emitter(config, report, is_stats=is_stats).emit(node)


# --------------------------------------------------------------------------- #
# Command translation
# --------------------------------------------------------------------------- #

class _Ctx:
    """Mutable state threaded across commands of a single query."""

    def __init__(self, config: MappingConfig, report: Report):
        self.config = config
        self.report = report
        self.data_object: Optional[str] = None
        self.is_metrics = False


def _cmd_keyword(segment: str) -> Tuple[str, str]:
    """Return (KEYWORD_lower, remainder)."""
    stripped = segment.strip()
    # commands are single words except a few; split on first whitespace
    parts = stripped.split(None, 1)
    head = parts[0].lower() if parts else ""
    rest = parts[1] if len(parts) > 1 else ""
    return head, rest


def _translate_from(rest: str, ctx: _Ctx) -> Optional[str]:
    # strip METADATA clause
    low = rest.lower()
    if " metadata " in f" {low} ":
        idx = low.find("metadata")
        rest = rest[:idx].rstrip().rstrip(",").rstrip()
        ctx.report.info("FROM ... METADATA clause dropped (no DQL equivalent).")
    indices = split_top_level(rest)
    data_objects = []
    for idx in indices:
        do = ctx.config.resolve_data_object(idx)
        if do is None:
            ctx.report.warn(
                f"Could not map index `{idx.strip()}` to a Dynatrace data object; defaulting to `logs`. "
                "Add an index_map rule in your config.", source=idx.strip())
            do = "logs"
        data_objects.append(do)
    chosen = data_objects[0]
    if len(set(data_objects)) > 1:
        ctx.report.warn(
            f"FROM lists indices mapping to different data objects {sorted(set(data_objects))}; "
            f"using `{chosen}`. Split into separate queries if needed.")
    if chosen == METRICS_SENTINEL:
        ctx.is_metrics = True
        ctx.data_object = None
        ctx.report.manual(
            "Metrics index detected. DQL queries metrics with `timeseries <agg>(metric.key)`, "
            "not `fetch`. The STATS/EVAL pipeline must be rebuilt as a timeseries query - "
            "see the dt-dql-essentials timeseries guidance.")
        return ("timeseries // TODO: metrics use `timeseries avg(<metric.key>), by:{...}` "
                "(not fetch) — rebuild from the metrics index")
    ctx.data_object = chosen
    ctx.report.info(
        f"`fetch {chosen}` has no inherent timeframe - set one via from:/to: or the dashboard timeframe.")
    return f"fetch {chosen}"


def _translate_where(rest: str, ctx: _Ctx) -> Optional[str]:
    dql = translate_expr(rest, ctx.config, ctx.data_object, ctx.report)
    return f"filter {dql}"


def _translate_stats(rest: str, ctx: _Ctx) -> Optional[str]:
    # split BY
    by_fields: List[str] = []
    body = rest
    low = rest.lower()
    # find top-level " by "
    by_idx = _find_top_level_keyword(rest, "by")
    if by_idx is not None:
        body = rest[:by_idx]
        by_clause = rest[by_idx + len("by"):].strip()
        by_fields = split_top_level(by_clause)
    aggs = split_top_level(body)

    # Detect bucket(timefield, interval) in BY -> makeTimeseries route
    bucket = _find_bucket(by_fields)
    emitted_aggs = []
    for a in aggs:
        emitted_aggs.append(_translate_assignment(a, ctx, is_stats=True))
    agg_str = ", ".join(emitted_aggs)

    if bucket is not None:
        interval, remaining_by = bucket
        ctx.report.info(
            "STATS ... BY bucket(time, interval) routed to DQL `makeTimeseries`.")
        other_by = [translate_expr(b, ctx.config, ctx.data_object, ctx.report) for b in remaining_by]
        out = f"makeTimeseries {{{agg_str}}}, interval: {interval}"
        if other_by:
            out += f", by: {{{', '.join(other_by)}}}"
        return out

    out = f"summarize {agg_str}"
    if by_fields:
        by_str = ", ".join(translate_expr(b, ctx.config, ctx.data_object, ctx.report) for b in by_fields)
        out += f", by: {{{by_str}}}"
    return out


def _translate_assignment(text: str, ctx: _Ctx, is_stats: bool) -> str:
    """Translate `alias = expr` or bare `expr`, mapping the alias too."""
    eq = _find_top_level_assign(text)
    if eq is not None:
        # the alias goes through the same field normalization as references to
        # it, so `EVAL dayOfWeek = ...` and a later `BY dayOfWeek` stay aligned
        alias = ctx.config.resolve_field(text[:eq].strip().strip("`"),
                                         ctx.data_object)
        expr = text[eq + 1:].strip()
        dql_expr = translate_expr(expr, ctx.config, ctx.data_object, ctx.report, is_stats=is_stats)
        return f"{_quote_field_if_needed(alias)} = {dql_expr}"
    return translate_expr(text, ctx.config, ctx.data_object, ctx.report, is_stats=is_stats)


def _translate_eval(rest: str, ctx: _Ctx) -> Optional[str]:
    items = split_top_level(rest)
    out = ", ".join(_translate_assignment(it, ctx, is_stats=False) for it in items)
    return f"fieldsAdd {out}"


def _translate_sort(rest: str, ctx: _Ctx) -> Optional[str]:
    items = split_top_level(rest)
    out = []
    for it in items:
        toks = it.split()
        direction = ""
        nulls_note = False
        # detect NULLS FIRST/LAST
        low = it.lower()
        if "nulls" in low:
            nulls_note = True
        # direction
        field_part = it
        for d in ("asc", "desc"):
            if low.rstrip().endswith(d) or f" {d} " in f" {low} ":
                direction = d
        # strip trailing direction / nulls keywords from field
        words = it.split()
        field_words = []
        for w in words:
            if w.lower() in ("asc", "desc", "nulls", "first", "last"):
                continue
            field_words.append(w)
        field_expr = translate_expr(" ".join(field_words), ctx.config, ctx.data_object, ctx.report)
        out.append(f"{field_expr} {direction}".strip())
        if nulls_note:
            ctx.report.warn("SORT ... NULLS FIRST/LAST has no direct DQL equivalent; ordering of nulls may differ.")
    return f"sort {', '.join(out)}"


def _translate_limit(rest: str, ctx: _Ctx) -> Optional[str]:
    return f"limit {rest.strip()}"


def _translate_keep(rest: str, ctx: _Ctx) -> Optional[str]:
    items = split_top_level(rest)
    mapped = []
    for it in items:
        if "*" in it:
            ctx.report.warn(f"KEEP wildcard `{it}` is not supported by DQL `fields`; list fields explicitly.",
                            source=it)
        mapped.append(_quote_field_if_needed(ctx.config.resolve_field(it.strip().strip("`"), ctx.data_object)))
    return f"fields {', '.join(mapped)}"


def _translate_drop(rest: str, ctx: _Ctx) -> Optional[str]:
    items = split_top_level(rest)
    mapped = [_quote_field_if_needed(ctx.config.resolve_field(it.strip().strip("`"), ctx.data_object))
              for it in items]
    return f"fieldsRemove {', '.join(mapped)}"


def _translate_rename(rest: str, ctx: _Ctx) -> Optional[str]:
    # ES|QL: RENAME old AS new [, ...]   (also supports new = old)
    items = split_top_level(rest)
    pairs = []
    for it in items:
        if " as " in f" {it.lower()} ":
            i = it.lower().find(" as ")
            old = it[:i].strip().strip("`")
            new = it[i + 4:].strip().strip("`")
        elif "=" in it:
            new, old = [p.strip().strip("`") for p in it.split("=", 1)]
        else:
            ctx.report.warn(f"Could not parse RENAME clause `{it}`.", source=it)
            continue
        old_m = ctx.config.resolve_field(old, ctx.data_object)
        pairs.append(f"{_quote_field_if_needed(new)} = {_quote_field_if_needed(old_m)}")
    return f"fieldsRename {', '.join(pairs)}"


def _translate_mv_expand(rest: str, ctx: _Ctx) -> Optional[str]:
    fieldname = ctx.config.resolve_field(rest.strip().strip("`"), ctx.data_object)
    return f"expand {_quote_field_if_needed(fieldname)}"


def _translate_dissect(rest: str, ctx: _Ctx) -> Optional[str]:
    parts = split_top_level(rest)  # field "pattern" [APPEND_SEPARATOR=..]
    field_and_pattern = rest.strip()
    ctx.report.manual(
        "DISSECT pattern must be rewritten as a DQL DPL pattern (`parse <field>, \"<DPL>\"`). "
        "ES|QL %{name} placeholders are not valid DPL.", source=field_and_pattern)
    # best-effort skeleton
    sp = field_and_pattern.split(None, 1)
    fld = ctx.config.resolve_field(sp[0].strip().strip("`"), ctx.data_object) if sp else "content"
    pat = sp[1] if len(sp) > 1 else '""'
    return f"parse {_quote_field_if_needed(fld)}, {pat} // TODO: rewrite pattern as DPL"


def _translate_grok(rest: str, ctx: _Ctx) -> Optional[str]:
    ctx.report.manual(
        "GROK pattern must be rewritten as a DQL DPL pattern. Grok %{SYNTAX:name} is not valid DPL.",
        source=rest.strip())
    sp = rest.strip().split(None, 1)
    fld = ctx.config.resolve_field(sp[0].strip().strip("`"), ctx.data_object) if sp else "content"
    pat = sp[1] if len(sp) > 1 else '""'
    return f"parse {_quote_field_if_needed(fld)}, {pat} // TODO: rewrite Grok as DPL"


def _translate_enrich(rest: str, ctx: _Ctx) -> Optional[str]:
    ctx.report.manual(
        "ENRICH maps to a DQL `lookup [ ... ]` subquery, but requires the enrich policy's source data "
        "to be expressed as a DQL fetch. Rebuild manually.", source=rest.strip())
    return f"// TODO ENRICH {rest.strip()} -> lookup [fetch <source> | ...], sourceField:.., lookupField:.."


def _translate_row(rest: str, ctx: _Ctx) -> Optional[str]:
    ctx.report.warn("ROW (literal row) maps to DQL `data record(field = value, ...)`; review syntax.")
    return f"data record({rest.strip()})"


_COMMANDS = {
    "from": _translate_from,
    "where": _translate_where,
    "stats": _translate_stats,
    "eval": _translate_eval,
    "sort": _translate_sort,
    "limit": _translate_limit,
    "keep": _translate_keep,
    "drop": _translate_drop,
    "rename": _translate_rename,
    "mv_expand": _translate_mv_expand,
    "dissect": _translate_dissect,
    "grok": _translate_grok,
    "enrich": _translate_enrich,
    "row": _translate_row,
}


# --------------------------------------------------------------------------- #
# small parsing utilities
# --------------------------------------------------------------------------- #

def _find_top_level_keyword(text: str, keyword: str) -> Optional[int]:
    """Index of a top-level (depth 0, unquoted) keyword like `by`, else None."""
    low = text.lower()
    target = keyword.lower()
    depth = 0
    quote = None
    i = 0
    n = len(text)
    while i < n:
        c = text[i]
        if quote is not None:
            if c == quote:
                quote = None
            i += 1
            continue
        if c in ('"', "'", "`"):
            quote = c
            i += 1
            continue
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif depth == 0 and low.startswith(target, i):
            before = text[i - 1] if i > 0 else " "
            after = text[i + len(target)] if i + len(target) < n else " "
            if not before.isalnum() and before != "_" and not after.isalnum() and after != "_":
                return i
        i += 1
    return None


def _find_top_level_assign(text: str) -> Optional[int]:
    """Index of a top-level single `=` (not ==, !=, <=, >=)."""
    depth = 0
    quote = None
    i = 0
    n = len(text)
    while i < n:
        c = text[i]
        if quote is not None:
            if c == quote:
                quote = None
            i += 1
            continue
        if c in ('"', "'", "`"):
            quote = c
        elif c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif depth == 0 and c == "=":
            prev = text[i - 1] if i > 0 else ""
            nxt = text[i + 1] if i + 1 < n else ""
            if prev not in "=!<>" and nxt != "=":
                return i
        i += 1
    return None


def _find_bucket(by_fields: List[str]) -> Optional[Tuple[str, List[str]]]:
    """If a BY term is bucket(timefield, interval), return (interval, other_by_fields)."""
    remaining = []
    interval = None
    for b in by_fields:
        bl = b.lower().strip()
        if bl.startswith("bucket(") or bl.startswith("date_trunc("):
            inner = b[b.find("(") + 1: b.rfind(")")]
            args = split_top_level(inner)
            if len(args) >= 2:
                interval = _normalize_interval(args[1].strip())
            else:
                interval = "1h"
        else:
            remaining.append(b)
    if interval is None:
        return None
    return interval, remaining


def _normalize_interval(raw: str) -> str:
    """ES|QL interval literal -> DQL duration literal.

    ES|QL accepts `1 hour`, `30 minutes`, `"1h"`, or a number. DQL wants `1h`,
    `30m`, etc.
    """
    s = raw.strip().strip('"').strip("'").lower()
    units = {
        "millisecond": "ms", "milliseconds": "ms", "ms": "ms",
        "second": "s", "seconds": "s", "sec": "s", "s": "s",
        "minute": "m", "minutes": "m", "min": "m", "m": "m",
        "hour": "h", "hours": "h", "h": "h",
        "day": "d", "days": "d", "d": "d",
        "week": "w", "weeks": "w", "w": "w",
    }
    parts = s.split()
    if len(parts) == 2 and parts[1] in units:
        return f"{parts[0]}{units[parts[1]]}"
    # already compact like 1h or 30m
    return s


# --------------------------------------------------------------------------- #
# Public entry point
# --------------------------------------------------------------------------- #

def translate_esql(query: str, config: Optional[MappingConfig] = None) -> EsqlTranslationResult:
    config = config or MappingConfig()
    report = Report()
    ctx = _Ctx(config, report)

    segments = split_pipes(query)
    if not segments:
        report.manual("Empty query.")
        return EsqlTranslationResult("", report, source=query)

    dql_lines: List[str] = []
    for seg in segments:
        head, rest = _cmd_keyword(seg)
        handler = _COMMANDS.get(head)
        if handler is None:
            report.manual(f"Unsupported ES|QL command `{head.upper()}`; passed through commented.",
                          source=seg)
            dql_lines.append(f"// TODO unsupported: {seg}")
            continue
        try:
            out = handler(rest, ctx)
        except Exception as exc:  # never abort the whole conversion on one command
            report.manual(f"Failed to translate `{head.upper()}` command: {exc}", source=seg)
            dql_lines.append(f"// TODO failed: {seg}")
            continue
        if out:
            dql_lines.append(out)

    # join into DQL pipeline form
    dql = ""
    for i, line in enumerate(dql_lines):
        if i == 0:
            dql = line
        elif line.startswith("//"):
            dql += "\n" + line
        else:
            dql += "\n| " + line
    from e2d.dql.validate import lint_into_report
    lint_into_report(dql, report, ctx.data_object)
    return EsqlTranslationResult(dql, report, source=query)
