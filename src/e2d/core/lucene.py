"""Lucene query-string -> filter IR.

Handles the constructs in the corpus: `field:value`, `field:(A OR B)`,
inclusive `[a TO b]` / exclusive `{a TO b}` ranges, open ranges `>x`/`>=x`,
wildcards `val*`, regex `/.../`, `+`/`-` required/excluded prefixes, explicit
AND/OR/NOT (and `&&`/`||`/`!`), grouping, and bare full-text terms.

Note: Lucene's default operator is OR, but for *filter* migration adjacent
clauses are combined with AND (the safer intent for `+a -b` style filters); this
is flagged INFO so a reviewer can confirm.
"""

from __future__ import annotations

import re
from typing import List, Optional, Tuple

from e2d.config import MappingConfig
from e2d.core.filter_ir import (
    And, Compare, Exists, In, Node, Not, Or, Phrase, Regex, TimeRange, Wildcard,
    TIME_FIELDS, strip_keyword,
)
from e2d.report import Report

# trailing scoring modifiers: `term~2` (fuzzy), `"phrase"~3` (proximity),
# `term^4` (boost). None of them filter; they only affect relevance scoring.
_BOOST_RE = re.compile(r"^(.+)\^(\d+(?:\.\d+)?)$")
_FUZZ_RE = re.compile(r"^(.+)~(\d*(?:\.\d+)?)$")


def _strip_scoring(val: str, report: Report) -> str:
    m = _BOOST_RE.match(val)
    if m:
        val = m.group(1)
        report.info(f"Relevance boost `^{m.group(2)}` dropped (scoring-only; no "
                    "filter semantics).")
    m = _FUZZ_RE.match(val)
    if m:
        val = m.group(1)
        report.warn(f"Fuzziness `~{m.group(2)}` dropped; DQL matches the exact "
                    "value, so fewer records may match than in Elasticsearch.")
    return val

_OPS = {"and": "AND", "or": "OR", "not": "NOT", "&&": "AND", "||": "OR", "!": "NOT"}


def _tokenize(s: str) -> List[Tuple[str, str]]:
    toks: List[Tuple[str, str]] = []
    i, n = 0, len(s)
    while i < n:
        c = s[i]
        if c.isspace():
            i += 1
            continue
        if c in "()[]{}":
            kind = {"(": "LP", ")": "RP", "[": "LB", "]": "RB", "{": "LC", "}": "RC"}[c]
            toks.append((kind, c)); i += 1; continue
        if c == ":":
            toks.append(("COLON", c)); i += 1; continue
        if c == '"':
            j = i + 1; buf = []
            while j < n and s[j] != '"':
                if s[j] == "\\" and j + 1 < n:
                    buf.append(s[j + 1]); j += 2; continue
                buf.append(s[j]); j += 1
            toks.append(("STRING", "".join(buf))); i = j + 1; continue
        if c == "/":
            j = i + 1; buf = []
            while j < n and s[j] != "/":
                if s[j] == "\\" and j + 1 < n:
                    buf.append(s[j + 1]); j += 2; continue
                buf.append(s[j]); j += 1
            toks.append(("REGEX", "".join(buf))); i = j + 1; continue
        if c in "+-":
            # A prefix operator only at a clause boundary (start / after space or
            # `(` `[` `:`) and immediately followed by a non-space — otherwise it
            # is a hyphen/plus inside a value (e.g. `direct-assurance`, `now-1h`).
            boundary = (i == 0) or s[i - 1].isspace() or s[i - 1] in "([:"
            follows = (i + 1 < n) and (not s[i + 1].isspace())
            if boundary and follows:
                toks.append(("PLUS" if c == "+" else "MINUS", c)); i += 1; continue
        # bareword: field name, value, operator, range bound, open-range (>x)
        j = i
        while j < n and not s[j].isspace() and s[j] not in '()[]{}:"/':
            if s[j] == "\\" and j + 1 < n:
                j += 2; continue
            j += 1
        word = s[i:j].replace("\\", "")
        low = word.lower()
        if low in _OPS:
            toks.append(("OP", _OPS[low]))
        elif word == "TO":
            toks.append(("TO", word))
        else:
            toks.append(("WORD", word))
        i = j
    return toks


class _LuceneParser:
    def __init__(self, toks, config, data_object, report):
        self.toks = toks
        self.pos = 0
        self.config = config
        self.data_object = data_object
        self.report = report
        self.implicit_and_noted = False

    def _peek(self, k=0):
        idx = self.pos + k
        return self.toks[idx] if idx < len(self.toks) else (None, None)

    def _next(self):
        t = self._peek()
        if t[0] is not None:
            self.pos += 1
        return t

    def parse(self) -> Optional[Node]:
        return self._or()

    def _or(self) -> Optional[Node]:
        left = self._and()
        children = [left] if left else []
        while self._peek()[0] == "OP" and self._peek()[1] == "OR":
            self._next()
            r = self._and()
            if r:
                children.append(r)
        if len(children) > 1:
            return Or(children)
        return children[0] if children else None

    def _and(self) -> Optional[Node]:
        left = self._unary()
        children = [left] if left else []
        while True:
            kind, val = self._peek()
            if kind == "OP" and val == "AND":
                self._next()
                r = self._unary()
                if r:
                    children.append(r)
            elif kind in ("WORD", "STRING", "LP", "PLUS", "MINUS", "OP") and not (kind == "OP" and val == "OR"):
                # implicit clause juxtaposition -> AND (filter intent)
                if not self.implicit_and_noted:
                    self.report.info("Adjacent Lucene clauses combined with AND (default-OR overridden for filtering).")
                    self.implicit_and_noted = True
                r = self._unary()
                if r:
                    children.append(r)
                else:
                    break
            else:
                break
        if len(children) > 1:
            return And(children)
        return children[0] if children else None

    def _unary(self) -> Optional[Node]:
        kind, val = self._peek()
        if kind == "OP" and val == "NOT":
            self._next()
            return Not(self._unary())
        if kind == "MINUS":
            self._next()
            return Not(self._unary())
        if kind == "PLUS":
            self._next()
            return self._unary()
        return self._primary()

    def _primary(self) -> Optional[Node]:
        kind, val = self._peek()
        if kind == "LP":
            self._next()
            inner = self._or()
            if self._peek()[0] == "RP":
                self._next()
            return inner
        if kind == "WORD" and self._peek(1)[0] == "COLON":
            return self._field_clause()
        if kind in ("WORD", "STRING"):
            self._next()
            if kind == "STRING":
                self._absorb_scoring_suffix()
            return Phrase(text=_strip_scoring(val, self.report) if kind == "WORD" else val)
        # stray token
        self._next()
        return None

    def _is_content(self, field: str) -> bool:
        return self.config.resolve_field(strip_keyword(field),
                                         self.data_object) == "content"

    def _absorb_scoring_suffix(self) -> None:
        """Consume a standalone `~N` / `^N` token following a quoted phrase."""
        kind, val = self._peek()
        if kind == "WORD" and val and val[0] in "~^":
            self._next()
            if val[0] == "~":
                self.report.warn(f"Phrase proximity `{val}` dropped; DQL matches "
                                 "the exact phrase, so fewer records may match.")
            else:
                self.report.info(f"Relevance boost `{val}` dropped (scoring-only).")

    def _field_clause(self) -> Optional[Node]:
        field = self._next()[1]
        self._next()  # colon
        if field == "_exists_":
            # `_exists_:name` is Lucene's field-existence check, not an equality
            kind, val = self._peek()
            if kind in ("WORD", "STRING"):
                self._next()
                return Exists(field=val)
        kind, val = self._peek()
        if kind == "LP":  # field:(A OR B ...)
            self._next()
            values, op = self._value_list()
            if op == "OR":
                return In(field=field, values=values)
            joiner = And if op == "AND" else Or
            return joiner([Compare(field, "==", v) for v in values])
        if kind in ("LB", "LC"):  # range
            return self._range(field, inclusive=(kind == "LB"))
        if kind == "REGEX":
            self._next()
            return Regex(field=field, pattern=val)
        if kind == "STRING":
            self._next()
            self._absorb_scoring_suffix()
            if self._is_content(field):
                return Phrase(text=val, field=field)
            return Compare(field, "==", val)
        if kind == "WORD":
            self._next()
            return self._value_node(field, val)
        return None

    def _value_node(self, field: str, val: str) -> Node:
        # open range like >2000 / >=10
        for op in (">=", "<=", ">", "<"):
            if val.startswith(op):
                return Compare(field, op, _coerce(val[len(op):]))
        val = _strip_scoring(val, self.report)
        if val == "*":
            # `field:*` means "the field exists", not a wildcard match
            return Exists(field=field)
        if "*" in val or "?" in val:
            return Wildcard(field=field, pattern=val)
        if self._is_content(field):
            # ES matches the analyzed value IN the message; == would require the
            # whole log line to equal it
            return Phrase(text=val, field=field)
        return Compare(field, "==", _coerce(val))

    def _value_list(self):
        values = []
        op = "OR"
        while True:
            kind, val = self._peek()
            if kind == "RP" or kind is None:
                self._next()
                break
            if kind == "OP":
                op = val
                self._next()
                continue
            self._next()
            values.append(_coerce(val))
        return values, op

    def _range(self, field: str, inclusive: bool) -> Node:
        # [ lo TO hi ]  or  { lo TO hi }
        self._next()  # consume LB/LC
        lo = self._next()[1]
        if self._peek()[0] == "TO":
            self._next()
        hi = self._next()[1]
        if self._peek()[0] in ("RB", "RC"):
            self._next()
        is_time = strip_keyword(field) in TIME_FIELDS
        gte_key = "gte" if inclusive else "gt"
        lte_key = "lte" if inclusive else "lt"
        lo_v = None if lo == "*" else lo
        hi_v = None if hi == "*" else hi
        if is_time:
            return TimeRange(field=field, **{gte_key: lo_v, lte_key: hi_v})
        parts = []
        if lo_v is not None:
            parts.append(Compare(field, ">=" if inclusive else ">", _coerce(lo_v)))
        if hi_v is not None:
            parts.append(Compare(field, "<=" if inclusive else "<", _coerce(hi_v)))
        return And(parts) if len(parts) > 1 else (parts[0] if parts else None)


def _coerce(v: str):
    try:
        if "." in v:
            return float(v)
        return int(v)
    except (ValueError, TypeError):
        return v


def translate_lucene(query: str, config: MappingConfig, data_object: Optional[str],
                     report: Report) -> Optional[Node]:
    if not query or not query.strip():
        return None
    toks = _tokenize(query)
    return _LuceneParser(toks, config, data_object, report).parse()
