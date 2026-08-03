"""KQL (Kibana Query Language / kuery) -> DQL boolean-expression translator.

Used for dashboard panel queries (`searchSourceJSON.query`) and for the KQL
embedded inside `filters` aggregations. Produces a DQL expression string
suitable for a `filter` command or a `countIf(...)` predicate.

Supported: `field : value`, `field : (a or b)` -> in(), `field : *` -> isNotNull,
wildcards (`*`) -> matchesValue, ranges (`>`,`>=`,`<`,`<=`), AND/OR/NOT,
parentheses, and bare full-text terms -> matchesPhrase(content, ...).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, List, Optional

from e2d.config import MappingConfig
from e2d.report import Report


# --------------------------------------------------------------------------- #
# tokenizer
# --------------------------------------------------------------------------- #

T_WORD = "word"
T_STRING = "string"
T_COLON = "colon"
T_OP = "op"
T_LP = "lparen"
T_RP = "rparen"


@dataclass
class K:
    type: str
    value: str


def _tokenize(s: str) -> List[K]:
    toks: List[K] = []
    i, n = 0, len(s)
    while i < n:
        c = s[i]
        if c.isspace():
            i += 1
            continue
        if c == '"':
            j = i + 1
            buf = []
            while j < n:
                if s[j] == "\\" and j + 1 < n:
                    buf.append(s[j + 1])
                    j += 2
                    continue
                if s[j] == '"':
                    j += 1
                    break
                buf.append(s[j])
                j += 1
            toks.append(K(T_STRING, "".join(buf)))
            i = j
            continue
        if c == "(":
            toks.append(K(T_LP, c)); i += 1; continue
        if c == ")":
            toks.append(K(T_RP, c)); i += 1; continue
        if c == ":":
            toks.append(K(T_COLON, c)); i += 1; continue
        if c in "<>":
            if i + 1 < n and s[i + 1] == "=":
                toks.append(K(T_OP, c + "=")); i += 2; continue
            toks.append(K(T_OP, c)); i += 1; continue
        # bareword: letters, digits, dots, wildcards, common field chars
        j = i
        while j < n and not s[j].isspace() and s[j] not in '():<>"':
            j += 1
        toks.append(K(T_WORD, s[i:j]))
        i = j
    return toks


# --------------------------------------------------------------------------- #
# parser + emitter (single pass, emits DQL string)
# --------------------------------------------------------------------------- #

class KqlParser:
    def __init__(self, tokens: List[K], config: MappingConfig,
                 data_object: Optional[str], report: Report):
        self.toks = tokens
        self.pos = 0
        self.config = config
        self.data_object = data_object
        self.report = report

    def _peek(self) -> Optional[K]:
        return self.toks[self.pos] if self.pos < len(self.toks) else None

    def _next(self) -> Optional[K]:
        t = self._peek()
        if t:
            self.pos += 1
        return t

    def _is_kw(self, word: str) -> bool:
        t = self._peek()
        return t is not None and t.type == T_WORD and t.value.lower() == word

    def parse(self) -> str:
        if not self.toks:
            return ""
        return self._or()

    def _skip_dup_ops(self) -> None:
        # tolerate authoring typos like `a and AND b` — redundant operators
        while True:
            t = self._peek()
            if t is not None and t.type == T_WORD and t.value.lower() in ("and", "or"):
                self.report.info(f"Skipped redundant KQL operator `{t.value}`.")
                self._next()
            else:
                break

    def _or(self) -> str:
        left = self._and()
        while self._is_kw("or"):
            self._next()
            self._skip_dup_ops()
            right = self._and()
            left = f"{left} or {right}"
        return left

    def _and(self) -> str:
        left = self._not()
        while True:
            if self._is_kw("and"):
                self._next()
                self._skip_dup_ops()
                right = self._not()
                left = f"{left} and {right}"
            elif self._implicit_and():
                # adjacent expressions with no operator -> AND (KQL default)
                right = self._not()
                left = f"{left} and {right}"
            else:
                break
        return left

    def _implicit_and(self) -> bool:
        t = self._peek()
        if t is None:
            return False
        if t.type in (T_RP,):
            return False
        if t.type == T_WORD and t.value.lower() in ("and", "or"):
            return False
        return t.type in (T_WORD, T_STRING, T_LP)

    def _not(self) -> str:
        if self._is_kw("not"):
            self._next()
            return f"not ({self._primary()})"
        return self._primary()

    def _primary(self) -> str:
        t = self._peek()
        if t is None:
            return ""
        if t.type == T_LP:
            self._next()
            inner = self._or()
            if self._peek() and self._peek().type == T_RP:
                self._next()
            return f"({inner})"
        if t.type in (T_STRING, T_WORD):
            # lookahead for ':' (field match — KQL allows quoted field names)
            # or operator (range)
            nxt = self.toks[self.pos + 1] if self.pos + 1 < len(self.toks) else None
            if nxt and nxt.type == T_COLON:
                return self._field_match()
            if t.type == T_WORD and nxt and nxt.type == T_OP:
                return self._range()
            # bare term / quoted phrase
            self._next()
            return self._full_text(t.value)
        self._next()
        return ""

    # -- field expressions ------------------------------------------------
    def _resolve(self, raw_field: str) -> str:
        name = raw_field
        if name.endswith(".keyword"):
            name = name[: -len(".keyword")]
            self.report.info(f"Dropped `.keyword` suffix from `{raw_field}`.")
        return self.config.resolve_field(name, self.data_object)

    def _field_match(self) -> str:
        field_tok = self._next()  # word
        self._next()  # colon
        field = self._resolve(field_tok.value)
        nxt = self._peek()
        if nxt and nxt.type == T_LP:
            return self._value_list(field)
        val = self._next()
        if val is None:
            return ""
        if val.type == T_WORD and val.value == "*":
            return f"isNotNull({_q(field)})"
        return _match(field, val.value, val.type == T_STRING, self.report)

    def _value_list(self, field: str) -> str:
        self._next()  # '('
        values: List[str] = []
        op = "or"
        while True:
            t = self._peek()
            if t is None or t.type == T_RP:
                break
            if t.type == T_WORD and t.value.lower() in ("or", "and"):
                op = t.value.lower()
                self._next()
                continue
            tok = self._next()
            values.append(tok.value)
        if self._peek() and self._peek().type == T_RP:
            self._next()
        if op == "or" and all("*" not in v for v in values):
            items = ", ".join(_lit(v) for v in values)
            return f"in({_q(field)}, {{{items}}})"
        joiner = f" {op} "
        return "(" + joiner.join(_match(field, v, True, self.report) for v in values) + ")"

    def _range(self) -> str:
        field_tok = self._next()
        op_tok = self._next()
        val = self._next()
        field = self._resolve(field_tok.value)
        rhs = val.value if val else ""
        return f"{_q(field)} {op_tok.value} {_lit(rhs)}"

    def _full_text(self, term: str) -> str:
        # bare term / quoted phrase with no field -> match against log body
        target = "content" if (self.data_object in (None, "logs")) else "content"
        self.report.warn(
            f"Bare full-text term `{term}` mapped to matchesPhrase({target}, ...); "
            "verify the target field for this data object.")
        return f'matchesPhrase({target}, "{_esc(term)}")'


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #

def _esc(s: str) -> str:
    return s.replace("\\", "\\\\").replace('"', '\\"')


def _q(field: str) -> str:
    if field and all(ch.isalnum() or ch in "._" for ch in field):
        return field
    return f"`{field}`"


def _lit(v: str) -> str:
    # numbers and booleans pass through; everything else becomes a quoted string
    low = v.lower()
    if low in ("true", "false"):
        return low
    try:
        float(v)
        return v
    except ValueError:
        return f'"{_esc(v)}"'


def _match(field: str, value: str, was_quoted: bool, report: Report) -> str:
    fq = _q(field)
    if "*" in value or "?" in value:
        # KQL wildcards -> DQL matchesValue (supports leading/trailing *)
        report.info(f"KQL wildcard `{value}` mapped to matchesValue().")
        return f'matchesValue({fq}, "{_esc(value)}")'
    if field == "content":
        # ES matches analyzed text (the value occurring IN the message); DQL ==
        # would require the whole log line to equal the value, which is silently
        # wrong for the log body.
        report.info("Match on the log body mapped to matchesPhrase(content, ...); "
                    "`==` would require the entire log line to equal the value.")
        return f'matchesPhrase({fq}, "{_esc(value)}")'
    # A quoted KQL value is always a string, even if it looks numeric ("1").
    rhs = f'"{_esc(value)}"' if was_quoted else _lit(value)
    return f"{fq} == {rhs}"


def translate_kql(query: str, config: MappingConfig, data_object: Optional[str],
                  report: Report) -> str:
    """Translate a KQL string into a DQL boolean expression. Empty -> ''."""
    if not query or not query.strip():
        return ""
    tokens = _tokenize(query)
    parser = KqlParser(tokens, config, data_object, report)
    out = parser.parse()
    if parser.pos < len(tokens):
        rest = " ".join(t.value for t in tokens[parser.pos:])
        report.warn(f"KQL query only partially translated; unparsed trailing input `{rest[:60]}` "
                    "was dropped — review.", source=query[:80])
    return out


def translate_query_string(query: Any, language: Optional[str], config: MappingConfig,
                           data_object: Optional[str], report: Report) -> str:
    """Translate a Kibana query in either language (kuery or lucene) into a DQL
    boolean expression string. Empty/untranslatable -> ''."""
    if not query or not str(query).strip():
        return ""
    if language == "lucene":
        from e2d.core.filter_ir import emit_filter
        from e2d.core.lucene import translate_lucene
        node = translate_lucene(str(query), config, data_object, report)
        return emit_filter(node, config, data_object, report) if node is not None else ""
    return translate_kql(str(query), config, data_object, report)
