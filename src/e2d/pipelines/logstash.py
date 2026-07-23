"""A focused Logstash `.conf` parser (DESIGN §D.4).

Not a full Logstash grammar — it covers the shape these pipelines actually use:
`input{} filter{} output{}` blocks, `plugin { key => value }` invocations,
`if / else if / else` conditionals, and value forms string / number / bareword /
array `[...]` / hash `{ k => v ... }` (hash entries may be comma- or
whitespace-separated, as Logstash allows). Anything unrecognised is surfaced by
the translator as REVIEW/MANUAL rather than silently dropped.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Tuple, Union

Token = Tuple[str, str]  # (kind, text)

_TOKEN_RE = re.compile(
    r"""
      (?P<WS>\s+)
    | (?P<COMMENT>\#[^\n]*)
    | (?P<ARROW>=>)
    | (?P<EQ>==)
    | (?P<NE>!=)
    | (?P<RMATCH>=~)
    | (?P<NRMATCH>!~)
    | (?P<GE>>=)
    | (?P<LE><=)
    | (?P<GT>>)
    | (?P<LT><)
    | (?P<NOT>!)
    | (?P<LBRACE>\{)
    | (?P<RBRACE>\})
    | (?P<LBRACK>\[)
    | (?P<RBRACK>\])
    | (?P<LPAREN>\()
    | (?P<RPAREN>\))
    | (?P<COMMA>,)
    | (?P<STRING>"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')
    | (?P<REGEX>/(?:[^/\\]|\\.)*/)
    | (?P<NUMBER>-?\d+(?:\.\d+)?)
    | (?P<WORD>[A-Za-z_][\w.]*)
    """,
    re.VERBOSE,
)


def tokenize(text: str) -> List[Token]:
    tokens: List[Token] = []
    pos = 0
    n = len(text)
    while pos < n:
        m = _TOKEN_RE.match(text, pos)
        if not m:
            raise ValueError(f"Logstash parse: unexpected character {text[pos]!r} at offset {pos}")
        pos = m.end()
        kind = m.lastgroup
        if kind in ("WS", "COMMENT"):
            continue
        tokens.append((kind, m.group()))
    return tokens


# ---- AST ------------------------------------------------------------------

@dataclass
class Plugin:
    name: str
    settings: Dict[str, Any]   # value: str | float | list | dict


@dataclass
class Conditional:
    # ordered (condition_tokens, body) branches; the trailing `else` has cond None
    branches: List[Tuple[Union[List[Token], None], List["Stmt"]]] = field(default_factory=list)


Stmt = Union[Plugin, Conditional]


@dataclass
class Pipeline:
    inputs: List[Stmt] = field(default_factory=list)
    filters: List[Stmt] = field(default_factory=list)
    outputs: List[Stmt] = field(default_factory=list)


class _Parser:
    def __init__(self, tokens: List[Token]):
        self.toks = tokens
        self.i = 0

    def _peek(self) -> Token:
        return self.toks[self.i] if self.i < len(self.toks) else ("EOF", "")

    def _next(self) -> Token:
        tok = self._peek()
        self.i += 1
        return tok

    def _expect(self, kind: str) -> Token:
        tok = self._next()
        if tok[0] != kind:
            raise ValueError(f"Logstash parse: expected {kind}, got {tok}")
        return tok

    def parse(self) -> Pipeline:
        pipe = Pipeline()
        while self._peek()[0] != "EOF":
            section = self._expect("WORD")[1]
            self._expect("LBRACE")
            stmts = self._parse_stmts()
            self._expect("RBRACE")
            if section == "input":
                pipe.inputs = stmts
            elif section == "filter":
                pipe.filters = stmts
            elif section == "output":
                pipe.outputs = stmts
        return pipe

    def _parse_stmts(self) -> List[Stmt]:
        stmts: List[Stmt] = []
        while self._peek()[0] not in ("RBRACE", "EOF"):
            if self._peek() == ("WORD", "if"):
                stmts.append(self._parse_conditional())
            else:
                stmts.append(self._parse_plugin())
        return stmts

    def _parse_conditional(self) -> Conditional:
        cond = Conditional()
        self._expect("WORD")  # 'if'
        cond_toks = self._parse_condition_tokens()
        body = self._parse_block()
        cond.branches.append((cond_toks, body))
        while self._peek() == ("WORD", "else"):
            self._next()  # else
            if self._peek() == ("WORD", "if"):
                self._next()
                ct = self._parse_condition_tokens()
                cond.branches.append((ct, self._parse_block()))
            else:
                cond.branches.append((None, self._parse_block()))
                break
        return cond

    def _parse_condition_tokens(self) -> List[Token]:
        """Collect everything up to the branch-opening `{` (paren depth 0)."""
        out: List[Token] = []
        depth = 0
        while True:
            kind, txt = self._peek()
            if kind == "EOF":
                raise ValueError("Logstash parse: unterminated condition")
            if kind == "LPAREN":
                depth += 1
            elif kind == "RPAREN":
                depth -= 1
            elif kind == "LBRACE" and depth == 0:
                break
            out.append(self._next())
        return out

    def _parse_block(self) -> List[Stmt]:
        self._expect("LBRACE")
        stmts = self._parse_stmts()
        self._expect("RBRACE")
        return stmts

    def _parse_plugin(self) -> Plugin:
        name = self._expect("WORD")[1]
        self._expect("LBRACE")
        settings: Dict[str, Any] = {}
        while self._peek()[0] != "RBRACE":
            key_kind, key = self._next()
            if key_kind not in ("WORD", "STRING"):
                raise ValueError(f"Logstash parse: bad setting key {(key_kind, key)}")
            key = _unquote(key) if key_kind == "STRING" else key
            self._expect("ARROW")
            settings[key] = self._parse_value()
            if self._peek()[0] == "COMMA":
                self._next()
        self._expect("RBRACE")
        return Plugin(name=name, settings=settings)

    def _parse_value(self) -> Any:
        kind, txt = self._peek()
        if kind == "LBRACK":
            return self._parse_array()
        if kind == "LBRACE":
            return self._parse_hash()
        self._next()
        if kind == "STRING":
            return _unquote(txt)
        if kind == "NUMBER":
            return float(txt) if "." in txt else int(txt)
        if kind == "REGEX":
            return {"__regex__": txt[1:-1]}
        return txt  # bareword (true/false/identifiers)

    def _parse_array(self) -> List[Any]:
        self._expect("LBRACK")
        items: List[Any] = []
        while self._peek()[0] != "RBRACK":
            items.append(self._parse_value())
            if self._peek()[0] == "COMMA":
                self._next()
        self._expect("RBRACK")
        return items

    def _parse_hash(self) -> Dict[str, Any]:
        self._expect("LBRACE")
        out: Dict[str, Any] = {}
        while self._peek()[0] != "RBRACE":
            k_kind, k = self._next()
            key = _unquote(k) if k_kind == "STRING" else k
            self._expect("ARROW")
            out[key] = self._parse_value()
            if self._peek()[0] == "COMMA":
                self._next()
        self._expect("RBRACE")
        return out


def _unquote(s: str) -> str:
    if len(s) >= 2 and s[0] in "\"'" and s[-1] == s[0]:
        inner = s[1:-1]
        return inner.replace("\\" + s[0], s[0]).replace("\\\\", "\\")
    return s


def parse_logstash(text: str) -> Pipeline:
    return _Parser(tokenize(text)).parse()
