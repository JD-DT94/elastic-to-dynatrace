"""Lexing helpers for ES|QL.

Two levels of splitting:

* `split_pipes`     - split a full ES|QL query into its `|`-delimited commands,
                      respecting quotes and bracket/paren nesting.
* `split_top_level` - split a comma- (or other delimiter-) separated list while
                      respecting quotes and nesting (used for STATS/KEEP/EVAL args).
* `tokenize`        - turn a single expression into a flat list of typed tokens,
                      which the expression translator rewrites.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List

_QUOTES = {'"', "'", "`"}
_OPEN = {"(": ")", "[": "]", "{": "}"}
_CLOSE = {")", "]", "}"}


def _split_respecting_nesting(text: str, delimiters: set) -> List[str]:
    """Split `text` on any single char in `delimiters` at nesting depth 0.

    Quotes (", ', `) and bracket pairs are honoured so delimiters inside them
    are ignored. ES|QL escapes quotes by doubling them (and `\\` inside strings);
    both are handled.
    """
    parts: List[str] = []
    buf: List[str] = []
    depth = 0
    quote = None
    i = 0
    n = len(text)
    while i < n:
        c = text[i]
        if quote is not None:
            buf.append(c)
            if c == "\\" and quote != "`" and i + 1 < n:
                # escaped char inside a string literal
                buf.append(text[i + 1])
                i += 2
                continue
            if c == quote:
                # doubled quote is an escaped quote, not a terminator
                if i + 1 < n and text[i + 1] == quote:
                    buf.append(text[i + 1])
                    i += 2
                    continue
                quote = None
            i += 1
            continue
        if c in _QUOTES:
            quote = c
            buf.append(c)
        elif c in _OPEN:
            depth += 1
            buf.append(c)
        elif c in _CLOSE:
            depth = max(0, depth - 1)
            buf.append(c)
        elif depth == 0 and c in delimiters:
            parts.append("".join(buf))
            buf = []
        else:
            buf.append(c)
        i += 1
    parts.append("".join(buf))
    return parts


def split_pipes(query: str) -> List[str]:
    """Split a full ES|QL query into trimmed, non-empty command segments."""
    # Normalise newlines to spaces so multi-line queries tokenize the same.
    flat = " ".join(line.strip() for line in query.splitlines())
    segments = _split_respecting_nesting(flat, {"|"})
    return [s.strip() for s in segments if s.strip()]


def split_top_level(text: str, delimiter: str = ",") -> List[str]:
    """Split a comma-separated argument/field list respecting nesting."""
    parts = _split_respecting_nesting(text, {delimiter})
    return [p.strip() for p in parts if p.strip()]


# --------------------------------------------------------------------------- #
# Expression tokenizer
# --------------------------------------------------------------------------- #

TT_IDENT = "ident"
TT_NUMBER = "number"
TT_STRING = "string"
TT_OP = "op"
TT_PUNCT = "punct"


@dataclass
class Token:
    type: str
    value: str


# Multi-char operators must be tried before single-char ones.
_MULTI_OPS = ["==", "!=", "<=", ">=", "::", "=~"]
_SINGLE_OPS = set("+-*/%<>=")
_PUNCT = set("(),.")


def tokenize(expr: str) -> List[Token]:
    tokens: List[Token] = []
    i = 0
    n = len(expr)
    while i < n:
        c = expr[i]
        if c.isspace():
            i += 1
            continue
        # string literals (ES|QL uses double quotes; allow single too)
        if c in ('"', "'"):
            quote = c
            j = i + 1
            buf = [c]
            while j < n:
                cj = expr[j]
                buf.append(cj)
                if cj == "\\" and j + 1 < n:
                    buf.append(expr[j + 1])
                    j += 2
                    continue
                if cj == quote:
                    if j + 1 < n and expr[j + 1] == quote:  # doubled escape
                        buf.append(expr[j + 1])
                        j += 2
                        continue
                    j += 1
                    break
                j += 1
            tokens.append(Token(TT_STRING, "".join(buf)))
            i = j
            continue
        # backtick-quoted identifier
        if c == "`":
            j = i + 1
            buf = [c]
            while j < n:
                buf.append(expr[j])
                if expr[j] == "`":
                    j += 1
                    break
                j += 1
            tokens.append(Token(TT_IDENT, "".join(buf)))
            i = j
            continue
        # numbers
        if c.isdigit() or (c == "." and i + 1 < n and expr[i + 1].isdigit()):
            j = i
            while j < n and (expr[j].isdigit() or expr[j] in ".eE+-"):
                # allow exponent sign only right after e/E
                if expr[j] in "+-" and (j == i or expr[j - 1] not in "eE"):
                    break
                j += 1
            tokens.append(Token(TT_NUMBER, expr[i:j]))
            i = j
            continue
        # identifiers / keywords (field paths may contain dots, handled as PUNCT)
        if c.isalpha() or c == "_" or c == "@":
            j = i
            while j < n and (expr[j].isalnum() or expr[j] in "_@"):
                j += 1
            tokens.append(Token(TT_IDENT, expr[i:j]))
            i = j
            continue
        # multi-char operators
        matched = False
        for op in _MULTI_OPS:
            if expr.startswith(op, i):
                tokens.append(Token(TT_OP, op))
                i += len(op)
                matched = True
                break
        if matched:
            continue
        if c in _SINGLE_OPS:
            tokens.append(Token(TT_OP, c))
            i += 1
            continue
        if c in _PUNCT:
            tokens.append(Token(TT_PUNCT, c))
            i += 1
            continue
        # unknown char - keep it so the translator can flag it
        tokens.append(Token(TT_PUNCT, c))
        i += 1
    return tokens
