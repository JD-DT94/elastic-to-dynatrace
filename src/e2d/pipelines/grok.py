"""Grok pattern -> DPL pattern translation (the Track-D hard core, DESIGN §D.2).

A grok string is a mix of literal text, named captures `%{PATTERN:field}` (with
optional `:type` coercion), and a few regex constructs (`(?:...)`, `?`, `|`,
backslash escapes). We map each grok pattern name to its closest DPL matcher and
re-emit the whole thing as a DPL `parse` pattern.

DPL is a different dialect from grok, so the result is a faithful approximation
flagged REVIEW (matching the data-mapping DB triage for `grok.*`): matcher
choices and timestamp formats should be eyeballed against real data.
"""

from __future__ import annotations

import re
from typing import List, Optional, Tuple

from e2d.report import Report

# grok pattern name -> DPL matcher. A tuple carries a default timestamp format.
# `None` matcher means "no faithful DPL matcher" -> caller falls back to LD + REVIEW.
_GROK_TO_DPL = {
    "IPORHOST": "IPADDR", "IP": "IPADDR", "IPV4": "IPV4ADDR", "IPV6": "IPV6ADDR",
    "HOSTNAME": "LD", "HOST": "LD", "SYSLOGHOST": "LD",
    "USER": "LD", "USERNAME": "LD", "NOTSPACE": "LD", "QS": "LD", "QUOTEDSTRING": "LD",
    "WORD": "WORD", "LOGLEVEL": "WORD", "JAVACLASS": "LD",
    "DATA": "LD", "GREEDYDATA": "LD",
    "NUMBER": "DOUBLE", "BASE10NUM": "DOUBLE", "BASE16NUM": "LD",
    "INT": "INT", "POSINT": "INT", "NONNEGINT": "INT",
    "SYSLOGTIMESTAMP": ("TIMESTAMP", "MMM d HH:mm:ss"),
    "HTTPDATE": ("TIMESTAMP", "dd/MMM/yyyy:HH:mm:ss Z"),
    "TIMESTAMP_ISO8601": ("TIMESTAMP", None),  # DPL TIMESTAMP auto-detects ISO8601
    "DATESTAMP": ("TIMESTAMP", "yyyy-MM-dd HH:mm:ss"),
}

# Composite grok patterns (a pattern built from other patterns) — expanded to
# their constituent grok before translation. These are the common Apache/Nginx
# shorthands; without expansion they fall through to a useless bare `LD`.
_GROK_COMPOSITES = {
    "COMMONAPACHELOG": (
        '%{IPORHOST:clientip} %{USER:ident} %{USER:auth} \\[%{HTTPDATE:timestamp}\\] '
        '"%{WORD:verb} %{DATA:request} HTTP/%{NUMBER:httpversion}" '
        '%{NUMBER:response:int} (?:-|%{NUMBER:bytes:int})'),
    "COMBINEDAPACHELOG": '%{COMMONAPACHELOG} %{QS:referrer} %{QS:agent}',
    "HTTPD_COMMONLOG": (
        '%{IPORHOST:clientip} %{USER:ident} %{USER:auth} \\[%{HTTPDATE:timestamp}\\] '
        '"%{WORD:verb} %{DATA:request} HTTP/%{NUMBER:httpversion}" '
        '%{NUMBER:response:int} (?:-|%{NUMBER:bytes:int})'),
    "HTTPD_COMBINEDLOG": '%{HTTPD_COMMONLOG} %{QS:referrer} %{QS:agent}',
    "SYSLOGBASE": '%{SYSLOGTIMESTAMP:timestamp} %{SYSLOGHOST:logsource} %{DATA:program}(?:\\[%{POSINT:pid}\\])?:',
}

_COMPOSITE_REF = re.compile(r"%\{([A-Z0-9_]+)\}")


def _expand_composites(pattern: str, depth: int = 0) -> str:
    """Recursively inline composite grok patterns (field-less `%{NAME}` refs)."""
    if depth > 6:
        return pattern
    return _COMPOSITE_REF.sub(
        lambda m: _expand_composites(_GROK_COMPOSITES[m.group(1)], depth + 1)
        if m.group(1) in _GROK_COMPOSITES else m.group(0),
        pattern)


# grok `:type` coercion overrides the pattern's default matcher.
_TYPE_TO_DPL = {"int": "INT", "long": "LONG", "float": "DOUBLE", "double": "DOUBLE"}

_GROK_TOKEN = re.compile(r"%\{([A-Z0-9_]+)(?::([\w.\[\]@]+))?(?::(\w+))?\}")


def _matcher_for(name: str, typ: Optional[str], report: Report) -> Tuple[str, Optional[str]]:
    """Return (dpl_matcher, timestamp_format_or_None) for one grok pattern."""
    if typ and typ in _TYPE_TO_DPL:
        return _TYPE_TO_DPL[typ], None
    spec = _GROK_TO_DPL.get(name)
    if spec is None:
        report.warn(f"Unknown grok pattern `%{{{name}}}`; emitted `LD` placeholder.", source=name)
        return "LD", None
    if isinstance(spec, tuple):
        return spec[0], spec[1]
    return spec, None


def _emit_literal(text: str, out: List[str]) -> None:
    """Append a DPL single-quoted literal for a run of constant text."""
    if not text:
        return
    out.append("'" + text.replace("'", "\\'") + "'")


def grok_to_dpl(pattern: str, report: Report) -> str:
    """Translate one grok match expression into a DPL `parse` pattern body."""
    pattern = _expand_composites(pattern)   # inline COMBINEDAPACHELOG etc. first
    out: List[str] = []
    lit: List[str] = []           # accumulating literal run
    i = 0
    n = len(pattern)

    def flush_lit() -> None:
        if lit:
            _emit_literal("".join(lit), out)
            lit.clear()

    while i < n:
        ch = pattern[i]
        m = _GROK_TOKEN.match(pattern, i)
        if m:
            flush_lit()
            name, field, typ = m.group(1), m.group(2), m.group(3)
            matcher, fmt = _matcher_for(name, typ, report)
            tok = matcher + (f"('{fmt}')" if fmt else "")
            if field:
                tok += ":" + field
            out.append(tok)
            i = m.end()
            continue
        if pattern.startswith("(?:", i):       # non-capturing group -> DPL group
            flush_lit()
            out.append("(")
            i += 3
            continue
        if ch == "(":
            flush_lit()
            out.append("(")
            i += 1
            continue
        if ch == ")":
            flush_lit()
            out.append(")")
            i += 1
            continue
        if ch == "?":                           # optional quantifier on prev group
            flush_lit()
            out.append("?")
            i += 1
            continue
        if ch == "|":                           # alternation
            flush_lit()
            out.append("|")
            i += 1
            continue
        if ch == "\\" and i + 1 < n:            # escaped literal char
            lit.append(pattern[i + 1])
            i += 2
            continue
        lit.append(ch)
        i += 1

    flush_lit()
    report.warn("grok -> DPL parse pattern is approximate; verify matchers/timestamp formats.",
                source=pattern[:60])
    return _join_tokens(out)


def _join_tokens(tokens: List[str]) -> str:
    """Space-join DPL pattern tokens, gluing a trailing `?` to its group close."""
    parts: List[str] = []
    for tok in tokens:
        if tok == "?" and parts:
            parts[-1] = parts[-1] + "?"
        else:
            parts.append(tok)
    return " ".join(parts)


def dissect_to_dpl(mapping: str, report: Report) -> str:
    """Translate a dissect `%{field}delim%{field}` mapping into a DPL pattern.

    Dissect is pure delimiter splitting: `%{name}` captures up to the next
    literal delimiter. `%{+name}` (append) and `%{}` (skip) are handled.
    """
    out: List[str] = []
    lit: List[str] = []
    i = 0
    n = len(mapping)

    def flush_lit() -> None:
        if lit:
            _emit_literal("".join(lit), out)
            lit.clear()

    field_re = re.compile(r"%\{([+&?]?)([\w.\[\]@]*)\}")
    while i < n:
        m = field_re.match(mapping, i)
        if m:
            flush_lit()
            modifier, field = m.group(1), m.group(2)
            if not field or modifier == "?":
                out.append("LD")                       # skip / named-skip
            elif modifier == "+":
                out.append(f"LD:{field}")              # append -> same field (REVIEW)
                report.warn(f"dissect append `%{{+{field}}}` concatenation is not preserved; "
                            "fields are captured separately.", source=field)
            else:
                out.append(f"LD:{field}")
            i = m.end()
            continue
        lit.append(mapping[i])
        i += 1
    flush_lit()

    report.warn("dissect -> DPL parse pattern is approximate; LD matchers split on the literals.",
                source=mapping[:60])
    return _join_tokens(out)
