"""Translate a parsed Logstash pipeline into OpenPipeline processing stages.

Each Logstash filter plugin becomes one or more DQL/DPL stages (the processors an
OpenPipeline would run, in order). Conditionals become routing headers or
`filterOut` drops. Constructs with no faithful target (Painless `ruby`, Kafka SOC
mirror) are emitted as MANUAL stubs. The result is a readable processing plan plus
an OK/REVIEW/MANUAL `Report`, consistent with the rest of `e2d`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from e2d.pipelines.grok import grok_to_dpl, dissect_to_dpl
from e2d.pipelines.logstash import Conditional, Pipeline, Plugin, Stmt, Token, _unquote
from e2d.report import Report

# Logstash event fields -> Dynatrace log fields: body is `content`, `@timestamp` is `timestamp`.
_SOURCE_FIELD = {"message": "content", "@timestamp": "timestamp"}
_OP = {"EQ": "==", "NE": "!=", "GE": ">=", "LE": "<=", "GT": ">", "LT": "<"}


def _field(path: str) -> str:
    return _SOURCE_FIELD.get(path, path)


def _dql_str(s: str) -> str:
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


# --------------------------------------------------------------------------- #
# condition translation
# --------------------------------------------------------------------------- #

@dataclass
class _Atom:
    dql: str
    tag: str                       # field | str | num | regex | arr | expr
    items: Optional[List[str]] = None


class _CondParser:
    def __init__(self, tokens: List[Token], report: Report):
        self.t = tokens
        self.i = 0
        self.report = report

    def _peek(self) -> Token:
        return self.t[self.i] if self.i < len(self.t) else ("EOF", "")

    def _next(self) -> Token:
        tok = self._peek()
        self.i += 1
        return tok

    def _is_word(self, w: str) -> bool:
        k, txt = self._peek()
        return k == "WORD" and txt == w

    def parse(self) -> str:
        return self._or()

    def _or(self) -> str:
        left = self._and()
        while self._is_word("or"):
            self._next()
            left = f"{left} or {self._and()}"
        return left

    def _and(self) -> str:
        left = self._not()
        while self._is_word("and"):
            self._next()
            left = f"{left} and {self._not()}"
        return left

    def _not(self) -> str:
        if self._peek()[0] == "NOT" or self._is_word("not"):
            self._next()
            return f"not ({self._cmp()})"
        return self._cmp()

    def _cmp(self) -> str:
        left = self._atom()
        kind = self._peek()[0]
        if kind in _OP:
            self._next()
            right = self._atom()
            return f"{left.dql} {_OP[kind]} {right.dql}"
        if self._is_word("in"):
            self._next()
            right = self._atom()
            if left.tag == "str" and right.tag == "field":
                return f"matchesValue({right.dql}, {left.dql})"
            if right.tag == "arr":
                return f"in({left.dql}, {{{', '.join(right.items or [])}}})"
            return f"in({left.dql}, {right.dql})"
        if kind in ("RMATCH", "NRMATCH"):
            self._next()
            rx = self._atom()
            call = f"matchesRegex({left.dql}, {rx.dql})"
            return call if kind == "RMATCH" else f"not {call}"
        return left.dql  # bare field truthiness

    def _atom(self) -> _Atom:
        kind, txt = self._peek()
        if kind == "LPAREN":
            self._next()
            inner = self._or()
            if self._peek()[0] == "RPAREN":
                self._next()
            return _Atom(f"({inner})", "expr")
        if kind == "LBRACK":
            # field ref `[a][b]` vs array literal `["x","y"]` — disambiguate by lookahead
            if self.i + 1 < len(self.t) and self.t[self.i + 1][0] == "WORD" \
                    and self.i + 2 < len(self.t) and self.t[self.i + 2][0] == "RBRACK":
                return self._field_ref()
            return self._array()
        self._next()
        if kind == "STRING":
            return _Atom(_dql_str(_unquote(txt)), "str")
        if kind == "NUMBER":
            return _Atom(txt, "num")
        if kind == "REGEX":
            # strip the `/.../` delimiters; `\/` is an escaped slash, just a slash in DQL
            return _Atom(_dql_str(txt[1:-1].replace("\\/", "/")), "regex")
        if kind == "WORD":
            return _Atom(txt, "field")
        return _Atom(txt, "expr")

    def _field_ref(self) -> _Atom:
        parts: List[str] = []
        while self._peek()[0] == "LBRACK":
            self._next()
            parts.append(self._next()[1])   # WORD
            if self._peek()[0] == "RBRACK":
                self._next()
        return _Atom(_field(".".join(parts)), "field")

    def _array(self) -> _Atom:
        self._next()  # LBRACK
        items: List[str] = []
        while self._peek()[0] != "RBRACK" and self._peek()[0] != "EOF":
            a = self._atom()
            items.append(a.dql)
            if self._peek()[0] == "COMMA":
                self._next()
        if self._peek()[0] == "RBRACK":
            self._next()
        return _Atom("{" + ", ".join(items) + "}", "arr", items)


def translate_condition(tokens: List[Token], report: Report) -> str:
    if not tokens:
        return "true"
    return _CondParser(tokens, report).parse()


# --------------------------------------------------------------------------- #
# pipeline translation
# --------------------------------------------------------------------------- #

@dataclass
class Stage:
    """One OpenPipeline processor (or a non-processor note for the readable plan)."""
    kind: str                  # 'dql' | 'drop' | 'manual' | 'note'
    dql: str = ""              # DQL statement (dql stages)
    matcher: str = "true"      # record-matching condition that gates this processor
    description: str = ""      # processor description / TODO / note text
    enabled: bool = True


@dataclass
class PipelineResult:
    stages: List[Stage] = field(default_factory=list)
    report: Report = field(default_factory=Report)


def _combine(parent: str, branch: str) -> str:
    if parent == "true":
        return branch
    if branch == "true":
        return parent
    return f"({parent}) and ({branch})"


def _hash_first(value: Any) -> Tuple[Optional[str], Optional[str]]:
    if isinstance(value, dict):
        for k, v in value.items():
            return k, v
    return None, None


def _is_drop_only(body: List[Stmt]) -> bool:
    return len(body) == 1 and isinstance(body[0], Plugin) and body[0].name == "drop"


def _dql(out: List[Stage], stmt: str, matcher: str, desc: str = "") -> None:
    out.append(Stage("dql", dql=stmt, matcher=matcher, description=desc))


def _translate_plugin(p: Plugin, out: List[Stage], report: Report, matcher: str = "true") -> None:
    s = p.settings
    if p.name == "grok":
        src, pat = _hash_first(s.get("match"))
        if pat is None:
            report.warn("grok with no `match` mapping; skipped.")
            return
        _dql(out, f'parse {_field(src)}, "{grok_to_dpl(pat, report)}"', matcher)
        if s.get("tag_on_failure"):
            report.info("grok `tag_on_failure` has no DPL analogue; parse simply yields null on no match.")
        return
    if p.name == "dissect":
        src, pat = _hash_first(s.get("mapping"))
        if pat is None:
            report.warn("dissect with no `mapping`; skipped.")
            return
        _dql(out, f'parse {_field(src)}, "{dissect_to_dpl(pat, report)}"', matcher)
        return
    if p.name == "kv":
        src = _field(s.get("source", "content"))
        fs, vs = s.get("field_split", " "), s.get("value_split", "=")
        # DPL has no faithful one-shot key-value matcher; emit a comment (valid HCL)
        # rather than an invalid `parse ... "KVP{}"` that would fail terraform apply.
        report.manual(f"kv filter on `{src}` (pairs split by {fs!r}, key/value by {vs!r}) has no "
                      "one-to-one DPL matcher — rebuild as a `parse` DPL pattern over the known keys, "
                      "or an AppEngine function.", source="kv")
        out.append(Stage("manual", matcher=matcher, enabled=False,
                         description=f"kv on {src}: split pairs on {fs!r}, key/value on {vs!r}"))
        return
    if p.name == "date":
        match = s.get("match")
        fieldname = match[0] if isinstance(match, list) and match else "timestamp"
        _dql(out, f"fieldsAdd timestamp = toTimestamp({_field(fieldname)})", matcher)
        report.warn("date filter -> toTimestamp(): custom formats may need a DPL TIMESTAMP matcher "
                    "in the parse stage instead.", source="date")
        return
    if p.name == "geoip":
        _dql(out, f"fieldsAdd {s.get('target', 'geo')} = ipToGeolocation({_field(s.get('source', 'content'))})",
             matcher)
        return
    if p.name == "useragent":
        src, tgt = _field(s.get("source", "content")), s.get("target", "ua")
        report.warn("useragent filter -> user-agent parsing; confirm the OpenPipeline UA processor.",
                    source="useragent")
        _dql(out, f"fieldsAdd {tgt} = parseUserAgent({src})", matcher, "TODO confirm UA processor")
        return
    if p.name == "translate":
        src = _field(_strip_brackets(str(s.get("source", ""))))
        tgt = _strip_brackets(str(s.get("target", "lookup_value")))
        dict_path = s.get("dictionary_path", "<dictionary>")
        report.warn(f"translate dictionary `{dict_path}` -> a Grail lookup table + lookup() stage; "
                    "load the dictionary as a table first.", source="translate")
        _dql(out, f"lookup [fetch <lookup_table>], sourceField:{src}, lookupField:key, "
                  f"fields:{{{tgt} = value}}", matcher, f"TODO load {dict_path} as a Grail table")
        return
    if p.name == "mutate":
        _translate_mutate(s, out, report, matcher)
        return
    if p.name == "fingerprint":
        srcs = s.get("source", [])
        tgt = _strip_brackets(str(s.get("target", "fingerprint")))
        joined = ", ".join(_field(_strip_brackets(str(x))) for x in (srcs if isinstance(srcs, list) else [srcs]))
        _dql(out, f"fieldsAdd {tgt} = hashSha256(concat({joined}))", matcher)
        report.info("fingerprint -> hashSha256(); Grail dedup differs, so this is often unnecessary.")
        return
    if p.name in ("ruby", "script"):
        report.manual(f"`{p.name}` runs custom code (Painless/Ruby) with no DQL equivalent; "
                      "reimplement as an AppEngine function or drop.", source=p.name)
        out.append(Stage("manual", matcher=matcher, enabled=False,
                         description=f"{p.name} — custom code, no DPL target"))
        return
    if p.name == "drop":
        out.append(Stage("drop", matcher=matcher, description="unconditional drop"))
        return
    report.warn(f"Unsupported filter plugin `{p.name}`; emitted a comment stub.", source=p.name)
    out.append(Stage("note", description=f"TODO unsupported plugin: {p.name}"))


def _translate_mutate(s: Dict[str, Any], out: List[Stage], report: Report, matcher: str) -> None:
    if isinstance(s.get("add_field"), dict):
        adds = ", ".join(f"{_quote_lhs(k)} = {_dql_str(str(v))}" for k, v in s["add_field"].items())
        _dql(out, f"fieldsAdd {adds}", matcher)
    if isinstance(s.get("rename"), dict):
        for old, new in s["rename"].items():
            _dql(out, f"fieldsRename {_strip_brackets(new)} = {_field(_strip_brackets(old))}", matcher)
    if isinstance(s.get("convert"), dict):
        casts = {"integer": "toLong", "float": "toDouble", "string": "toString", "boolean": "toBoolean"}
        for fld, typ in s["convert"].items():
            f = _field(_strip_brackets(fld))
            _dql(out, f"fieldsAdd {f} = {casts.get(str(typ), 'toString')}({f})", matcher)
    for op, fn in (("lowercase", "lower"), ("uppercase", "upper")):
        if isinstance(s.get(op), list):
            for fld in s[op]:
                f = _field(_strip_brackets(str(fld)))
                _dql(out, f"fieldsAdd {f} = {fn}({f})", matcher)
    if isinstance(s.get("gsub"), list):
        triples = s["gsub"]
        for j in range(0, len(triples) - 2, 3):
            fld = _field(_strip_brackets(str(triples[j])))
            _dql(out, f"fieldsAdd {fld} = replacePattern({fld}, "
                      f"{_dql_str(str(triples[j + 1]))}, {_dql_str(str(triples[j + 2]))})", matcher)
        report.warn("mutate.gsub regex masking -> replacePattern(): verify the RE2/DPL regex dialect "
                    "and backreference syntax.", source="gsub")
    if isinstance(s.get("remove_field"), list):
        flds = ", ".join(_field(_strip_brackets(str(x))) for x in s["remove_field"])
        _dql(out, f"fieldsRemove {flds}", matcher)
    if s.get("add_tag"):
        report.info("mutate.add_tag has no direct DQL field; add a marker via fieldsAdd if needed.")


def _strip_brackets(name: str) -> str:
    return name.replace("[", "").replace("]", ".").strip(".").replace("..", ".") if "[" in name else name


def _quote_lhs(name: str) -> str:
    clean = _strip_brackets(name)
    if all(c.isalnum() or c in "._" for c in clean):
        return clean
    return f"`{clean}`"


def _translate_stmts(stmts: List[Stmt], out: List[Stage], report: Report, matcher: str = "true") -> None:
    for st in stmts:
        if isinstance(st, Plugin):
            _translate_plugin(st, out, report, matcher)
        elif isinstance(st, Conditional):
            _translate_conditional(st, out, report, matcher)


def _translate_conditional(cond: Conditional, out: List[Stage], report: Report, matcher: str) -> None:
    # `if COND { drop {} }` collapses to a single drop processor gated by COND.
    if len(cond.branches) == 1:
        ctoks, body = cond.branches[0]
        if ctoks is not None and _is_drop_only(body):
            out.append(Stage("drop", matcher=_combine(matcher, translate_condition(ctoks, report)),
                             description="drop matching records"))
            return
    report.warn("conditional routing -> OpenPipeline routing rules / per-processor matchers; "
                "branches are flattened to matcher-gated processors (verify exclusivity).",
                source="if/else")
    for ctoks, body in cond.branches:
        branch = "true" if ctoks is None else translate_condition(ctoks, report)
        _translate_stmts(body, out, report, _combine(matcher, branch))


def _summarize_outputs(stmts: List[Stmt], out: List[Stage], report: Report) -> None:
    for st in stmts:
        if isinstance(st, Conditional):
            for ctoks, body in st.branches:
                cond = "else" if ctoks is None else translate_condition(ctoks, report)
                out.append(Stage("note", description=f"output route ({cond}):"))
                _summarize_outputs(body, out, report)
        elif isinstance(st, Plugin):
            if st.name == "elasticsearch":
                idx = st.settings.get("index", "")
                ilm = st.settings.get("ilm_policy")
                note = f"output: Elasticsearch index `{idx}` -> Grail logs"
                if ilm:
                    note += f"; ILM `{ilm}` -> Grail bucket assignment by retention (REVIEW)"
                    report.warn(f"ILM policy `{ilm}` -> map to a Grail bucket with matching retention.",
                                source="ilm")
                out.append(Stage("note", description=note))
            elif st.name == "kafka":
                report.manual("Kafka output (SOC mirror) -> a second Grail consumer / data forwarding; "
                              "no OpenPipeline equivalent.", source="kafka")
                out.append(Stage("note", description="MANUAL: Kafka SOC mirror — separate consumer/forwarder"))
            else:
                out.append(Stage("note", description=f"output: {st.name} (REVIEW)"))


def translate_pipeline(pipe: Pipeline) -> PipelineResult:
    res = PipelineResult()
    _translate_stmts(pipe.filters, res.stages, res.report)
    if pipe.outputs:
        res.stages.append(Stage("note", description="---- outputs ----"))
        _summarize_outputs(pipe.outputs, res.stages, res.report)
    return res


def plan_text(res: PipelineResult) -> str:
    """A readable DQL processing plan: `fetch logs` head + one line per stage."""
    lines = ["fetch logs"]
    for st in res.stages:
        if st.kind == "dql":
            suffix = f"   // when: {st.matcher}" if st.matcher != "true" else ""
            if st.description:
                suffix += f"   // {st.description}"
            lines.append(f"| {st.dql}{suffix}")
        elif st.kind == "drop":
            lines.append(f"| filterOut {st.matcher}"
                         + (f"   // {st.description}" if st.description else ""))
        elif st.kind == "manual":
            lines.append(f"// MANUAL: {st.description}")
        else:  # note
            lines.append(f"// {st.description}")
    return "\n".join(lines)


def render_pipeline(name: str, res: PipelineResult) -> str:
    header = (f"// OpenPipeline processing stages generated from {name}\n"
              f"// Review notes:\n")
    notes = "\n".join("//   " + w.format() for w in res.report.warnings) or "//   (none)"
    return header + notes + "\n\n" + plan_text(res) + "\n"
