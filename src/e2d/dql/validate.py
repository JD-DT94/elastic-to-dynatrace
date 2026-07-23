"""Offline DQL linter.

Text/heuristic rules — there is no full DQL parser here — but each rule is tuned
for high precision (few false positives) over recall. The rules encode pitfalls
from the Dynatrace DQL reference; the most important one, `array-arithmetic`,
catches the exact class of bug a naive `makeTimeseries`/`timeseries` translation
hits: the produced metrics are arrays, so scalar arithmetic on them is invalid
(`a / b` must be element-wise `a[] / b[]`).

Each rule yields a `Finding`; `lint_into_report` folds them into a conversion
`Report` so they surface in the migration report alongside translation warnings.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional

from e2d.report import Report, Severity, Warning


@dataclass
class Finding:
    code: str                 # stable rule id, e.g. "array-arithmetic"
    severity: Severity        # WARN (review) | MANUAL (must fix) | INFO
    message: str              # human-readable, ideally with the fix

    def format(self) -> str:
        return f"[DQL:{self.code}] {self.message}"


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #

# a DQL identifier (field/alias), allowing dotted and backticked forms.
# Wrapped as a non-capturing group so it can be interpolated into larger
# patterns without its internal `|` swallowing the surrounding regex.
_IDENT = r"(?:`[^`]+`|[A-Za-z_][\w.]*)"


def _stages(dql: str) -> List[str]:
    """Split a DQL pipeline into its stages (head + each `|`-led command)."""
    # stages are separated by `|` at line starts or inline; normalise first
    parts = re.split(r"\n\s*\|\s*|\s\|\s", dql.strip())
    return [p.strip() for p in parts if p.strip()]


def _timeseries_aliases(stages: List[str]) -> List[str]:
    """Names that become **arrays** because a `timeseries`/`makeTimeseries`
    command defined them (either `cmd alias = ...` or `cmd {a = .., b = ..}`)."""
    aliases: List[str] = []
    for st in stages:
        m = re.match(r"(?:make)?[Tt]imeseries\b(.*)", st)
        if not m:
            continue
        spec = m.group(1)
        brace = re.search(r"\{(.*)\}", spec, re.S)
        body = brace.group(1) if brace else spec
        # capture each `<ident> =` that is not `==`
        for am in re.finditer(rf"({_IDENT})\s*=(?!=)", body):
            aliases.append(am.group(1).strip("`"))
    return aliases


# --------------------------------------------------------------------------- #
# rules
# --------------------------------------------------------------------------- #

def lint_dql(dql: str, data_object: Optional[str] = None) -> List[Finding]:
    findings: List[Finding] = []
    stages = _stages(dql)

    # -- array-arithmetic: scalar math on timeseries arrays ------------------ #
    arrays = _timeseries_aliases(stages)
    if arrays:
        # only inspect stages AFTER the first timeseries command
        ts_idx = next(i for i, s in enumerate(stages)
                      if re.match(r"(?:make)?[Tt]imeseries\b", s))
        tail = " ".join(stages[ts_idx + 1:])
        for a in dict.fromkeys(arrays):
            ref = re.escape(a)
            # alias adjacent to an arithmetic operator, not already `alias[]` and
            # not a function call `alias(`
            bad = (rf"(?<![\w.`]){ref}(?![\w.`(\[])\s*[-+*/]"
                   rf"|[-+*/]\s*(?<![\w.`]){ref}(?![\w.`(\[])")
            if re.search(bad, tail):
                findings.append(Finding(
                    "array-arithmetic", Severity.WARN,
                    f"`{a}` is a timeseries array after timeseries/makeTimeseries; "
                    f"arithmetic must be element-wise — write `{a}[]` (e.g. `a[] / b[]`)."))

    # -- deprecated entity namespace ----------------------------------------- #
    for m in dict.fromkeys(re.findall(r"dt\.entity\.[\w.]+", dql)):
        findings.append(Finding(
            "deprecated-entity-field", Severity.WARN,
            f"`{m}` uses the deprecated `dt.entity.*` namespace; use the real data "
            f"field (e.g. `service.name`) or `dt.smartscape.*` for topology."))

    # -- static list written with [] instead of {} --------------------------- #
    if re.search(r"\bin\s*\(\s*" + _IDENT + r"\s*,\s*\[", dql):
        findings.append(Finding(
            "static-list-brackets", Severity.WARN,
            "`in(field, [..])` uses `[]` which wraps a sub-query; a static list "
            "needs braces: `in(field, {\"a\", \"b\"})`."))

    # -- by: without braces -------------------------------------------------- #
    if re.search(r"\bby:\s*(?!\{)" + _IDENT, dql):
        findings.append(Finding(
            "by-without-braces", Severity.WARN,
            "`by:` field lists must be wrapped in braces, e.g. `by: {service.name}`."))

    # -- block comments are not valid DQL (only // line comments) ------------ #
    if "/*" in dql or "*/" in dql:
        findings.append(Finding(
            "block-comment", Severity.MANUAL,
            "DQL has no block comments (`/* */`) — only line comments (`//`). A `/* */` "
            "will fail to parse; convert it to `//`."))

    # -- metrics use timeseries, not fetch ----------------------------------- #
    if re.search(r"\bfetch\s+dt\.metrics?\b", dql):
        findings.append(Finding(
            "fetch-metric", Severity.MANUAL,
            "metrics are not fetched — use `timeseries avg(<metric.key>)` instead of "
            "`fetch dt.metric`."))

    # -- percentile/median/percentRank in a metric `timeseries` need rollup: -- #
    # Applies ONLY to the `timeseries` command (pre-aggregated metrics). NOT to
    # `makeTimeseries`, which percentiles raw events and has no `rollup:` param.
    # (`makeTimeseries` has a capital T, so a lowercase `timeseries\b` won't match it.)
    if re.search(r"(?<![A-Za-z])timeseries\b", dql) and \
       re.search(r"\b(?:percentile|median|percentRank)\s*\(", dql) and \
       "rollup:" not in dql:
        findings.append(Finding(
            "percentile-needs-rollup", Severity.WARN,
            "`percentile`/`median`/`percentRank` in a metric `timeseries` need `rollup:` "
            "(e.g. `rollup: avg`) or the query silently returns no data."))

    # -- count() takes no argument (countIf/countDistinct do) ---------------- #
    # match `count(` with something other than `)` next, but not countIf/countDistinct
    if re.search(r"(?<![A-Za-z])count\(\s*[^)\s]", dql):
        findings.append(Finding(
            "count-arity", Severity.MANUAL,
            "`count()` takes no argument — use `count()` to count records, `countIf(<cond>)` for a "
            "conditional count, or `countDistinct(<field>)` for cardinality."))

    # -- function-name pitfalls ---------------------------------------------- #
    for wrong, right in (("toLowercase", "lower"), ("toUppercase", "upper"),
                         ("length", "stringLength")):
        if re.search(rf"\b{wrong}\s*\(", dql):
            findings.append(Finding(
                "wrong-function-name", Severity.WARN,
                f"`{wrong}()` is not a DQL function; use `{right}()`."))

    # -- assignment '=' used where comparison '==' is meant (filter only) ---- #
    for st in stages:
        if re.match(r"filter(?:Out)?\b", st):
            # a single '=' not part of ==, <=, >=, != ; ignore named params (k: v)
            if re.search(r"(?<![=!<>:])=(?![=])", st):
                findings.append(Finding(
                    "assignment-in-filter", Severity.WARN,
                    "`filter` uses `==` for equality; a single `=` is assignment "
                    f"and will not compare — check: `{st}`."))
                break

    return findings


def lint_into_report(dql: str, report: Report, data_object: Optional[str] = None) -> List[Finding]:
    """Lint `dql` and fold each finding into `report` (so it appears in the
    migration report). Returns the findings for callers that want them too."""
    findings = lint_dql(dql, data_object)
    for f in findings:
        report.warnings.append(Warning(f.severity, f.format()))
    return findings
