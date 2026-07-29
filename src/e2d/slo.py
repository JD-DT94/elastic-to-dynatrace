"""Kibana SLOs -> Dynatrace SLOs.

Kibana SLO definitions (8.8+) carry an indicator (how the SLI is measured),
an objective target, a time window and a budgeting method. Dynatrace SLOs are
built on a DQL query that yields a field named ``sli``, so the custom-KQL
indicator translates directly: the good/total KQL pair becomes ``countIf``
conditions through the same KQL translator the rest of the toolkit uses.

Covered: ``sli.kql.custom`` (good/total/filter KQL over an index).
Flagged for manual work: APM indicators (latency/error-rate map better to
Dynatrace's built-in service SLOs), metric-based indicators, and the
``timeslices`` budgeting method (Dynatrace evaluates budget over the whole
window).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field as dc_field
from typing import Any, Dict, List, Optional

from e2d.config import MappingConfig
from e2d.report import Report


@dataclass
class SloResult:
    name: str
    dql: str = ""
    target_pct: Optional[float] = None
    window: str = ""
    budgeting: str = ""
    report: Report = dc_field(default_factory=Report)


def looks_like_slo(doc: Any) -> bool:
    return (isinstance(doc, dict) and "indicator" in doc
            and ("objective" in doc or "budgetingMethod" in doc))


def _kql_condition(kql: Any, config: MappingConfig, data_object: str,
                   report: Report) -> str:
    """One KQL clause -> a DQL boolean expression (for countIf)."""
    if isinstance(kql, dict):  # kibana sometimes nests {kqlQuery: "..."}
        kql = kql.get("kqlQuery") or kql.get("query") or ""
    kql = (kql or "").strip()
    if not kql or kql == "*":
        return "true"
    from e2d.core.queries import translate_filter_line
    return translate_filter_line(kql, "kql", config, data_object, report)


def translate_slo(text: str, config: Optional[MappingConfig] = None,
                  name: Optional[str] = None) -> SloResult:
    config = config or MappingConfig()
    doc = json.loads(text)
    res = SloResult(name=doc.get("name") or name or "slo")
    objective = doc.get("objective") or {}
    if isinstance(objective.get("target"), (int, float)):
        res.target_pct = round(float(objective["target"]) * 100, 4)
    tw = doc.get("timeWindow") or {}
    res.window = f"{tw.get('duration', '?')} {tw.get('type', '')}".strip()
    res.budgeting = doc.get("budgetingMethod", "")
    if res.budgeting == "timeslices":
        res.report.warn("Kibana budgeting method `timeslices` has no direct "
                        "equivalent; the Dynatrace SLO evaluates the error "
                        "budget over the whole window (occurrences-style). "
                        "Review whether that meets the objective's intent.")

    ind = doc.get("indicator") or {}
    itype = ind.get("type", "")
    params = ind.get("params") or {}

    if itype != "sli.kql.custom":
        hint = ("APM latency/availability indicators map better to a Dynatrace "
                "service-level objective on the equivalent monitored service; "
                "create it in the SLO app against the service's response time "
                "or failure rate." if itype.startswith("sli.apm")
                else "Rebuild the SLI as a DQL query yielding an `sli` field.")
        res.report.manual(f"SLO indicator `{itype or '?'}` has no automatic "
                          f"conversion. {hint}")
        return res

    index = params.get("index", "")
    data_object = config.resolve_data_object(index) or "logs" if index else "logs"
    pre = _kql_condition(params.get("filter"), config, data_object, res.report)
    good = _kql_condition(params.get("good"), config, data_object, res.report)
    total = _kql_condition(params.get("total"), config, data_object, res.report)
    if good == "true":
        res.report.manual("The SLO has no `good` query; the SLI would always "
                          "be 100%. Define what counts as good before using it.")

    lines = [f"fetch {data_object}"]
    if pre != "true":
        lines.append(f"| filter {pre}")
    total_expr = "count()" if total == "true" else f"countIf({total})"
    lines.append(f"| summarize sli = countIf({good}) * 100.0 / {total_expr}")
    res.dql = "\n".join(lines)

    from e2d.dql.validate import lint_into_report
    lint_into_report(res.dql, res.report, data_object)
    return res


def render_slo(res: SloResult) -> str:
    L: List[str] = [f"# SLO: {res.name}", ""]
    if res.target_pct is not None:
        L.append(f"- Objective target: **{res.target_pct}%**")
    if res.window:
        L.append(f"- Time window: **{res.window}**")
    if res.budgeting:
        L.append(f"- Budgeting method in Kibana: `{res.budgeting}`")
    L.append("")
    if res.dql:
        L.append("## SLI query (DQL)")
        L.append("")
        L.append("```")
        L.append(res.dql)
        L.append("```")
        L.append("")
        L.append("## Create it in Dynatrace")
        L.append("")
        L.append("1. Open the **Service-Level Objectives** app, create a new SLO, "
                 "and paste the DQL above as the SLI (it yields the required "
                 "`sli` field).")
        if res.target_pct is not None:
            L.append(f"2. Set the target to **{res.target_pct}%** and the "
                     f"evaluation window to **{res.window or 'the original window'}**.")
        else:
            L.append("2. Set the target and window to match the original objective.")
        L.append("3. Or automate it: the SLO API accepts the same definition; "
                 "see Dynatrace docs on creating SLOs with a custom DQL SLI.")
        L.append("")
        L.append("Definition sketch for the API:")
        L.append("")
        L.append("```json")
        L.append(json.dumps({"name": res.name,
                             "customSli": {"indicator": res.dql},
                             "criteria": [{"timeframeFrom": f"now-{_win(res.window)}",
                                           "timeframeTo": "now",
                                           "target": res.target_pct}]}, indent=2))
        L.append("```")
    else:
        L.append("No DQL could be generated; see the notes in the migration report.")
    return "\n".join(L) + "\n"


def _win(window: str) -> str:
    return (window.split() or ["30d"])[0]
