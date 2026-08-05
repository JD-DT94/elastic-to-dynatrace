"""AppD instrumentation config -> Dynatrace guidance.

Information points, data collectors and transaction detection rules all describe
the same thing: places where AppD was told to look harder, because by default it
does not. Dynatrace's answers are structurally different — continuous capture,
automatic service detection, request attributes — so none of these translate
into a deployable artifact and this module deliberately produces guidance rather
than pretending otherwise.

What it does contribute is the inventory: how many of each exist, what they were
named, and which Dynatrace construct each maps onto. That is the part a
migration plan actually needs, and it is the part nobody wants to compile by
hand from a controller.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List

from e2d.report import Report

INFO_POINTS = "appd_infopoints"
DATA_COLLECTORS = "appd_datacollectors"
TXN_RULES = "appd_txn_rules"
SERVICE_ENDPOINTS = "appd_service_endpoints"
BACKENDS = "appd_backends"
DB_COLLECTORS = "appd_db_collectors"

KIND_TITLE = {
    INFO_POINTS: "Information points",
    DATA_COLLECTORS: "Data collectors",
    TXN_RULES: "Transaction detection rules",
    SERVICE_ENDPOINTS: "Service endpoints",
    BACKENDS: "Backends and remote services",
    DB_COLLECTORS: "Database collectors",
}


def _get(d: Any, *names, default=None):
    if not isinstance(d, dict):
        return default
    for n in names:
        if n in d:
            return d[n]
        for k in d:
            if k.lower() == n.lower():
                return d[k]
    return default


def _records(doc: Any) -> List[dict]:
    if isinstance(doc, list):
        return [r for r in doc if isinstance(r, dict)]
    if isinstance(doc, dict):
        for key in ("informationPoints", "dataGathererConfigs",
                    "methodInvocationDataCollectors", "httpDataCollectors",
                    "rules", "items"):
            v = _get(doc, key)
            if isinstance(v, list):
                return [r for r in v if isinstance(r, dict)]
        return [doc]
    return []


def detect_kind(doc: Any):
    """Which instrumentation artifact this is, or None.

    Markers are deliberately narrow. A loose probe here would swallow unrelated
    JSON and report confident nonsense about an estate.
    """
    if isinstance(doc, dict):
        for key, kind in (("informationPoints", INFO_POINTS),
                          ("dataGathererConfigs", DATA_COLLECTORS),
                          ("methodInvocationDataCollectors", DATA_COLLECTORS),
                          ("httpDataCollectors", DATA_COLLECTORS)):
            if _get(doc, key) is not None:
                return kind

    records = _records(doc)
    if not records:
        return None
    probe = records[0]
    if _get(probe, "informationPointType") is not None:
        return INFO_POINTS
    if _get(probe, "dataGathererType") is not None:
        return DATA_COLLECTORS
    if _get(probe, "ruleType") is not None and (
            _get(probe, "entryPointType") is not None
            or _get(probe, "txMatchRule") is not None):
        return TXN_RULES
    if _get(probe, "collectorType") is not None or (
            _get(probe, "collectorDefinition") is not None):
        return DB_COLLECTORS
    if _get(probe, "exitPointType") is not None or (
            _get(probe, "backendName") is not None):
        return BACKENDS
    # a service endpoint carries its own type plus a tier binding; without the
    # tier it is too close to a plain named record to claim confidently
    if _get(probe, "serviceEndpointType") is not None or (
            _get(probe, "sepType") is not None
            and _get(probe, "tierName", "tierId") is not None):
        return SERVICE_ENDPOINTS
    return None


@dataclass
class InstrumentationResult:
    kind: str
    names: List[str] = field(default_factory=list)
    report: Report = field(default_factory=Report)


def translate_instrumentation(text_or_doc, kind: str) -> InstrumentationResult:
    doc = json.loads(text_or_doc) if isinstance(text_or_doc, (str, bytes)) else text_or_doc
    res = InstrumentationResult(kind=kind)
    for rec in _records(doc):
        name = _get(rec, "name", "ruleName", "displayName")
        if name:
            res.names.append(str(name))

    n = len(res.names)
    if kind == INFO_POINTS:
        res.report.manual(
            f"{n or 'Some'} information point(s) found. These become **business events**, "
            "and it is not a translation — you define capture rules and metric "
            "transformations from scratch, driven by what the business needs to see rather "
            "than by what AppD happened to capture. Treat this as a redesign in phase 7.")
    elif kind == DATA_COLLECTORS:
        res.report.warn(
            f"{n or 'Some'} data collector(s) found. Method-argument and return-value "
            "capture becomes **request attributes** (or OpenTelemetry span attributes), "
            "configured per service. The capture intent ports across; the mechanism does not.")
    elif kind == TXN_RULES:
        res.report.warn(
            f"{n or 'Some'} transaction detection rule(s) found. Most exist to make AppD "
            "recognise a framework it does not know natively — Dynatrace detects the "
            "mainstream stacks automatically, so start by assuming you need none of them. "
            "Only genuinely unusual entry points need a **custom service** definition.")
        res.report.info(
            "Detection rules exported through the API cannot be imported through the AppD "
            "UI and vice versa, so if this export looks short compared with the UI, you are "
            "probably missing the inactive rules rather than looking at the full set.")
    elif kind == SERVICE_ENDPOINTS:
        res.report.info(
            f"{n or 'Some'} service endpoint(s) found. Dynatrace detects every endpoint on a "
            "service automatically and has no per-application quota, so there is nothing to "
            "recreate — this list is useful as a checklist for confirming the same endpoints "
            "appear after instrumentation, not as configuration to port.")
    elif kind == BACKENDS:
        res.report.info(
            f"{n or 'Some'} backend / remote service(s) found. Dynatrace discovers databases, "
            "queues and outbound HTTP dependencies from trace data and builds the "
            "dependency map itself. Use this list to verify the same dependencies show up "
            "in Smartscape once agents are reporting.")
    elif kind == DB_COLLECTORS:
        res.report.warn(
            f"{n or 'Some'} database collector(s) found. Dynatrace database monitoring is "
            "configured differently — deep database visibility comes from the services "
            "calling the database, with an extension where you need instance-level metrics. "
            "Inventory the databases here, then decide per database whether the extension "
            "is warranted.")
    return res


def render_instrumentation(res: InstrumentationResult, source: str = "") -> str:
    title = KIND_TITLE.get(res.kind, "AppD instrumentation")
    L: List[str] = [f"# {title}", ""]
    if source:
        L += [f"Source: `{source}`", ""]

    target = {
        INFO_POINTS: ("Business events (Business Analytics)",
                      "Capture rules plus metric transformations, defined from scratch."),
        DATA_COLLECTORS: ("Request attributes",
                          "Configured per service; OpenTelemetry span attributes are the "
                          "alternative where the service is already instrumented with OTel."),
        TXN_RULES: ("Automatic service detection, plus custom services where needed",
                    "Assume none are needed until a service fails to appear."),
        SERVICE_ENDPOINTS: ("Service endpoints (detected automatically)",
                            "Nothing to migrate. Keep the list as a post-instrumentation "
                            "checklist."),
        BACKENDS: ("Smartscape topology (detected automatically)",
                   "Nothing to migrate. Keep the list to verify the dependency map."),
        DB_COLLECTORS: ("Database monitoring via the calling services, plus an extension "
                        "for instance-level metrics",
                        "Decide per database whether instance-level metrics justify an "
                        "extension."),
    }.get(res.kind, ("", ""))

    L += [f"**Lands in Dynatrace as:** {target[0]}", "", target[1], ""]

    if res.names:
        L += [f"## Inventory ({len(res.names)})", ""]
        L += [f"- `{n}`" for n in res.names[:200]]
        if len(res.names) > 200:
            L.append(f"- …and {len(res.names) - 200} more")
        L.append("")

    notes = res.report.format_deduped()
    if notes:
        L += ["## Notes", ""] + [f"- {n}" for n in notes] + [""]
    return "\n".join(L)
