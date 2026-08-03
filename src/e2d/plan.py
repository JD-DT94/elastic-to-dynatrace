"""Deployment sequencing: turn a MigrationSummary into an ordered rollout plan.

Two jobs:

1. **Order.** Converted artifacts depend on each other — routing/retention
   decide where data lands, pipelines create the custom fields dashboards
   query, and detectors need data flowing before they can evaluate — so the
   plan lists the steps in the order that avoids dead ends.
2. **Field gaps.** Cross-reference the custom fields each converted dashboard
   queries against the fields the converted pipelines actually produce. A
   field nobody produces is the #1 cause of a tile that renders empty with no
   error, so it is called out per dashboard before anything is deployed.
"""

from __future__ import annotations

import re
from typing import Dict, List

# Fields created by a pipeline stage's DQL: `fieldsAdd a = ..., b = ...`
# assignments (also fieldsRename targets) and DPL parse exports such as
# `IPADDR:client_ip` or `LD:audit.logText`.
_FIELDS_STMT = re.compile(r"\bfields(?:Add|Rename)\b(.*)")
_ASSIGN = re.compile(r"(?:^|,)\s*([A-Za-z_][\w.]*)\s*=")
_DPL_EXPORT = re.compile(r"\b[A-Z][A-Z0-9_]*:([A-Za-z_][\w.]*)")


def fields_produced(stage_dqls: List[str]) -> List[str]:
    """Field names a pipeline's DQL stages create at ingest."""
    out = set()
    for dql in stage_dqls:
        for m in _FIELDS_STMT.finditer(dql):
            out.update(_ASSIGN.findall(m.group(1)))
        if "parse" in dql:
            out.update(_DPL_EXPORT.findall(dql))
    return sorted(out)


def build_plan(summary) -> dict:
    """Ordered deployment steps + per-dashboard field gaps for a finished run."""
    by_cat: Dict[str, List[str]] = {}
    for it in summary.items:
        if it.status != "ERROR" and it.source not in by_cat.get(it.category, ()):
            by_cat.setdefault(it.category, []).append(it.source)

    # Dynatrace lowercases attribute keys at ingest, so a pipeline exporting
    # audit.logText satisfies a dashboard that queries audit.logtext
    produced = set()
    for fields in getattr(summary, "pipeline_fields", {}).values():
        produced.update(f.lower() for f in fields)
    gaps = []
    for src, fields in sorted(getattr(summary, "dashboard_fields", {}).items()):
        missing = sorted(f for f in fields if f.lower() not in produced)
        if missing:
            gaps.append({"dashboard": src, "fields": missing})

    steps: List[dict] = []

    def step(title: str, why: str, how: str, items: List[str]) -> None:
        if items:
            steps.append({"title": title, "why": why, "how": how, "items": items})

    step("Storage & routing decisions",
         "Bucket retention and OpenPipeline routing decide where data lands and "
         "how long it lives. Settle them before logs start flowing.",
         "Work through each guide under config_advice/.",
         by_cat.get("config", []))
    step("Deploy ingest pipelines",
         "Pipelines create the custom fields everything downstream queries; "
         "dashboards and alerts stay empty until these run.",
         "terraform apply each pipelines_tf/<name>/ folder, or paste the .dpl "
         "stages into OpenPipeline in the UI.",
         by_cat.get("pipeline", []))
    step("Verify fields are ingested",
         "A tile whose field is missing renders empty with no error. This step "
         "catches that before anyone stares at a blank dashboard.",
         "Check each dashboard's *.fields.md manifest against live data "
         "(fetch logs | fieldsSummary <field>).",
         sorted(getattr(summary, "dashboard_fields", {})))
    step("Repoint shippers",
         "Once pipelines are ready to process what arrives, move (or dual-ship) "
         "the collection edge so data starts flowing.",
         "Apply each shippers/<name>.otel.yaml collector config, or add the "
         "dual-ship output from CUTOVER-PLAN.md to the existing shippers.",
         by_cat.get("shipper", []))
    step("Import dashboards",
         "Safe once their fields are flowing.",
         "Upload each dashboards/*.json in the Dynatrace Dashboards app, or "
         "push via the deploy panel / e2d push.",
         by_cat.get("dashboard", []))
    step("Create SLOs",
         "SLOs read live data; create them after dashboards confirm the data "
         "looks right.",
         "Follow each slos/<name>.slo.md: paste the DQL SLI into the SLO app "
         "or POST it via the SLO API.",
         by_cat.get("slo", []))
    step("Recreate synthetic monitors",
         "Independent of log data; needs only the target endpoints reachable "
         "from the chosen locations.",
         "POST each synthetics/<name>.monitor.json via the Synthetic API, "
         "after picking locations (see the .md guide).",
         by_cat.get("synthetic", []))
    step("Recreate transforms as rollups",
         "Rollup queries only make sense against live data.",
         "Follow each transforms/*.transform.md note.",
         by_cat.get("transform", []))
    step("Enable alerting last",
         "Detectors evaluate live data; enabling them before data flows just "
         "fires false alarms. Review each threshold and window first.",
         "terraform apply each alerts_tf/<name>/ folder, or push detectors from "
         "the deploy panel; keep them disabled until validated.",
         by_cat.get("alert", []))
    if getattr(summary, "metrics_advisories", 0):
        steps.append({"title": "Optimise: extract metrics",
                      "why": "The busiest tiles are cheaper, faster and retained "
                             "longer as ingest-time metrics.",
                      "how": "Work through METRICS-GUIDE.md once dashboards are settled.",
                      "items": ["METRICS-GUIDE.md"]})
    for n, s in enumerate(steps, 1):
        s["n"] = n

    return {"steps": steps, "field_gaps": gaps,
            "have_pipelines": bool(by_cat.get("pipeline"))}


def render_plan_md(plan: dict) -> List[str]:
    """The plan as markdown lines for MIGRATION_REPORT.md."""
    L: List[str] = ["## Deployment order", ""]
    if not plan["steps"]:
        L.append("Nothing to deploy; no artifacts were converted.")
        return L
    L.append("Deploy in this order. Each step creates what the next depends on.")
    L.append("")
    for s in plan["steps"]:
        L.append(f"{s['n']}. **{s['title']}.** {s['why']}")
        arts = ", ".join(f"`{a}`" for a in s["items"])
        L.append(f"   - Covers: {arts}")
        L.append(f"   - How: {s['how']}")
    L.append("")
    if plan["field_gaps"]:
        L.append("### Field gaps to close")
        L.append("")
        if plan["have_pipelines"]:
            L.append("These dashboards query custom fields that **no converted pipeline "
                     "produces**. Their tiles will render empty until the fields are "
                     "ingested some other way:")
        else:
            L.append("No pipelines were part of this run, so these dashboards' custom "
                     "fields must already exist in your tenant. Verify before "
                     "importing:")
        L.append("")
        for g in plan["field_gaps"]:
            L.append(f"- `{g['dashboard']}`: " + ", ".join(f"`{f}`" for f in g["fields"]))
        L.append("")
    return L
