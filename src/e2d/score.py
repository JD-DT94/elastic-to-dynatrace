"""Scorecard: one honest picture of how a whole run converted.

Every mature converter (AWS SCT's assessment report, Elastic's migration
platform, OpenObserve's dashboard migrator) leads with the same thing: what
fraction converted cleanly, what needs review, what needs a person, and a
rough effort estimate for the manual tail. The per-item data already exists
in the migration summary; this module just folds it.

Outcome vocabulary (derived from item status):
  exact        converted with no caveats (OK)
  approximate  converted, human should double-check the flagged points (REVIEW)
  manual       could not be converted faithfully; a person rebuilds it (MANUAL)
  failed       the converter itself errored on the input (ERROR)
"""

from __future__ import annotations

from typing import Dict, List

OUTCOME = {"OK": "exact", "REVIEW": "approximate", "MANUAL": "manual",
           "ERROR": "failed"}

# deliberately rough review-effort weights, hours per item
HOURS = {"approximate": 0.25, "manual": 1.5, "failed": 0.5}


def build_scorecard(summary) -> dict:
    total = len(summary.items)
    by_outcome: Dict[str, int] = {"exact": 0, "approximate": 0, "manual": 0,
                                  "failed": 0}
    by_category: Dict[str, Dict[str, int]] = {}
    for it in summary.items:
        outcome = OUTCOME.get(it.status, "manual")
        by_outcome[outcome] += 1
        row = by_category.setdefault(
            it.category, {"total": 0, "exact": 0, "approximate": 0,
                          "manual": 0, "failed": 0})
        row["total"] += 1
        row[outcome] += 1
    pct = {k: (round(100 * v / total) if total else 0)
           for k, v in by_outcome.items()}
    hours = sum(HOURS.get(o, 0) * n for o, n in by_outcome.items())
    return {"total": total,
            "counts": by_outcome,
            "pct": pct,
            "est_review_hours": round(hours * 2) / 2,
            "by_category": by_category,
            "skipped": len(summary.skipped)}


def scorecard_line(sc: dict) -> str:
    if not sc["total"]:
        return "Nothing converted."
    parts = [f"{sc['pct']['exact']}% exact",
             f"{sc['pct']['approximate']}% approximate",
             f"{sc['pct']['manual']}% manual"]
    if sc["counts"]["failed"]:
        parts.append(f"{sc['pct']['failed']}% failed")
    line = (f"{sc['total']} artifact(s): " + ", ".join(parts)
            + f". Rough review estimate: {sc['est_review_hours']:g} h.")
    if sc["skipped"]:
        line += f" ({sc['skipped']} file(s) skipped.)"
    return line


def render_scorecard_md(sc: dict) -> List[str]:
    L: List[str] = ["## Scorecard", "", scorecard_line(sc), ""]
    if sc["by_category"]:
        L.append("| Category | Total | Exact | Approximate | Manual |")
        L.append("|----------|-------|-------|-------------|--------|")
        for cat in sorted(sc["by_category"]):
            row = sc["by_category"][cat]
            L.append(f"| {cat} | {row['total']} | {row['exact']} | "
                     f"{row['approximate']} | {row['manual']} |")
        L.append("")
    return L


def report_payload(summary) -> dict:
    """Machine-readable run report (migration_report.json) for CI and tooling."""
    from e2d.plan import build_plan
    return {
        "tool": "e2d",
        "scorecard": build_scorecard(summary),
        "counts": summary.counts(),
        "items": [{"category": it.category, "source": it.source,
                   "status": it.status,
                   "outcome": OUTCOME.get(it.status, "manual"),
                   "outputs": it.outputs, "notes": it.notes}
                  for it in summary.items],
        "skipped": summary.skipped,
        "secrets": sorted(set(summary.secrets)),
        "plan": build_plan(summary),
    }
