"""The phased migration guide, tailored by what an export actually contained.

Two documents come out of here:

* **the sequencing guide** — ten phases in running order, each carrying the
  catalogue items it owns and the constraints that decide its duration;
* **the coverage report** — every catalogue item against what the export
  proved is present, so nothing in the estate is quietly missing from the plan.

The ordering is not arbitrary. Three real constraints fix it: nothing exists in
Dynatrace until an agent reports, so instrumentation precedes everything; Davis
needs one to two weeks of data before its baselines can be trusted, so alerting
cannot start with instrumentation; and AppD history does not transfer, so
validation means running both stacks side by side rather than comparing after
the fact.
"""

from __future__ import annotations

from typing import Dict, Iterable, List, Optional

from e2d.appd import catalogue as cat

# How long Davis needs before its baselines are worth alerting on.
BASELINE_DAYS = "7 to 14 days"
# Typical parallel-run window per wave before sign-off.
PARALLEL_RUN = "2 to 4 weeks"


def _bullet(item: cat.Item, mark: str = "") -> str:
    label = cat.APPROACH_LABEL[item.approach]
    head = f"- {mark}**{item.appd}** &rarr; {item.dynatrace} _({label})_"
    return head + (f"\n  {item.note}" if item.note else "")


def render_sequencing(found_kinds: Iterable[str] = (),
                      hosts: int = 0, waves: int = 0,
                      converted: Optional[Dict[str, int]] = None) -> str:
    """The phased plan. `found_kinds` are the artifact kinds seen in the export,
    so items proven present can be marked."""
    kinds = set(found_kinds)
    present = {id(i) for i in cat.detected(kinds)}
    converted = converted or {}
    phases = cat.by_phase()

    L: List[str] = [
        "# AppDynamics to Dynatrace — migration sequencing",
        "",
        "Ten phases in running order, on a data-first, configuration-second, "
        "decommission-last principle. Items marked **[in your export]** were proven "
        "present by the files converted in this run; the rest are listed because they "
        "exist in most estates and are easy to forget until they block something.",
        "",
    ]

    if hosts:
        L += [f"This run sized the instrumentation at **{hosts} host(s)**"
              + (f" across **{waves} wave(s)**" if waves else "")
              + ". See `onboarding/ONBOARDING-PLAN.md` for the wave detail.", ""]

    L += ["## Before you start", "",
          "Do not attempt a 1:1 port. A large share of any AppD configuration exists "
          "only because AppD needs manual setup for things Dynatrace derives "
          "automatically — service detection, dependency mapping, baselining, snapshot "
          "capture. Migrating those items costs real time and delivers nothing. The "
          f"catalogue marks **{cat.counts_by_approach().get(cat.NOT_NEEDED, 0)}** item "
          "types as needing no migration at all; confirming which of those you hold is "
          "the cheapest scope reduction available.",
          "",
          "Three other principles decide whether the plan survives contact:",
          "",
          "- **Migrate in waves**, one application group at a time, validating each "
          "before starting the next. Independent waves can run concurrently across "
          "teams once host groups and the deployment inventory are agreed.",
          "- **Rebuild dashboards, do not replicate them.** The entity model differs "
          "enough that a faithful copy is usually worse than a redesign.",
          "- **Historical data does not transfer.** AppD metrics and traces stay in "
          "AppD. Dynatrace starts from deployment day, which is what makes the parallel "
          "run non-negotiable rather than a nice-to-have.",
          ""]

    for number, title, why in cat.PHASES:
        items = phases.get(number, [])
        L += [f"## Phase {number} — {title}", "", why, ""]

        extra = _phase_notes(number, kinds, hosts, waves, converted)
        if extra:
            L += extra + [""]

        if items:
            for item in items:
                mark = "[in your export] " if id(item) in present else ""
                L.append(_bullet(item, mark))
            L.append("")

    L += ["## Exit criteria per wave", "",
          "A wave is done when all of these are true, not when the agents are installed:",
          "",
          "1. Every host in the wave reports, and its processes appear as services.",
          "2. Tags and management zone membership are correct for those services.",
          f"3. Davis has had {BASELINE_DAYS} of data, and its baselines look sane.",
          "4. Alert parity is confirmed — Dynatrace raised what AppD raised, and the "
          "differences are understood rather than merely noted.",
          "5. The owning application team has signed off.",
          "",
          "Only then remove that wave's AppD agents. Decommission the controllers after "
          "the last wave, and cancel the licensing after that.",
          ""]
    return "\n".join(L)


def _phase_notes(number: int, kinds: set, hosts: int, waves: int,
                 converted: Dict[str, int]) -> List[str]:
    """Run-specific guidance for a phase, where this export justifies it."""
    if number == 1:
        n = len([k for k in kinds if k.startswith("appd_")])
        if n:
            return [f"This run read {n} kind(s) of AppD artifact. Anything in the "
                    "catalogue below that is *not* marked as present is either absent "
                    "from your estate or missing from the export — worth confirming "
                    "which, because the second case becomes a surprise in a later phase."]
        return []
    if number == 3 and hosts:
        return [f"**{hosts} OneAgent install(s)**"
                + (f" across {waves} wave(s)." if waves else ".")
                + " Deploy alongside the AppD agents and leave both running — nothing "
                  "is removed until phase 10. Newly detected process groups need one "
                  "process restart before deep monitoring engages, which is usually the "
                  "only app-team-visible step and the thing wave scheduling is really "
                  "negotiating."]
    if number == 5:
        notes = [f"**Wait {BASELINE_DAYS} after instrumentation before tuning alerts.** "
                 "Davis baselines from observed data; alerting on it too early produces "
                 "noise that costs you the team's trust just as they start using it."]
        covered = converted.get("covered-by-davis", 0)
        auto = converted.get("converted", 0)
        manual = converted.get("manual", 0)
        if auto or covered or manual:
            parts = []
            if auto:
                parts.append(f"{auto} converted to detectors")
            if covered:
                parts.append(f"{covered} already covered by built-in Davis")
            if manual:
                parts.append(f"{manual} needing a manual rebuild")
            notes.append("From this run: " + ", ".join(parts) +
                         ". Prioritise the critical rules; the covered ones need no work.")
        return notes
    if number == 6:
        return ["Work in priority order — executive health, then service health, then "
                "infrastructure, then business KPIs — and stop when the dashboards people "
                "actually open are covered. Converted tiles are a starting point, not a "
                "deliverable."]
    if number == 9:
        return [f"Run both platforms together for {PARALLEL_RUN} per wave. Because AppD "
                "history cannot be loaded into Dynatrace, this overlap is the only way to "
                "compare like for like — budget for double agent footprint and double "
                "licensing across the window."]
    if number == 10:
        return ["Wave by wave, and only after sign-off. Removing agents ahead of "
                "validation turns a reversible step into an outage investigation with no "
                "data on either side."]
    return []


def render_coverage(found_kinds: Iterable[str] = (),
                    converted: Optional[Dict[str, int]] = None) -> str:
    """Every catalogue item, against what this export proved is present."""
    kinds = set(found_kinds)
    present = {id(i) for i in cat.detected(kinds)}
    by_area = cat.by_area()
    totals = cat.counts_by_approach()

    L: List[str] = [
        "# AppDynamics configuration catalogue",
        "",
        f"Everything an AppD estate can hold ({len(cat.CATALOGUE)} item types), what each "
        "becomes in Dynatrace, and how it gets there. **In export** marks the items this "
        "run found evidence of.",
        "",
        "| Approach | Meaning | Items |",
        "|---|---|---|",
    ]
    for key in (cat.AUTOMATIC, cat.ASSISTED, cat.REBUILD, cat.NOT_NEEDED):
        L.append(f"| {cat.APPROACH_LABEL[key]} | "
                 f"{_approach_meaning(key)} | {totals.get(key, 0)} |")
    L.append("")

    not_needed = totals.get(cat.NOT_NEEDED, 0)
    L += [f"The {not_needed} *nothing to migrate* items are the ones worth checking first. "
          "They are not gaps — they are configuration that exists in AppD purely to make it "
          "do what Dynatrace does unprompted, and carrying them across would add cost and "
          "alert noise for no benefit.",
          ""]

    for area_key, area_title in cat.AREAS:
        items = by_area.get(area_key, [])
        if not items:
            continue
        L += [f"## {area_title}", "",
              "| AppDynamics | Dynatrace | Approach | Phase | In export |",
              "|---|---|---|---|---|"]
        for item in items:
            mark = "yes" if id(item) in present else "—"
            L.append(f"| {item.appd} | {item.dynatrace} | "
                     f"{cat.APPROACH_LABEL[item.approach]} | {item.phase} | {mark} |")
        L.append("")
        notes = [i for i in items if i.note]
        if notes:
            for item in notes:
                L.append(f"- **{item.appd}.** {item.note}")
            L.append("")

    L += ["## What this run converted", ""]
    converted = converted or {}
    if converted:
        for key, label in (("converted", "converted to Davis anomaly detectors"),
                           ("covered-by-davis", "already covered by built-in Davis, no work needed"),
                           ("manual", "need a manual rebuild")):
            if converted.get(key):
                L.append(f"- {converted[key]} health rule(s) {label}")
    else:
        L.append("- No AppD health rules were present in this export.")
    L += ["",
          "See `MIGRATION_REPORT.md` for the per-artifact detail and "
          "`APPD-SEQUENCING.md` for the phased plan.", ""]
    return "\n".join(L)


def _approach_meaning(key: str) -> str:
    return {
        cat.AUTOMATIC: "This tool produces a deployable artifact",
        cat.ASSISTED: "This tool writes the plan; you apply it",
        cat.REBUILD: "Rebuild by hand — a copy would mislead",
        cat.NOT_NEEDED: "Dynatrace does this automatically",
    }[key]
