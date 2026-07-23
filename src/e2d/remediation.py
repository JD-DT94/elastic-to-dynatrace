"""Manual-remediation knowledge base for constructs e2d can't fully convert.

When a conversion flags something MANUAL/REVIEW, the user is left asking "what is
this and how do I finish it in Dynatrace?". This module answers that: each entry
explains the construct and gives concrete Dynatrace steps. `remediations_for`
matches a report note (or any text) to the relevant entries so the GUI can show a
"How to fix" panel next to each finding.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List


@dataclass
class Remedy:
    key: str          # stable id
    triggers: tuple   # lowercase substrings that imply this construct
    title: str
    what: str         # what the Elastic construct is
    fix: str          # how to do it in Dynatrace (Markdown)


_REMEDIES: List[Remedy] = [
    Remedy("top_hits", ("top_hits", "top hits"),
           "top_hits aggregation",
           "Returns a few example documents per bucket alongside the aggregation.",
           "DQL aggregations don't carry sample rows. Run a **companion record query** for the examples: "
           "`fetch logs | filter <same filters> | sort timestamp desc | limit 3`, or add the sample "
           "fields to a Notebook section beside the summarized tile."),
    Remedy("scripted_metric", ("scripted_metric", "scripted metric", "arbitrary painless"),
           "scripted_metric (arbitrary Painless)",
           "A custom map/combine/reduce script computing a bespoke value.",
           "If it's a distinct count (HashSet of a field), use `countDistinct(<field>)` — e2d does this "
           "automatically when it recognises the pattern. Otherwise re-express the logic as DQL "
           "(`summarize`, `fieldsAdd`, `if()`), or move it to a **Workflow JavaScript task**."),
    Remedy("painless", ("painless", "condition.script", "emit-chain", "ternary"),
           "Painless script (condition / transform / runtime field)",
           "Inline Java-like script for a condition, derived field, or transform.",
           "Simple comparisons and ternaries map to DQL `if(cond, a, else: b)` / `fieldsAdd`. e2d "
           "translates the common shapes; verify them. Anything stateful or iterative belongs in a "
           "**Workflow JavaScript task**."),
    Remedy("array_compare", ("array_compare", "quantifier"),
           "array_compare with a quantifier (some / all)",
           "Fires when SOME or ALL elements of a bucket array satisfy a comparison.",
           "This is per-dimension event semantics: a **Davis anomaly detector** grouped `by:` that "
           "dimension fires once per breaching value (= `some`). For `all`, add a guard that no value "
           "is below the threshold. For array-typed fields use `matchesValue()` / `MATCH`."),
    Remedy("http_input", ("input.http", "chained `input.http", "http task", "external config"),
           "Watcher input.http / chained input",
           "Pulls external config (e.g. thresholds) over HTTP before the search runs.",
           "Add a **Workflow HTTP task** that fetches the config first, then pass its result into the "
           "query/threshold task. Store any credentials as a Dynatrace credential, never inline."),
    Remedy("grok_dissect", ("rewrite pattern as dpl", "rewrite grok as dpl", "grok", "dissect", "dpl"),
           "grok / dissect pattern",
           "Extracts fields from a log line using grok %{SYNTAX:name} or dissect %{name}.",
           "Rewrite as a DQL **DPL** pattern in a `parse` command, e.g. "
           "`parse content, \"IPADDR:client ' ' LD:rest\"`. The matcher names differ from grok — see "
           "the DPL grammar; e2d converts the common matchers and flags the rest."),
    Remedy("ruby_script", ("ruby", "kafka", "soc mirror"),
           "Logstash ruby filter / Kafka output",
           "Arbitrary Ruby code, or a fan-out to Kafka (e.g. a SOC mirror).",
           "Ruby has no OpenPipeline equivalent — re-express the intent with DPL processors "
           "(`fieldsAdd`, `parse`, `lookup`) or a Workflow. A Kafka mirror becomes a **second pipeline "
           "consumer / data forwarding** rule."),
    Remedy("enrich", ("enrich", "lookup ["),
           "ENRICH / translate dictionary",
           "Joins in reference data from an enrich policy or translate dictionary.",
           "Use a DQL **`lookup [ ... ]`** subquery against a Grail lookup table or reference bucket: "
           "`lookup [fetch <ref>], sourceField:.., lookupField:..`. Load the dictionary into a lookup "
           "table first."),
    Remedy("metric_missing", ("not a dynatrace metric", "metric `", "needs creating via openpipeline"),
           "Metric doesn't exist in Dynatrace",
           "The alert references an Elastic metric name (e.g. system.cpu.*) with no Grail equivalent.",
           "**Create the metric in OpenPipeline**: add a `value_metric` (or `counter_metric`) processor "
           "to a logs pipeline that extracts the value into a new `metric_key`, then point the anomaly "
           "detector at that key. e2d emits a starter processor in `metric_creation.md`."),
    Remedy("cron", ("cron",),
           "cron trigger",
           "A cron expression controlling when the watcher runs.",
           "A **Davis anomaly detector** evaluates every minute (no cron needed). If you need a specific "
           "cadence, use a **Workflow schedule trigger** with the equivalent time/interval."),
    Remedy("ilm", ("ilm", "index management", "retention tier", "hot/warm/cold"),
           "ILM / index lifecycle",
           "Hot/warm/cold tiers and delete phases for indices.",
           "Grail has a single **retention per bucket** — there are no tiers. Map `delete.min_age` to "
           "the bucket retention and assign data to that bucket; the warm/cold distinction goes away."),
]


def remediations_for(text: str) -> List[Remedy]:
    """Every remedy whose triggers appear in `text` (a report note / finding)."""
    low = (text or "").lower()
    return [r for r in _REMEDIES if any(t in low for t in r.triggers)]


def remediations_for_notes(notes: List[str]) -> List[Remedy]:
    """De-duplicated remedies across a list of notes (for one converted item)."""
    seen, out = set(), []
    for n in notes or []:
        for r in remediations_for(n):
            if r.key not in seen:
                seen.add(r.key)
                out.append(r)
    return out
