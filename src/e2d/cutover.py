"""Cutover planning: turn ILM policies into a dual-ship and decommission plan.

Dynatrace will not accept log records older than 24 hours, so Elasticsearch
history cannot be replayed into Grail after the fact. The workable strategy is:

1. **Dual-ship** new logs to both stacks during a validation window.
2. **Cut over** dashboards/alerts once parity is confirmed.
3. Keep the Elasticsearch cluster **read-only** until each index's retention
   obligation has elapsed, then decommission it.
4. For the rare index where history must live in Dynatrace, re-stamp it with
   ``e2d backfill`` (original event time preserved in ``original_timestamp``).

This module renders that strategy concretely from the ILM policies found in a
migration run: per-policy retention, how long the old cluster must stay
queryable after cutover, matching Grail bucket definitions, and dual-ship
config snippets.
"""

from __future__ import annotations

import json
import re
from typing import Dict, List, Optional

_AGE = re.compile(r"^\s*(\d+)\s*(ms|s|m|h|d|w|y)\s*$", re.I)
_UNIT_DAYS = {"ms": 1 / 86_400_000, "s": 1 / 86_400, "m": 1 / 1_440,
              "h": 1 / 24, "d": 1.0, "w": 7.0, "y": 365.0}


def parse_min_age_days(value: Optional[str]) -> Optional[int]:
    """`min_age` ("30d", "720h", "0ms") -> whole days, rounded up."""
    if not value:
        return None
    m = _AGE.match(str(value))
    if not m:
        return None
    days = int(m.group(1)) * _UNIT_DAYS[m.group(2).lower()]
    return max(1, int(days + 0.999)) if days > 0 else 0


def bucket_definition(policy_name: str, retention_days: int) -> dict:
    """A Grail bucket definition matching the ILM retention, ready to POST to
    /platform/storage/management/v1/bucket-definitions."""
    safe = re.sub(r"[^a-z0-9_]", "_", policy_name.lower()).strip("_") or "migrated"
    return {"bucketName": f"{safe}_logs",
            "table": "logs",
            "displayName": f"Migrated: {policy_name}",
            "retentionDays": max(1, min(retention_days, 3650))}


def _dual_ship_snippets() -> List[str]:
    L: List[str] = []
    L.append("### Dual-ship snippets")
    L.append("")
    L.append("Add a second output so logs flow to both stacks during validation.")
    L.append("")
    L.append("Logstash (add alongside the existing elasticsearch output):")
    L.append("")
    L.append("```")
    L.append("output {")
    L.append("  elasticsearch { hosts => [\"es:9200\"] }   # keep during the overlap")
    L.append("  http {")
    L.append("    url             => \"https://<env-id>.live.dynatrace.com/api/v2/logs/ingest\"")
    L.append("    http_method     => \"post\"")
    L.append("    format          => \"json_batch\"")
    L.append("    headers         => { \"Authorization\" => \"Api-Token ${DT_API_TOKEN}\" }")
    L.append("    content_type    => \"application/json\"")
    L.append("  }")
    L.append("}")
    L.append("```")
    L.append("")
    L.append("OpenTelemetry Collector (send the same pipeline to both backends):")
    L.append("")
    L.append("```yaml")
    L.append("exporters:")
    L.append("  elasticsearch:")
    L.append("    endpoints: [\"https://es:9200\"]")
    L.append("  otlphttp/dynatrace:")
    L.append("    endpoint: \"https://<env-id>.live.dynatrace.com/api/v2/otlp\"")
    L.append("    headers:")
    L.append("      Authorization: \"Api-Token ${DT_API_TOKEN}\"")
    L.append("service:")
    L.append("  pipelines:")
    L.append("    logs:")
    L.append("      exporters: [elasticsearch, otlphttp/dynatrace]")
    L.append("```")
    return L


def render_cutover_plan(policies: Dict[str, Optional[int]],
                        template_patterns: Optional[Dict[str, List[str]]] = None) -> str:
    """CUTOVER-PLAN.md content. `policies` maps ILM policy name -> retention days
    (None when the policy never deletes)."""
    L: List[str] = ["# Cutover plan: Elastic to Dynatrace", ""]
    L.append("Dynatrace rejects log records older than **24 hours** (and resets "
             "timestamps more than 10 minutes in the future), so Elasticsearch "
             "history cannot be replayed into Grail. Plan around that:")
    L.append("")
    L.append("1. **Dual-ship** new logs to both stacks (snippets below).")
    L.append("2. **Validate** during the overlap: `e2d verify --data` proves tiles "
             "return data; `e2d parity` compares counts between both stacks.")
    L.append("3. **Cut over** dashboards and alerts once parity holds.")
    L.append("4. **Freeze** Elasticsearch read-only; keep it queryable until each "
             "index's retention obligation lapses (table below), then decommission.")
    L.append("5. Where history is genuinely needed inside Dynatrace, use "
             "`e2d backfill`: it re-stamps records into the accepted window and "
             "keeps the true event time in `original_timestamp`.")
    L.append("")

    if policies:
        L.append("## Retention obligations from your ILM policies")
        L.append("")
        L.append("| ILM policy | ES retention | Keep ES read-only after cutover | Grail bucket |")
        L.append("|------------|--------------|--------------------------------|--------------|")
        for name in sorted(policies):
            days = policies[name]
            if days is None:
                L.append(f"| `{name}` | no delete phase | until owners confirm | "
                         "define retention explicitly |")
            else:
                b = bucket_definition(name, days)
                L.append(f"| `{name}` | {days} d | {days} d | `{b['bucketName']}` "
                         f"({b['retentionDays']} d) |")
        L.append("")
        defs = [bucket_definition(n, d) for n, d in sorted(policies.items())
                if d is not None]
        if defs:
            L.append("## Grail bucket definitions")
            L.append("")
            L.append("POST each to `/platform/storage/management/v1/bucket-definitions` "
                     "(scope `storage:bucket-definitions:write`), then route the "
                     "matching pipeline's storage stage to the bucket:")
            L.append("")
            L.append("```json")
            L.append(json.dumps(defs, indent=2))
            L.append("```")
            L.append("")

    if template_patterns:
        L.append("## Index patterns covered")
        L.append("")
        for name, pats in sorted(template_patterns.items()):
            L.append(f"- `{name}`: " + ", ".join(f"`{p}`" for p in pats))
        L.append("")

    L.extend(_dual_ship_snippets())
    L.append("")
    L.append("## Hard limits to remember")
    L.append("")
    L.append("- Log timestamps older than now-24h are rejected (HTTP 400).")
    L.append("- Timestamps more than 10 minutes in the future are reset to now.")
    L.append("- Payloads: 10 MB / 50,000 records per ingest request.")
    L.append("- `e2d backfill` works inside these rules by re-stamping; budget "
             "DPS ingest cost before replaying large volumes.")
    return "\n".join(L) + "\n"
