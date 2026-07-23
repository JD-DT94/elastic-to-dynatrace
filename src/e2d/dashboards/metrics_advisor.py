"""Advise where converted dashboard tiles would benefit from log→metric extraction.

The converter deliberately builds every tile on **raw log queries** (`fetch logs
| makeTimeseries …`) — that works immediately, with zero setup, on whatever is
already ingested. But a tile that continuously aggregates high-volume logs is a
textbook case for an **OpenPipeline metric-extraction processor**: extract the
number once at ingest, then chart the metric. Metrics are cheaper to query at
scale, retained longer (15 months+ vs the log bucket's retention), and faster
to render.

This module only *advises* — it never changes the tiles. Each advisory pairs the
tile's current log query with a ready-to-adapt OpenPipeline metric-extraction
scaffold and the `timeseries` query to switch the tile to afterwards.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional

# aggregation calls worth extracting: fn(field) over a numeric attribute, or a
# filtered/plain count over time
_AGG = re.compile(
    r"\b(?P<fn>avg|sum|min|max|median|percentile)\(\s*(?:if\([^)]*,\s*)?"
    r"`?(?P<field>[A-Za-z_][\w.\-]*)`?", )
_COUNT = re.compile(r"\b(?P<fn>count|countIf)\(")
_BY = re.compile(r"by:\s*\{([^}]*)\}")
_FILTER = re.compile(r"^\|\s*filter\s+(..*)$", re.M)


def _metric_key(dashboard: str, field: str) -> str:
    slug = re.sub(r"[^a-z0-9.]+", ".", field.lower()).strip(".")
    return f"log.{slug}" if slug else "log.metric"


def advise_dashboard(dashboard: Dict) -> List[Dict]:
    """Scan a converted dashboard for time-series tiles on log data and return
    one advisory per tile: which values to extract, the dimensions, and the
    metric keys to create."""
    advisories: List[Dict] = []
    name = dashboard.get("name", "dashboard")
    tiles = dashboard.get("content", {}).get("tiles", {})
    for tid, tile in tiles.items():
        if tile.get("type") != "data":
            continue
        q = tile.get("query", "")
        # only continuous/time-series tiles: one-off tables don't warrant a metric
        if "makeTimeseries" not in q and not q.startswith("timeseries"):
            continue
        if not q.startswith("fetch "):
            continue  # already metric-backed
        data_object = q.split("\n", 1)[0][len("fetch "):].strip()

        value_fields = sorted({m.group("field") for m in _AGG.finditer(q)
                               if m.group("field") not in ("timestamp",)})
        counts = len(_COUNT.findall(q))
        dims: List[str] = []
        mby = _BY.search(q)
        if mby:
            dims = [d.strip().strip("`") for d in mby.group(1).split(",") if d.strip()]

        if not value_fields and not counts:
            continue
        advisories.append({
            "dashboard": name,
            "tile": tile.get("title") or tid,
            "data_object": data_object,
            "query": q,
            "value_fields": value_fields,
            "count_series": counts,
            "dimensions": dims,
            "metric_keys": ([_metric_key(name, f) for f in value_fields]
                            or [_metric_key(name, tile.get("title") or "events") + ".count"]),
        })
    return advisories


def render_metrics_guide(advisories: List[Dict]) -> Optional[str]:
    """One Markdown guide covering every advisory across a migration run."""
    if not advisories:
        return None
    L: List[str] = ["# Log → metric extraction guide", ""]
    L.append(
        "The converted dashboards below chart **raw log queries** — they work as-is, "
        "today, with no extra setup. Keep them that way while you validate the "
        "migration. Once a tile is confirmed correct and you expect to keep it "
        "long-term, consider extracting the number into a **metric at ingest** "
        "(OpenPipeline → your logs pipeline → *Metric extraction* processor):")
    L.append("")
    L.append("- **Cost & speed** — a metric query scans a tiny fraction of the data a "
             "log scan does; busy dashboards refresh faster and consume less.")
    L.append("- **Retention** — metrics live 15+ months; log buckets usually less. "
             "Long-range trend tiles need the metric.")
    L.append("- **Alerting** — Davis anomaly detection works best on metrics.")
    L.append("")
    L.append("**Best practice:** metric keys as `log.<domain>.<name>` "
             "(e.g. `log.orders.duration`); keep dimensions **low-cardinality** "
             "(service, environment — never a correlation/transaction id); create the "
             "metric first, let it collect, then switch the tile query — the "
             "`timeseries` replacement for each tile is given below.")
    L.append("")

    by_dash: Dict[str, List[Dict]] = {}
    for a in advisories:
        by_dash.setdefault(a["dashboard"], []).append(a)

    for dash, items in by_dash.items():
        L.append(f"## {dash}")
        L.append("")
        for a in items:
            L.append(f"### Tile: {a['tile']}")
            L.append("")
            L.append(f"Currently a raw-log query on `{a['data_object']}` "
                     f"({a['count_series']} count series"
                     + (f", value fields: {', '.join('`%s`' % f for f in a['value_fields'])}"
                        if a["value_fields"] else "") + ").")
            L.append("")
            L.append("**1. OpenPipeline metric extraction** (Settings → OpenPipeline → "
                     f"`{a['data_object']}` → your pipeline → + Processor → Metric extraction):")
            L.append("")
            if a["value_fields"]:
                for f, key in zip(a["value_fields"], a["metric_keys"]):
                    L.append(f"- **Value metric** `{key}` — field to extract: `{f}`"
                             + (f"; dimensions: {', '.join('`%s`' % d for d in a['dimensions'])}"
                                if a["dimensions"] else ""))
            else:
                L.append(f"- **Counter metric** `{a['metric_keys'][0]}` (value = occurrence)"
                         + (f"; dimensions: {', '.join('`%s`' % d for d in a['dimensions'])}"
                            if a["dimensions"] else ""))
                L.append("  - Put the tile's `filter` condition into the processor's "
                         "**matching condition** so only matching records count.")
            L.append("")
            L.append("**2. After the metric has data, switch the tile query to:**")
            L.append("")
            L.append("```dql")
            key = a["metric_keys"][0]
            agg = "avg" if a["value_fields"] else "sum"
            by = f", by: {{{', '.join(a['dimensions'])}}}" if a["dimensions"] else ""
            L.append(f"timeseries {agg}({key}){by}")
            L.append("```")
            L.append("")
            L.append("<details><summary>Current raw-log query (kept in the dashboard)</summary>")
            L.append("")
            L.append("```dql")
            L.append(a["query"])
            L.append("```")
            L.append("</details>")
            L.append("")
    return "\n".join(L) + "\n"
