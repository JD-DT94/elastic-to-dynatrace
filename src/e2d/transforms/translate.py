"""Continuous transform (pivot) -> rollup DQL + a plan.

The pivot's `group_by` entries are terms/date_histogram buckets and its
`aggregations` are the metrics — exactly an Elasticsearch `aggs` tree. Merging
them into one flat `aggs` and running it through `convert_query_dsl` yields the
`summarize`/`makeTimeseries` rollup the transform materialises.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, List, Optional

from e2d.config import MappingConfig
from e2d.core.query_dsl import convert_query_dsl
from e2d.dql.validate import lint_into_report
from e2d.report import Report


@dataclass
class TransformResult:
    name: str
    dql: str
    data_object: str
    frequency: Optional[str]
    has_ratio: bool          # an availability/success bucket_script -> SLO candidate
    report: Report


def is_transform(doc: Any) -> bool:
    return isinstance(doc, dict) and "pivot" in doc and "source" in doc


def translate_transform(text_or_doc: Any, config: Optional[MappingConfig] = None,
                        name: Optional[str] = None) -> TransformResult:
    config = config or MappingConfig()
    report = Report()
    doc = text_or_doc if isinstance(text_or_doc, dict) else json.loads(text_or_doc)

    src = doc.get("source", {})
    idx = src.get("index")
    indices = idx if isinstance(idx, list) else ([idx] if idx else [])
    data_object = "logs"
    for i in indices:
        d = config.resolve_data_object(i or "")
        if d and d != "__metrics__":
            data_object = d
            break

    pivot = doc.get("pivot", {})
    merged = {**pivot.get("group_by", {}), **pivot.get("aggregations", {})}
    body: dict = {"size": 0, "aggs": merged}
    if src.get("query"):
        body["query"] = src["query"]

    dql, _viz = convert_query_dsl(body, config, data_object, report)
    lint_into_report(dql, report, data_object)

    has_ratio = any("bucket_script" in a for a in pivot.get("aggregations", {}).values()
                    if isinstance(a, dict))
    freq = doc.get("frequency")
    delay = doc.get("sync", {}).get("time", {}).get("delay")
    report.info(f"Continuous transform (runs every {freq}, sync delay {delay}) -> run this DQL on a "
                "schedule: a Workflow timer writing a metric via OpenPipeline, or an SLO for a ratio.")
    return TransformResult(name or doc.get("id") or "transform", dql, data_object, freq, has_ratio, report)


def render_transform(res: TransformResult) -> str:
    L: List[str] = [f"# Transform: {res.name}", ""]
    L.append(f"Source data object: **{res.data_object}**  ·  Originally a **continuous** transform "
             f"(every **{res.frequency}**)")
    L.append("")
    L.append("## Rollup query (DQL)")
    L.append("")
    L.append("```dql")
    L.append(res.dql)
    L.append("```")
    L.append("")
    L.append("## How to build it in Dynatrace")
    L.append("")
    L.append("A transform materialises a rollup index; Dynatrace computes on read, so you usually "
             "**don't need to pre-materialise**. Options:")
    L.append("- Put the DQL on a **dashboard tile / Notebook** and query live (simplest).")
    L.append("- For a stored rollup metric, run the DQL on a **scheduled Workflow** and write the result "
             "via an OpenPipeline `value_metric` processor.")
    if res.has_ratio:
        L.append("- This transform computes an **availability/success ratio** — model it as a Dynatrace "
                 "**SLO** (the ratio becomes the SLO's success criterion).")
    L.append("- Verify the rollup matches the source transform before relying on it.")
    return "\n".join(L) + "\n"
