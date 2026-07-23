"""Top-level query conversion: detect dialect and route to the right front-end.

Inputs seen in the corpus:
  * Query DSL JSON (object with `query`/`aggs`) -> convert_query_dsl
  * KQL lines                                   -> existing kql translator
  * Lucene lines                                -> lucene front-end + filter emitter
A `.txt` of mixed samples uses `# KQL` / `# Lucene` section headers to switch.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from e2d.config import MappingConfig
from e2d.core.filter_ir import emit_filter, split_timeframe
from e2d.core.lucene import translate_lucene
from e2d.core.query_dsl import convert_query_dsl
from e2d.dashboards.kql import translate_kql
from e2d.dql.validate import lint_into_report
from e2d.report import Report


@dataclass
class QueryResult:
    dql: str
    report: Report = field(default_factory=Report)
    source: str = ""

    @property
    def needs_review(self) -> bool:
        return self.report.needs_review


def translate_filter_line(text: str, lang: str, config: MappingConfig,
                          data_object: str, report: Report) -> str:
    """Translate a single KQL or Lucene line into a DQL `filter` expression."""
    if lang == "lucene":
        node = translate_lucene(text, config, data_object, report)
        timeframe, remaining = split_timeframe(node)
        if timeframe:
            report.info(f"Time range lifted to query timeframe: {timeframe}")
        return emit_filter(remaining, config, data_object, report)
    # default: KQL
    return translate_kql(text, config, data_object, report)


def looks_like_json(text: str) -> bool:
    s = text.lstrip()
    return s[:1] in "{["


def convert_query_text(text: str, config: MappingConfig, data_object: str,
                       default_lang: str = "kql") -> List[QueryResult]:
    """Convert a text blob of one-per-line KQL/Lucene samples (with optional
    `# KQL` / `# Lucene` section headers)."""
    results: List[QueryResult] = []
    lang = default_lang
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("#"):
            low = line.lower()
            if "lucene" in low:
                lang = "lucene"
            elif "kql" in low:
                lang = "kql"
            continue
        report = Report()
        dql = translate_filter_line(line, lang, config, data_object, report)
        full = f"fetch {data_object}\n| filter {dql}"
        lint_into_report(full, report, data_object)
        results.append(QueryResult(dql=full, report=report, source=line))
    return results


def convert_query_json(text: str, config: MappingConfig, data_object: str) -> QueryResult:
    report = Report()
    doc = json.loads(text)
    dql, _viz = convert_query_dsl(doc, config, data_object, report)
    lint_into_report(dql, report, data_object)
    return QueryResult(dql=dql, report=report, source="(query dsl)")
