"""Kibana Vega panels -> standard DQL tiles, where the spec permits.

Most Kibana Vega panels are not exotic visuals — they are a standard chart
drawn over an embedded **Elasticsearch query** (``data.url = {index, body}``,
where ``body`` carries ``query``/``aggs``). That body is exactly what the
Query-DSL translator converts, and the Vega ``mark`` names the chart type. So:

  * one ES data source + a simple mark  -> real DQL tile (bar/line/area/pie…)
  * anything genuinely Vega (multiple datasets, layered/concat specs, signals,
    inline values, unparseable HJSON) -> the existing MANUAL placeholder

Kibana accepts HJSON specs; we tolerate the common lenient bits (comments and
trailing commas) but not unquoted keys — those fall back to the placeholder.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Tuple

from e2d.config import MappingConfig
from e2d.report import Report

_LINE_COMMENT = re.compile(r'^\s*(//|#)[^\n]*$', re.M)
_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.S)
_TRAILING_COMMA = re.compile(r",\s*([}\]])")


def _parse_spec(raw: Any) -> Optional[Dict[str, Any]]:
    if isinstance(raw, dict):
        return raw
    if not isinstance(raw, str) or not raw.strip():
        return None
    for attempt in (raw,
                    _TRAILING_COMMA.sub(r"\1",
                                        _LINE_COMMENT.sub("", _BLOCK_COMMENT.sub("", raw)))):
        try:
            doc = json.loads(attempt)
            return doc if isinstance(doc, dict) else None
        except ValueError:
            continue
    return None


def _es_sources(spec: Dict[str, Any]) -> Tuple[List[Tuple[Optional[str], Dict]], bool]:
    """Return ([(index, es_body), ...], has_non_es_data)."""
    data = spec.get("data")
    entries = data if isinstance(data, list) else [data] if data else []
    sources: List[Tuple[Optional[str], Dict]] = []
    non_es = False
    for e in entries:
        if not isinstance(e, dict):
            non_es = True
            continue
        url = e.get("url")
        if isinstance(url, dict) and isinstance(url.get("body"), dict):
            sources.append((url.get("index"), url["body"]))
        elif "values" in e or url is not None:
            non_es = True
    return sources, non_es


def _viz_from_mark(spec: Dict[str, Any], hint: str) -> str:
    mark = spec.get("mark")
    if isinstance(mark, dict):
        mark = mark.get("type")
    mark = str(mark or "").lower()
    if hint == "lineChart":          # has a time axis
        return {"bar": "barChart", "area": "areaChart"}.get(mark, "lineChart")
    if hint == "categorical":
        return {"arc": "pieChart", "pie": "pieChart"}.get(mark, "categoricalBarChart")
    if hint == "single":
        return "singleValue"
    return "table"


def convert_vega(params: Dict[str, Any], config: MappingConfig, report: Report,
                 fallback_index: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Try to convert a Vega panel into a standard tile.

    Returns ``{"dql", "visualization", "data_object"}`` on success, or None —
    with the reason reported — so the caller can emit the manual placeholder.
    """
    spec = _parse_spec(params.get("spec"))
    if spec is None:
        report.info("The Vega spec could not be parsed (HJSON with unquoted keys?); "
                    "falling back to a placeholder.")
        return None

    # genuinely-Vega constructs we do not attempt
    for key in ("layer", "hconcat", "vconcat", "repeat", "facet", "signals", "marks"):
        if key in spec:
            report.info(f"The Vega spec uses `{key}`, which has no standard-tile "
                        "equivalent; falling back to a placeholder.")
            return None

    sources, non_es = _es_sources(spec)
    if len(sources) != 1 or non_es:
        report.info("The Vega spec does not draw from a single embedded Elasticsearch "
                    "query; falling back to a placeholder.")
        return None

    index, body = sources[0]
    data_object = "logs"
    title = index or fallback_index
    if title:
        do = config.resolve_data_object(str(title))
        if do and do != "__metrics__":
            data_object = do
        elif do is None:
            report.warn(f"Vega index `{title}` matched no data-object rule; defaulting "
                        "to `logs`. Add an index_map rule.", source=str(title))

    from e2d.core.query_dsl import convert_query_dsl
    dql, hint = convert_query_dsl(body, config, data_object, report)
    if spec.get("transform"):
        report.warn("The Vega spec post-processes its query result (`transform`); the tile "
                    "charts the raw aggregation — compare it with the original panel.")
    report.info("Vega panel converted from its embedded Elasticsearch query; the visual "
                "styling is Dynatrace-standard rather than the custom Vega rendering.")
    return {"dql": dql, "visualization": _viz_from_mark(spec, hint),
            "data_object": data_object}
