"""Single-query conversion behind the paste-a-query box in both GUIs.

Takes one pasted Elastic query (ES|QL, Query DSL JSON, KQL or Lucene), returns
the DQL plus the same warnings a full migration run would surface, as a plain
dict the pages can render directly.
"""

from __future__ import annotations

import re
from typing import Optional

from e2d.config import MappingConfig

_ESQL_START = re.compile(r"(?is)^\s*(from|row|show)\b")


def detect_lang(text: str) -> str:
    s = text.strip()
    if s[:1] in "{[":
        return "dsl"
    if _ESQL_START.match(s):
        return "esql"
    return "kql"


def convert_query(text: str, lang: str = "auto",
                  config: Optional[MappingConfig] = None,
                  data_object: str = "logs") -> dict:
    """Convert one pasted query. Never raises; failures come back as
    ``{"error": ..., "status": "ERROR"}`` so the page can show them inline."""
    config = config or MappingConfig()
    text = (text or "").strip()
    if not text:
        return {"lang": lang, "dql": "", "notes": [], "status": "ERROR",
                "error": "Nothing to convert. Paste a query first."}
    if lang in ("", "auto"):
        lang = detect_lang(text)
    try:
        if lang == "esql":
            from e2d.esql.translator import translate_esql
            res = translate_esql(text, config)
            dql, notes = res.dql, res.report.format_deduped()
            status = _status(res.report)
        elif lang == "dsl":
            from e2d.core.queries import convert_query_json
            res = convert_query_json(text, config, data_object)
            dql, notes = res.dql, res.report.format_deduped()
            status = _status(res.report)
        else:  # kql / lucene, one query per line
            from e2d.core.queries import convert_query_text
            results = convert_query_text(text, config, data_object, default_lang=lang)
            if not results:
                return {"lang": lang, "dql": "", "notes": [], "status": "ERROR",
                        "error": "No query lines found in the pasted text."}
            dql = "\n\n".join(r.dql for r in results)
            notes, status = [], "OK"
            for r in results:
                notes += r.report.format_deduped()
                status = _worst(status, _status(r.report))
    except ValueError as e:
        return {"lang": lang, "dql": "", "notes": [], "status": "ERROR",
                "error": f"Could not parse the query as {lang}: {e}"}
    except Exception as e:  # a bad paste must never take the page down
        return {"lang": lang, "dql": "", "notes": [], "status": "ERROR",
                "error": f"Conversion failed: {e}"}
    return {"lang": lang, "dql": dql, "notes": notes, "status": status}


def _status(report) -> str:
    if report.has_blocking:
        return "MANUAL"
    if report.needs_review:
        return "REVIEW"
    return "OK"


def _worst(a: str, b: str) -> str:
    order = {"OK": 0, "REVIEW": 1, "MANUAL": 2, "ERROR": 3}
    return a if order[a] >= order[b] else b
