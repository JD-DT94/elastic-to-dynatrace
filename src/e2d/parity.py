"""Parity check: does the converted DQL count what the original query counted?

The single biggest trust question in a migration is "does the new tile show
the same numbers as the old one". During a dual-ship window both stacks hold
the same data, so it becomes answerable: run the original Query DSL against
Elasticsearch (`_count`) and the converted DQL against Grail (count over the
same window), and compare within a tolerance (dual-shipped stacks are rarely
byte-identical; ingest lag and pipeline drops cause small drift).

v1 scope: Query DSL inputs (.json files carrying a `query`). ES|QL and
KQL/Lucene texts are reported as skipped; extending them mainly needs an
executor per dialect.
"""

from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from e2d.config import MappingConfig

DEFAULT_TOLERANCE = 0.02   # 2% relative drift is a pass by default


@dataclass
class ParityCase:
    label: str
    es_query: Dict[str, Any]     # the DSL `query` body for _count
    dql: str                     # converted count query, window applied


@dataclass
class ParityVerdict:
    label: str
    es_count: Optional[int]
    dql_count: Optional[int]
    verdict: str                 # MATCH | DIFF | SKIP
    detail: str = ""


# --------------------------------------------------------------------------- #
# pure pieces (unit-tested)
# --------------------------------------------------------------------------- #

def count_dql(dql: str, window: str) -> str:
    """Turn a converted query into a windowed count. Filter-only queries get a
    summarize appended; queries that already aggregate are counted as-is by
    wrapping their row count."""
    dql = dql.strip()
    dql = re.sub(r"^fetch\s+(\w+)", rf"fetch \1, from: now() - {window}", dql, count=1)
    if "summarize" not in dql and "makeTimeseries" not in dql:
        return dql + "\n| summarize parity_count = count()"
    return dql


def es_count_body(query: Dict[str, Any], window: str,
                  timestamp_field: str = "@timestamp") -> Dict[str, Any]:
    """Wrap the original DSL query with the same relative window."""
    rng = {"range": {timestamp_field: {"gte": f"now-{window}"}}}
    if not query:
        return {"query": rng}
    return {"query": {"bool": {"must": [query], "filter": [rng]}}}


def compare(es_count: Optional[int], dql_count: Optional[int], label: str,
            tolerance: float = DEFAULT_TOLERANCE) -> ParityVerdict:
    if es_count is None or dql_count is None:
        return ParityVerdict(label, es_count, dql_count, "SKIP",
                             "one side could not be executed")
    if es_count == dql_count:
        return ParityVerdict(label, es_count, dql_count, "MATCH", "exact")
    base = max(es_count, dql_count)
    drift = abs(es_count - dql_count) / base if base else 0.0
    if drift <= tolerance:
        return ParityVerdict(label, es_count, dql_count, "MATCH",
                             f"within tolerance ({drift:.2%})")
    return ParityVerdict(label, es_count, dql_count, "DIFF",
                         f"drift {drift:.2%} exceeds tolerance {tolerance:.0%}")


def collect_cases(in_dir: str, config: MappingConfig, window: str) -> Tuple[List[ParityCase], List[str]]:
    """Pair each Query DSL input with its converted count-DQL."""
    from e2d.migrate import classify
    from e2d.core.queries import convert_query_json
    cases: List[ParityCase] = []
    skipped: List[str] = []
    for p in sorted(Path(in_dir).rglob("*")):
        if not p.is_file():
            continue
        try:
            text = p.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        kind = classify(p, text)
        if kind == "querydsl":
            doc = json.loads(text)
            res = convert_query_json(text, config, "logs")
            cases.append(ParityCase(p.name, doc.get("query") or {},
                                    count_dql(res.dql, window)))
        elif kind in ("esql", "querytext"):
            skipped.append(f"{p.name}: {kind} parity not implemented yet; compare by hand")
    return cases, skipped


# --------------------------------------------------------------------------- #
# executors + CLI
# --------------------------------------------------------------------------- #

def _es_count(es_url: str, token: str, scheme: str, index: str,
              body: Dict[str, Any], verify_tls: bool) -> Tuple[Optional[int], str]:
    try:
        import requests
    except ImportError:
        return None, "requests not installed"
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"{scheme} {token}"
    try:
        r = requests.post(f"{es_url.rstrip('/')}/{index}/_count", headers=headers,
                          json=body, timeout=60, verify=verify_tls)
        if r.status_code >= 400:
            return None, f"ES HTTP {r.status_code}: {r.text[:160]}"
        return int(r.json().get("count", 0)), ""
    except Exception as e:
        return None, f"ES request failed: {e}"


def _dql_count(env_url: str, token: str, dql: str) -> Tuple[Optional[int], str]:
    from e2d.api.client import QUERY_EXECUTE_PATH, QUERY_POLL_PATH
    try:
        import requests
    except ImportError:
        return None, "requests not installed"
    import time as _time
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    try:
        r = requests.post(env_url.rstrip("/") + QUERY_EXECUTE_PATH, headers=headers,
                          json={"query": dql, "maxResultRecords": 10,
                                "requestTimeoutMilliseconds": 55_000}, timeout=60)
        body = r.json() if r.content else {}
        if r.status_code >= 400:
            return None, f"DT HTTP {r.status_code}: {str(body)[:160]}"
        deadline = _time.time() + 60
        while body.get("state") in ("RUNNING", "NOT_STARTED") and _time.time() < deadline:
            _time.sleep(1)
            r = requests.post(env_url.rstrip("/") + QUERY_POLL_PATH, headers=headers,
                              params={"request-token": body.get("requestToken", "")},
                              timeout=60)
            body = r.json() if r.content else {}
        records = (body.get("result") or {}).get("records") or []
        if not records:
            return 0, ""
        first = records[0]
        for key in ("parity_count", "count()", "count"):
            if isinstance(first, dict) and key in first:
                return int(first[key]), ""
        # aggregated query: parity over its row count
        return len(records), ""
    except Exception as e:
        return None, f"DT request failed: {e}"


def parity_cli(args) -> int:
    import os
    config = MappingConfig.load(args.config) if args.config else MappingConfig()
    env_url = args.env_url or os.environ.get("DYNATRACE_ENV_URL", "")
    dt_token = os.environ.get(args.token_env, "")
    es_token = os.environ.get(args.es_token_env, "")
    if not env_url or not dt_token:
        print(f"error: parity needs --env-url (or DYNATRACE_ENV_URL) and a token in "
              f"{args.token_env}", file=sys.stderr)
        return 2

    cases, skipped = collect_cases(args.input, config, args.window)
    for s in skipped:
        print(f"[SKIP ] {s}")
    if not cases:
        print("No Query DSL inputs found to compare.", file=sys.stderr)
        return 1

    n_match = n_diff = n_skip = 0
    for case in cases:
        es_n, es_err = _es_count(args.es_url, es_token, args.es_auth, args.index,
                                 es_count_body(case.es_query, args.window),
                                 not args.insecure)
        dt_n, dt_err = _dql_count(env_url, dt_token, case.dql)
        v = compare(es_n, dt_n, case.label, args.tolerance)
        detail = v.detail if v.verdict != "SKIP" else (es_err or dt_err or v.detail)
        print(f"[{v.verdict:5}] {v.label}: ES={v.es_count} DQL={v.dql_count}  ({detail})")
        n_match += v.verdict == "MATCH"
        n_diff += v.verdict == "DIFF"
        n_skip += v.verdict == "SKIP"

    print(f"\nparity over last {args.window}: {n_match} match, {n_diff} differ, "
          f"{n_skip} skipped (of {len(cases)})", file=sys.stderr)
    return 1 if n_diff else 0
