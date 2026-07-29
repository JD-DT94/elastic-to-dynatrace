"""Backfill historical Elasticsearch logs into Dynatrace despite the 24-hour wall.

Grail refuses log records whose timestamp is older than now minus 24 hours
(HTTP 400) and resets anything more than 10 minutes in the future, so history
cannot be ingested as-is. This module implements the one supportable pattern:

* every record is **re-stamped** into the accepted window, and
* the true event time is preserved in an ``original_timestamp`` attribute
  (plus ``backfilled = "true"`` and ``source.index``), so queries and
  dashboards can use the original time by filtering and charting on the
  attribute instead of the record timestamp.

Two stamp modes:

``now``
    Every record gets the ingest-time timestamp. Simple; the native timeline
    shows one spike at ingest time.
``spread``
    The original time range is mapped linearly onto the last ~23 hours,
    preserving relative order and spacing so the native timeline is roughly
    shaped like the original one (compressed).

Reads from Elasticsearch with ``search_after`` pagination; writes with the
log-ingest API in batches that stay well inside the documented limits
(10 MB payload / 50,000 records per request; attribute values <= 32 kB,
<= 500 attributes). Dry run by default; ``--apply`` sends.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterator, List, Optional, Tuple

# documented ingest limits, applied with headroom
MAX_BATCH_RECORDS = 5_000          # limit is 50,000
MAX_BATCH_BYTES = 8 * 1024 * 1024  # limit is 10 MB
MAX_ATTR_VALUE = 32 * 1024         # 32 kB per attribute value
MAX_ATTRS = 450                    # limit is 500; leave room for our own

PLATFORM_INGEST_PATH = "/platform/ingest/v1/logs"
CLASSIC_INGEST_PATH = "/api/v2/logs/ingest"

# stamp targets: stay inside now-24h with an hour of headroom, and behind
# now+10min future reset with five minutes of headroom
SPREAD_WINDOW_H = 23
SPREAD_END_MARGIN_MIN = 5


@dataclass
class BackfillStats:
    scanned: int = 0
    prepared: int = 0
    sent: int = 0
    batches: int = 0
    skipped: int = 0                       # records without a usable timestamp
    errors: List[str] = field(default_factory=list)


# --------------------------------------------------------------------------- #
# record shaping (pure, unit-tested)
# --------------------------------------------------------------------------- #

def parse_ts(value: Any) -> Optional[datetime]:
    """Parse an Elasticsearch timestamp: ISO 8601 (Z or offset) or epoch millis."""
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(value / 1000.0, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    if isinstance(value, str):
        s = value.strip()
        if s.isdigit():
            return parse_ts(int(s))
        try:
            return datetime.fromisoformat(s.replace("Z", "+00:00"))
        except ValueError:
            return None
    return None


def restamp(original: datetime, now: datetime, mode: str,
            tmin: datetime, tmax: datetime) -> datetime:
    """Place a record inside the accepted ingest window."""
    if mode == "spread" and tmax > tmin:
        start = now - timedelta(hours=SPREAD_WINDOW_H)
        end = now - timedelta(minutes=SPREAD_END_MARGIN_MIN)
        frac = (original - tmin).total_seconds() / (tmax - tmin).total_seconds()
        return start + timedelta(seconds=frac * (end - start).total_seconds())
    return now


def flatten(src: Dict[str, Any], prefix: str = "", depth: int = 0) -> Dict[str, str]:
    """Flatten a _source document to dotted string attributes (5 levels deep)."""
    out: Dict[str, str] = {}
    if depth >= 5:
        return out
    for k, v in src.items():
        key = f"{prefix}{k}"
        if isinstance(v, dict):
            out.update(flatten(v, key + ".", depth + 1))
        elif isinstance(v, list):
            out[key] = json.dumps(v)[:MAX_ATTR_VALUE]
        elif v is not None:
            out[key] = str(v)[:MAX_ATTR_VALUE]
    return out


def to_log_record(hit: Dict[str, Any], now: datetime, mode: str,
                  tmin: datetime, tmax: datetime,
                  timestamp_field: str = "@timestamp") -> Optional[Dict[str, Any]]:
    """Shape one ES hit into a Dynatrace log-ingest record, or None if it has
    no usable timestamp."""
    src = hit.get("_source") or {}
    original = parse_ts(src.get(timestamp_field))
    if original is None:
        return None
    if original.tzinfo is None:
        original = original.replace(tzinfo=timezone.utc)

    content = src.get("message")
    if not isinstance(content, str) or not content:
        content = json.dumps(src)[:MAX_ATTR_VALUE]

    attrs = flatten({k: v for k, v in src.items()
                     if k not in ("message", timestamp_field)})
    if len(attrs) > MAX_ATTRS:
        attrs = dict(sorted(attrs.items())[:MAX_ATTRS])

    record: Dict[str, Any] = dict(attrs)
    record["content"] = content
    record["timestamp"] = restamp(original, now, mode, tmin, tmax) \
        .isoformat(timespec="milliseconds")
    record["original_timestamp"] = original.isoformat(timespec="milliseconds")
    record["backfilled"] = "true"
    if hit.get("_index"):
        record["source.index"] = str(hit["_index"])
    return record


def make_batches(records: Iterator[Dict[str, Any]],
                 max_records: int = MAX_BATCH_RECORDS,
                 max_bytes: int = MAX_BATCH_BYTES) -> Iterator[List[Dict[str, Any]]]:
    """Group records into batches under both the count and payload-size limits."""
    batch: List[Dict[str, Any]] = []
    size = 2  # brackets
    for rec in records:
        blob = len(json.dumps(rec).encode("utf-8")) + 1
        if batch and (len(batch) >= max_records or size + blob > max_bytes):
            yield batch
            batch, size = [], 2
        batch.append(rec)
        size += blob
    if batch:
        yield batch


# --------------------------------------------------------------------------- #
# elasticsearch read / dynatrace write (thin network wrappers)
# --------------------------------------------------------------------------- #

def es_scan(es_url: str, token: str, auth_scheme: str, index: str,
            time_from: str, time_to: str, query_string: Optional[str],
            page_size: int, timestamp_field: str,
            verify_tls: bool = True) -> Iterator[Dict[str, Any]]:
    """Yield hits oldest-first via search_after pagination."""
    import requests
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"{auth_scheme} {token}"
    filters: List[Dict[str, Any]] = [
        {"range": {timestamp_field: {"gte": time_from, "lte": time_to}}}]
    if query_string:
        filters.append({"query_string": {"query": query_string}})
    body: Dict[str, Any] = {
        "size": page_size,
        "sort": [{timestamp_field: "asc"}, {"_doc": "asc"}],
        "query": {"bool": {"filter": filters}},
    }
    url = f"{es_url.rstrip('/')}/{index}/_search"
    while True:
        r = requests.post(url, headers=headers, json=body, timeout=120,
                          verify=verify_tls)
        r.raise_for_status()
        hits = (r.json().get("hits") or {}).get("hits") or []
        if not hits:
            return
        yield from hits
        body["search_after"] = hits[-1]["sort"]


def ingest_batch(env_url: str, token: str, batch: List[Dict[str, Any]],
                 classic: bool = False, timeout: int = 120) -> Optional[str]:
    """POST one batch; return an error string or None on success."""
    import requests
    if classic:
        url = env_url.rstrip("/") + CLASSIC_INGEST_PATH
        headers = {"Authorization": f"Api-Token {token}"}
    else:
        url = env_url.rstrip("/") + PLATFORM_INGEST_PATH
        headers = {"Authorization": f"Bearer {token}"}
    headers["Content-Type"] = "application/json; charset=utf-8"
    try:
        r = requests.post(url, headers=headers, data=json.dumps(batch),
                          timeout=timeout)
    except Exception as e:
        return f"request failed: {e}"
    if r.status_code >= 400:
        return f"HTTP {r.status_code}: {r.text[:200]}"
    return None


# --------------------------------------------------------------------------- #
# driver
# --------------------------------------------------------------------------- #

def run_backfill(es_url: str, es_token: str, es_auth: str, index: str,
                 time_from: str, time_to: str, query: Optional[str],
                 env_url: str, dt_token: str, stamp: str, apply: bool,
                 page_size: int = 1000, limit: int = 0,
                 timestamp_field: str = "@timestamp", classic: bool = False,
                 verify_tls: bool = True, out=sys.stderr) -> BackfillStats:
    stats = BackfillStats()
    tmin = parse_ts(time_from) or datetime.now(timezone.utc)
    tmax = parse_ts(time_to) or datetime.now(timezone.utc)
    if tmin.tzinfo is None:
        tmin = tmin.replace(tzinfo=timezone.utc)
    if tmax.tzinfo is None:
        tmax = tmax.replace(tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)

    def shaped() -> Iterator[Dict[str, Any]]:
        for hit in es_scan(es_url, es_token, es_auth, index, time_from, time_to,
                           query, page_size, timestamp_field, verify_tls):
            stats.scanned += 1
            rec = to_log_record(hit, now, stamp, tmin, tmax, timestamp_field)
            if rec is None:
                stats.skipped += 1
                continue
            stats.prepared += 1
            yield rec
            if limit and stats.prepared >= limit:
                return

    sample_shown = False
    for batch in make_batches(shaped()):
        stats.batches += 1
        if not sample_shown:
            print("sample record:", json.dumps(batch[0], indent=2)[:800], file=out)
            sample_shown = True
        if apply:
            err = ingest_batch(env_url, dt_token, batch, classic=classic)
            if err:
                stats.errors.append(f"batch {stats.batches}: {err}")
                if len(stats.errors) >= 5:
                    stats.errors.append("too many batch failures; aborting")
                    break
            else:
                stats.sent += len(batch)
        else:
            stats.sent += len(batch)  # would-send count in dry runs
    return stats


def backfill_cli(args) -> int:
    import os
    es_token = os.environ.get(args.es_token_env, "")
    dt_token = os.environ.get(args.token_env, "")
    env_url = args.env_url or os.environ.get("DYNATRACE_ENV_URL", "")
    if args.apply and (not env_url or not dt_token):
        print(f"error: --apply needs --env-url (or DYNATRACE_ENV_URL) and a token in "
              f"{args.token_env}", file=sys.stderr)
        return 2
    try:
        import requests  # noqa: F401
    except ImportError:
        print("error: backfill needs the requests package (pip install .[push])",
              file=sys.stderr)
        return 2

    stats = run_backfill(
        es_url=args.es_url, es_token=es_token, es_auth=args.es_auth,
        index=args.index, time_from=args.time_from, time_to=args.time_to,
        query=args.query, env_url=env_url, dt_token=dt_token,
        stamp=args.stamp, apply=args.apply, page_size=args.page_size,
        limit=args.limit, timestamp_field=args.timestamp_field,
        classic=args.classic, verify_tls=not args.insecure)

    mode = "sent" if args.apply else "would send (dry run; pass --apply)"
    print(f"\nscanned {stats.scanned}, prepared {stats.prepared}, "
          f"skipped {stats.skipped} (no usable timestamp), "
          f"{mode} {stats.sent} record(s) in {stats.batches} batch(es)",
          file=sys.stderr)
    for e in stats.errors:
        print(f"  error: {e}", file=sys.stderr)
    if stats.prepared:
        print("\nquery backfilled data by ORIGINAL time, e.g.:\n"
              "  fetch logs\n"
              "  | filter backfilled == \"true\"\n"
              f"  | filter original_timestamp >= \"{args.time_from}\" "
              f"and original_timestamp <= \"{args.time_to}\"", file=sys.stderr)
    return 1 if stats.errors else 0
