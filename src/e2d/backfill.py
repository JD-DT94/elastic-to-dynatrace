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

import hashlib
import json
import re
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple

from e2d.net import RetryPolicy, classify_response, with_retry

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
    sample: Optional[Dict[str, Any]] = None  # first shaped record, for inspection
    dlq: int = 0                             # records written to the dead-letter file
    resumed: bool = False                    # this run continued from a checkpoint
    note: str = ""                           # human context (resume/skip messages)


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
    """Flatten a _source document to dotted string attributes (5 levels deep).

    Keys are lowercased to mirror Dynatrace's ingest normalization, so the
    sample record and dedup counts show exactly what lands in Grail."""
    out: Dict[str, str] = {}
    if depth >= 5:
        return out
    for k, v in src.items():
        key = f"{prefix}{k}".lower()
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
    if hit.get("_id"):
        # deterministic key: duplicates from an interrupted run stay detectable
        # in DQL (summarize by dedup.key) even though ingest has no upsert
        record["dedup.key"] = hashlib.sha1(
            f"{hit.get('_index', '')}/{hit['_id']}".encode()).hexdigest()[:16]
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
            verify_tls: bool = True, search_after: Optional[list] = None,
            policy: Optional[RetryPolicy] = None,
            sleep=time.sleep) -> Iterator[Dict[str, Any]]:
    """Yield hits oldest-first via search_after pagination. Each page fetch
    runs under the retry envelope; a page that still fails after the envelope
    raises RuntimeError (the caller keeps its checkpoint and can resume)."""
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
    if search_after:
        body["search_after"] = search_after
    url = f"{es_url.rstrip('/')}/{index}/_search"
    while True:
        got: Dict[str, Any] = {}

        def attempt():
            try:
                r = requests.post(url, headers=headers, json=body, timeout=120,
                                  verify=verify_tls)
            except Exception as e:
                return False, True, f"request failed: {e}", None
            ok, retryable, detail, ra = classify_response(
                r.status_code, r.text, r.headers)
            if ok:
                got["json"] = r.json()
            return ok, retryable, detail, ra

        ok, detail, _ = with_retry(attempt, policy, sleep=sleep)
        if not ok:
            raise RuntimeError(f"Elasticsearch read failed: {detail}")
        hits = (got["json"].get("hits") or {}).get("hits") or []
        if not hits:
            return
        yield from hits
        body["search_after"] = hits[-1]["sort"]


def ingest_batch(env_url: str, token: str, batch: List[Dict[str, Any]],
                 classic: bool = False, timeout: int = 120,
                 policy: Optional[RetryPolicy] = None,
                 sleep=time.sleep) -> Tuple[Optional[str], bool]:
    """POST one batch under the retry envelope.

    Returns (error, permanent). (None, False) on success. permanent=True means
    the server rejected the payload itself (a non-retryable 4xx): the batch
    belongs in the dead-letter file, not in another retry."""
    import requests
    if classic:
        url = env_url.rstrip("/") + CLASSIC_INGEST_PATH
        headers = {"Authorization": f"Api-Token {token}"}
    else:
        url = env_url.rstrip("/") + PLATFORM_INGEST_PATH
        headers = {"Authorization": f"Bearer {token}"}
    headers["Content-Type"] = "application/json; charset=utf-8"
    payload = json.dumps(batch)
    seen = {"permanent": False}

    def attempt():
        try:
            r = requests.post(url, headers=headers, data=payload, timeout=timeout)
        except Exception as e:
            return False, True, f"request failed: {e}", None
        ok, retryable, detail, ra = classify_response(r.status_code, r.text, r.headers)
        seen["permanent"] = (not ok) and (not retryable)
        return ok, retryable, detail, ra

    ok, detail, _ = with_retry(attempt, policy, sleep=sleep)
    if ok:
        return None, False
    return detail, seen["permanent"]


# --------------------------------------------------------------------------- #
# checkpoint + dead-letter files
# --------------------------------------------------------------------------- #

def _load_state(path: str, index: str, time_from: str, time_to: str) -> Optional[dict]:
    try:
        st = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if (st.get("index"), st.get("from"), st.get("to")) != (index, time_from, time_to):
        return None  # a different window: ignore, will be overwritten
    return st


def _save_state(path: str, **st: Any) -> None:
    Path(path).write_text(json.dumps(st), encoding="utf-8")


def _dead_letter(path: str, records: List[Dict[str, Any]]) -> None:
    with open(path, "a", encoding="utf-8") as fh:
        for rec in records:
            fh.write(json.dumps(rec) + "\n")


def discover_indices(es_url: str, token: str, auth_scheme: str,
                     pattern: str = "*", timestamp_field: str = "@timestamp",
                     verify_tls: bool = True, max_indices: int = 200) -> List[Dict[str, Any]]:
    """List non-system indices matching `pattern` with doc counts, on-disk size,
    and the oldest/newest timestamp each one holds, so a caller can offer a
    pick-what-to-backfill table."""
    import requests
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"{auth_scheme} {token}"
    base = es_url.rstrip("/")
    r = requests.get(f"{base}/_cat/indices/{pattern}"
                     "?format=json&h=index,docs.count,store.size&s=index",
                     headers=headers, timeout=60, verify=verify_tls)
    r.raise_for_status()
    rows: List[Dict[str, Any]] = []
    for row in r.json():
        idx = row.get("index", "")
        if not idx or idx.startswith("."):
            continue
        entry: Dict[str, Any] = {"index": idx,
                                 "docs": int(row.get("docs.count") or 0),
                                 "size": row.get("store.size") or "",
                                 "oldest": None, "newest": None}
        try:
            rr = requests.post(
                f"{base}/{idx}/_search", headers=headers, timeout=30,
                verify=verify_tls,
                json={"size": 0, "aggs": {
                    "mn": {"min": {"field": timestamp_field,
                                   "format": "strict_date_time"}},
                    "mx": {"max": {"field": timestamp_field,
                                   "format": "strict_date_time"}}}})
            aggs = rr.json().get("aggregations") or {}
            entry["oldest"] = (aggs.get("mn") or {}).get("value_as_string")
            entry["newest"] = (aggs.get("mx") or {}).get("value_as_string")
        except Exception:
            pass  # index without the timestamp field: still listed, no range
        rows.append(entry)
        if len(rows) >= max_indices:
            break
    return rows


# --------------------------------------------------------------------------- #
# driver
# --------------------------------------------------------------------------- #

def run_backfill(es_url: str, es_token: str, es_auth: str, index: str,
                 time_from: str, time_to: str, query: Optional[str],
                 env_url: str, dt_token: str, stamp: str, apply: bool,
                 page_size: int = 1000, limit: int = 0,
                 timestamp_field: str = "@timestamp", classic: bool = False,
                 verify_tls: bool = True, out=sys.stderr,
                 on_progress=None, state_path: Optional[str] = None,
                 dlq_path: Optional[str] = None,
                 policy: Optional[RetryPolicy] = None,
                 sleep=time.sleep) -> BackfillStats:
    stats = BackfillStats()
    tmin = parse_ts(time_from) or datetime.now(timezone.utc)
    tmax = parse_ts(time_to) or datetime.now(timezone.utc)
    if tmin.tzinfo is None:
        tmin = tmin.replace(tzinfo=timezone.utc)
    if tmax.tzinfo is None:
        tmax = tmax.replace(tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)

    # checkpoint: resume an interrupted apply run instead of duplicating it
    cursor: Optional[list] = None
    prior_sent = prior_scanned = 0
    if state_path and apply:
        st = _load_state(state_path, index, time_from, time_to)
        if st and st.get("done"):
            stats.note = (f"checkpoint says this window is complete "
                          f"({st.get('sent', 0)} records sent); delete "
                          f"{state_path} to redo it")
            if out is not None:
                print(stats.note, file=out)
            return stats
        if st:
            cursor = st.get("cursor")
            prior_sent = int(st.get("sent") or 0)
            prior_scanned = int(st.get("scanned") or 0)
            stats.resumed = True
            stats.note = f"resumed from checkpoint ({prior_sent} records already sent)"
            if out is not None:
                print(stats.note, file=out)

    def shaped() -> Iterator[Dict[str, Any]]:
        for hit in es_scan(es_url, es_token, es_auth, index, time_from, time_to,
                           query, page_size, timestamp_field, verify_tls,
                           search_after=cursor, policy=policy, sleep=sleep):
            stats.scanned += 1
            rec = to_log_record(hit, now, stamp, tmin, tmax, timestamp_field)
            if rec is None:
                stats.skipped += 1
                continue
            rec["__sort"] = hit.get("sort")
            stats.prepared += 1
            yield rec
            if limit and stats.prepared >= limit:
                return

    aborted = False
    try:
        for batch in make_batches(shaped()):
            stats.batches += 1
            payload = [{k: v for k, v in r.items() if k != "__sort"} for r in batch]
            if stats.sample is None:
                stats.sample = payload[0]
                if out is not None:
                    print("sample record:", json.dumps(payload[0], indent=2)[:800],
                          file=out)
            if apply:
                err, permanent = ingest_batch(env_url, dt_token, payload,
                                              classic=classic, policy=policy,
                                              sleep=sleep)
                if err and permanent:
                    # the payload itself is rejected: dead-letter it and move on
                    stats.errors.append(f"batch {stats.batches} dead-lettered: {err}")
                    if dlq_path:
                        _dead_letter(dlq_path, payload)
                        stats.dlq += len(payload)
                elif err:
                    # retry envelope exhausted: the target is down. Keep the
                    # checkpoint and stop so a re-run resumes cleanly.
                    stats.errors.append(f"batch {stats.batches}: {err}")
                    aborted = True
                else:
                    stats.sent += len(batch)
            else:
                stats.sent += len(batch)  # would-send count in dry runs
            if apply and not aborted and state_path:
                sort = batch[-1].get("__sort")
                if sort is not None:
                    _save_state(state_path, index=index, sent=prior_sent + stats.sent,
                                scanned=prior_scanned + stats.scanned, cursor=sort,
                                done=False, **{"from": time_from, "to": time_to})
            if on_progress is not None:
                on_progress(stats)
            if aborted:
                break
    except RuntimeError as e:  # ES read failed after the retry envelope
        stats.errors.append(str(e))
        aborted = True
    if apply and state_path and not aborted:
        _save_state(state_path, index=index, sent=prior_sent + stats.sent,
                    scanned=prior_scanned + stats.scanned, cursor=None,
                    done=True, **{"from": time_from, "to": time_to})
    if on_progress is not None:
        on_progress(stats)
    return stats


def run_redrive(dlq_file: str, env_url: str, dt_token: str, apply: bool,
                classic: bool = False, policy: Optional[RetryPolicy] = None,
                sleep=time.sleep) -> BackfillStats:
    """Re-send dead-lettered records. Successes are dropped from the file;
    records that still fail stay in it for the next attempt."""
    stats = BackfillStats()
    records: List[Dict[str, Any]] = []
    with open(dlq_file, "r", encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                records.append(json.loads(line))
    stats.scanned = stats.prepared = len(records)
    remaining: List[Dict[str, Any]] = []
    for batch in make_batches(iter(records)):
        stats.batches += 1
        if not apply:
            stats.sent += len(batch)
            continue
        err, _permanent = ingest_batch(env_url, dt_token, batch, classic=classic,
                                       policy=policy, sleep=sleep)
        if err:
            stats.errors.append(f"batch {stats.batches}: {err}")
            remaining.extend(batch)
        else:
            stats.sent += len(batch)
    if apply:
        if remaining:
            Path(dlq_file).write_text(
                "".join(json.dumps(r) + "\n" for r in remaining), encoding="utf-8")
            stats.dlq = len(remaining)
        else:
            Path(dlq_file).unlink()
    return stats


def backfill_cli(args) -> int:
    import os
    es_token = os.environ.get(args.es_token_env, "")
    dt_token = os.environ.get(args.token_env, "")
    env_url = args.env_url or os.environ.get("DYNATRACE_ENV_URL", "")
    try:
        import requests  # noqa: F401
    except ImportError:
        print("error: backfill needs the requests package (pip install .[push])",
              file=sys.stderr)
        return 2

    if getattr(args, "discover", False):
        rows = discover_indices(args.es_url, es_token, args.es_auth,
                                args.index or "*", args.timestamp_field,
                                verify_tls=not args.insecure)
        if not rows:
            print("No matching indices.", file=sys.stderr)
            return 1
        w = max(len(r["index"]) for r in rows)
        print(f"{'INDEX':{w}}  {'DOCS':>12}  {'SIZE':>8}  OLDEST .. NEWEST")
        for r in rows:
            print(f"{r['index']:{w}}  {r['docs']:>12,}  {r['size']:>8}  "
                  f"{r['oldest'] or '?'} .. {r['newest'] or '?'}")
        return 0

    if getattr(args, "redrive", None):
        if args.apply and (not env_url or not dt_token):
            print(f"error: --redrive --apply needs --env-url and a token in "
                  f"{args.token_env}", file=sys.stderr)
            return 2
        stats = run_redrive(args.redrive, env_url, dt_token, apply=args.apply,
                            classic=args.classic)
        mode = "re-sent" if args.apply else "would re-send (dry run; pass --apply)"
        print(f"{mode} {stats.sent} of {stats.prepared} dead-lettered record(s) "
              f"in {stats.batches} batch(es)", file=sys.stderr)
        if stats.dlq:
            print(f"  {stats.dlq} record(s) still failing; kept in {args.redrive}",
                  file=sys.stderr)
        for e in stats.errors:
            print(f"  error: {e}", file=sys.stderr)
        return 1 if stats.errors else 0

    if not args.index:
        print("error: --index is required (or use --discover to list indices)",
              file=sys.stderr)
        return 2
    if not args.time_from or not args.time_to:
        print("error: --from and --to are required (use --discover to see each "
              "index's time range)", file=sys.stderr)
        return 2
    if args.apply and (not env_url or not dt_token):
        print(f"error: --apply needs --env-url (or DYNATRACE_ENV_URL) and a token in "
              f"{args.token_env}", file=sys.stderr)
        return 2

    indices = [i.strip() for i in args.index.split(",") if i.strip()]
    if args.state and len(indices) > 1:
        print("error: --state works with a single --index; omit it to get one "
              "state file per index", file=sys.stderr)
        return 2
    failed = False
    for index in indices:
        if len(indices) > 1:
            print(f"\n== {index} ==", file=sys.stderr)
        safe = re.sub(r"[^A-Za-z0-9_-]", "_", index)
        state_path = None if args.no_state else \
            (args.state or f"e2d-backfill-{safe}.state.json")
        dlq_path = args.dlq or (state_path.replace(".state.json", ".dlq.ndjson")
                                if state_path else "e2d-backfill.dlq.ndjson")
        stats = run_backfill(
            es_url=args.es_url, es_token=es_token, es_auth=args.es_auth,
            index=index, time_from=args.time_from, time_to=args.time_to,
            query=args.query, env_url=env_url, dt_token=dt_token,
            stamp=args.stamp, apply=args.apply, page_size=args.page_size,
            limit=args.limit, timestamp_field=args.timestamp_field,
            classic=args.classic, verify_tls=not args.insecure,
            state_path=state_path, dlq_path=dlq_path)

        mode = "sent" if args.apply else "would send (dry run; pass --apply)"
        print(f"\nscanned {stats.scanned}, prepared {stats.prepared}, "
              f"skipped {stats.skipped} (no usable timestamp), "
              f"{mode} {stats.sent} record(s) in {stats.batches} batch(es)",
              file=sys.stderr)
        if stats.dlq:
            print(f"  {stats.dlq} record(s) dead-lettered to {dlq_path}; fix and "
                  f"re-send with: e2d backfill --es-url {args.es_url} "
                  f"--redrive {dlq_path} --apply", file=sys.stderr)
        for e in stats.errors:
            print(f"  error: {e}", file=sys.stderr)
        failed = failed or bool(stats.errors)

    print("\nquery backfilled data by ORIGINAL time, e.g.:\n"
          "  fetch logs\n"
          "  | filter backfilled == \"true\"\n"
          f"  | filter original_timestamp >= \"{args.time_from}\" "
          f"and original_timestamp <= \"{args.time_to}\"", file=sys.stderr)
    return 1 if failed else 0
