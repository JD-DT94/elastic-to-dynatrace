"""Direct upload of dashboards to Dynatrace via the Document Service API.

This is the imperative alternative to the Terraform path. Terraform is generally
preferable (declarative, diffable, idempotent), but `push` is handy for quick
one-off uploads.

API: POST {env}/platform/document/v1/documents  (multipart/form-data)
  form fields : name, type=dashboard
  file part   : content  (the dashboard content JSON)
Auth: Bearer platform token with scope `document:documents:write`.

Because uploads are outward-facing and not reversible in bulk, `push` defaults to
a dry run; pass --apply to actually create documents.
"""

from __future__ import annotations

import json
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

DOC_PATH = "/platform/document/v1/documents"
# Grail DQL validation endpoint — checks a query without executing it.
QUERY_VERIFY_PATH = "/platform/storage/query/v1/query:verify"


def _iter_dashboard_files(input_path: str) -> List[Path]:
    p = Path(input_path)
    if p.is_dir():
        return sorted(q for q in p.glob("*.json"))
    return [p]


def _content_payload(doc: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
    """Return (name, content_object) from either a full dashboard or a content doc."""
    if "content" in doc and "name" in doc:
        return doc["name"], doc["content"]
    # already a bare content payload
    return doc.get("name", "Imported dashboard"), doc


# --------------------------------------------------------------------------- #
# online DQL verification (authoritative — uses the real engine)
# --------------------------------------------------------------------------- #

@dataclass
class VerifyResult:
    dql: str
    valid: Optional[bool]            # None => could not check (skipped)
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    skipped_reason: Optional[str] = None


def _parse_verify_response(dql: str, status: int, body: Dict[str, Any]) -> VerifyResult:
    """Fold the query:verify response into a VerifyResult.

    The endpoint returns a `valid` flag plus `notifications` carrying a
    `severity` (ERROR/WARNING/...) and `message`. We treat any ERROR notification
    (or an explicit `valid: false`, or a non-2xx status) as invalid.
    """
    notes = body.get("notifications") or []
    errors = [n.get("message", "") for n in notes if str(n.get("severity", "")).upper() == "ERROR"]
    warnings = [n.get("message", "") for n in notes
                if str(n.get("severity", "")).upper() in ("WARNING", "WARN")]
    valid = body.get("valid")
    if valid is None:
        valid = status < 400 and not errors
    valid = bool(valid) and not errors
    return VerifyResult(dql, valid, errors, warnings)


def verify_dql(env_url: str, token: Optional[str], dql: str, timeout: int = 30) -> VerifyResult:
    """Validate one DQL query against the tenant. Best-effort: returns a skipped
    result (valid=None) rather than raising when creds or `requests` are missing."""
    if not env_url or not token:
        return VerifyResult(dql, None, skipped_reason="no env-url/token")
    try:
        import requests
    except ImportError:
        return VerifyResult(dql, None, skipped_reason="requests not installed (pip install ...[push])")
    try:
        resp = requests.post(
            env_url.rstrip("/") + QUERY_VERIFY_PATH,
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            json={"query": dql},
            timeout=timeout,
        )
    except Exception as e:  # network failure shouldn't crash a verify sweep
        return VerifyResult(dql, None, skipped_reason=f"request failed: {e}")
    try:
        body = resp.json()
    except ValueError:
        body = {}
    if resp.status_code >= 400 and not body:
        return VerifyResult(dql, False, errors=[f"HTTP {resp.status_code}: {resp.text[:200]}"])
    return _parse_verify_response(dql, resp.status_code, body)


_VAR_REF = re.compile(r"\$[A-Za-z_][A-Za-z0-9_]*(?::[a-z]+)?")


def _substitute_variables(dql: str) -> str:
    """query:verify cannot resolve dashboard variables — stand in a neutral
    string literal so the query still parses and type-checks."""
    return _VAR_REF.sub('""', dql)


def _strip_variable_filters(dql: str) -> str:
    """For DATA checks, a variable filter substituted with "" would match nothing
    and falsely report an empty tile — drop whole `filter …$Var…` stages instead,
    then neutralise any remaining variable references."""
    parts = dql.split("\n| ")
    kept = [parts[0]] + [p for p in parts[1:]
                         if not (p.lstrip().startswith("filter") and "$" in p)]
    return _substitute_variables("\n| ".join(kept))


QUERY_EXECUTE_PATH = "/platform/storage/query/v1/query:execute"
QUERY_POLL_PATH = "/platform/storage/query/v1/query:poll"


def execute_dql_count(env_url: str, token: str, dql: str,
                      timeout: int = 60) -> Tuple[Optional[int], Optional[str]]:
    """Run a query and return (record_count, error). record_count is capped at 1 —
    the caller only needs 'returns data' vs 'returns nothing'. (None, reason)
    when the check could not run."""
    try:
        import requests
    except ImportError:
        return None, "requests not installed (pip install ...[push])"
    import time as _time
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    try:
        resp = requests.post(
            env_url.rstrip("/") + QUERY_EXECUTE_PATH, headers=headers,
            json={"query": dql, "maxResultRecords": 1,
                  "requestTimeoutMilliseconds": min(timeout, 55) * 1000},
            timeout=timeout)
        body = resp.json() if resp.content else {}
        if resp.status_code >= 400:
            return None, f"HTTP {resp.status_code}: {str(body)[:160]}"
        deadline = _time.time() + timeout
        while body.get("state") in ("RUNNING", "NOT_STARTED") and _time.time() < deadline:
            _time.sleep(1)
            resp = requests.post(
                env_url.rstrip("/") + QUERY_POLL_PATH, headers=headers,
                params={"request-token": body.get("requestToken", "")}, timeout=timeout)
            body = resp.json() if resp.content else {}
        if body.get("state") not in (None, "SUCCEEDED"):
            return None, f"query state {body.get('state')}"
        records = (body.get("result") or {}).get("records")
        if records is None:
            return None, "no result in response"
        return len(records), None
    except Exception as e:
        return None, f"request failed: {e}"


def _iter_dql_artifacts(input_path: str) -> List[Tuple[str, str]]:
    """Collect (label, dql) pairs from converted artifacts under a path:
    every `.dql` file, plus each tile query and variable input in dashboard JSON."""
    p = Path(input_path)
    items: List[Tuple[str, str]] = []
    files = [p] if p.is_file() else sorted(p.rglob("*"))
    for f in files:
        if f.suffix == ".dql":
            items.append((f.name, f.read_text(encoding="utf-8")))
        elif f.suffix == ".json":
            try:
                doc = json.loads(f.read_text(encoding="utf-8"))
            except (ValueError, OSError):
                continue
            content = doc.get("content", doc) if isinstance(doc, dict) else {}
            for key, tile in (content.get("tiles") or {}).items():
                q = tile.get("query") if isinstance(tile, dict) else None
                if q:
                    items.append((f"{f.name}#tile:{key}", _substitute_variables(q)))
            for var in content.get("variables") or []:
                q = var.get("input") if isinstance(var, dict) else None
                if q:
                    items.append((f"{f.name}#var:{var.get('key', '?')}", q))
    return items


def verify_cli(args) -> int:
    env_url = getattr(args, "env_url", None) or os.environ.get("DYNATRACE_ENV_URL")
    token = os.environ.get(getattr(args, "token_env", "DT_API_TOKEN"))
    if not env_url or not token:
        print("error: online verify needs --env-url (or DYNATRACE_ENV_URL) and a token "
              f"in {getattr(args, 'token_env', 'DT_API_TOKEN')}", file=sys.stderr)
        return 2

    items = _iter_dql_artifacts(args.input)
    if not items:
        print(f"No DQL artifacts (.dql / dashboard tiles) found at {args.input}", file=sys.stderr)
        return 1

    check_data = getattr(args, "data", False)
    n_ok = n_bad = n_skip = n_empty = 0
    for label, dql in items:
        res = verify_dql(env_url, token, dql)
        if res.valid is None:
            print(f"[SKIP ] {label}: {res.skipped_reason}")
            n_skip += 1
        elif not res.valid:
            print(f"[BAD  ] {label}: {'; '.join(res.errors) or 'invalid'}", file=sys.stderr)
            n_bad += 1
        elif check_data:
            count, err = execute_dql_count(env_url, token, _strip_variable_filters(dql))
            if err is not None:
                print(f"[OK   ] {label}  (data check skipped: {err})")
                n_ok += 1
            elif count == 0:
                print(f"[EMPTY] {label}: query is valid but returned no data in the current "
                      "timeframe — the tile will render blank. Check the fields manifest "
                      "(.fields.md) for attributes that may need an OpenPipeline extraction.",
                      file=sys.stderr)
                n_empty += 1
            else:
                print(f"[OK   ] {label}  (returns data)")
                n_ok += 1
        else:
            extra = f"  ({len(res.warnings)} warning(s))" if res.warnings else ""
            print(f"[OK   ] {label}{extra}")
            n_ok += 1

    tail = f", {n_empty} valid-but-empty" if check_data else ""
    print(f"\nverified {len(items)} quer(ies): {n_ok} ok, {n_bad} invalid{tail}, {n_skip} skipped",
          file=sys.stderr)
    return 1 if (n_bad or n_empty) else 0


def push_cli(args) -> int:
    env_url = getattr(args, "env_url", None) or os.environ.get("DYNATRACE_ENV_URL")
    if not env_url:
        print("error: provide --env-url or set DYNATRACE_ENV_URL", file=sys.stderr)
        return 2
    env_url = env_url.rstrip("/")
    token = os.environ.get(getattr(args, "token_env", "DT_API_TOKEN"))
    apply = getattr(args, "apply", False)

    files = _iter_dashboard_files(args.input)
    if not files:
        print(f"No .json dashboards found at {args.input}", file=sys.stderr)
        return 1

    if apply and not token:
        print(f"error: token env var '{getattr(args, 'token_env', 'DT_API_TOKEN')}' is empty",
              file=sys.stderr)
        return 2

    requests = None
    if apply:
        try:
            import requests  # noqa: F401
        except ImportError:
            print("error: 'requests' is required for --apply: pip install elastic-to-dynatrace[push]",
                  file=sys.stderr)
            return 2

    n_ok = n_err = 0
    for f in files:
        try:
            doc = json.loads(f.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            print(f"[SKIP] {f.name}: invalid JSON ({e})", file=sys.stderr)
            n_err += 1
            continue
        name, content = _content_payload(doc)

        if not apply:
            tiles = len(content.get("tiles", {})) if isinstance(content, dict) else "?"
            print(f"[DRY ] would create dashboard '{name}' ({tiles} tiles) from {f.name}")
            n_ok += 1
            continue

        import requests
        url = env_url + DOC_PATH
        resp = requests.post(
            url,
            headers={"Authorization": f"Bearer {token}"},
            data={"name": name, "type": "dashboard"},
            files={"content": (f.name, json.dumps(content).encode("utf-8"), "application/json")},
            timeout=60,
        )
        if resp.status_code in (200, 201):
            doc_id = ""
            try:
                doc_id = resp.json().get("documentMetadata", {}).get("id", "")
            except Exception:
                pass
            print(f"[OK  ] created '{name}'  id={doc_id}")
            n_ok += 1
        else:
            print(f"[ERR ] '{name}': HTTP {resp.status_code} {resp.text[:200]}", file=sys.stderr)
            n_err += 1

    mode = "applied" if apply else "dry-run"
    print(f"\n{mode}: {n_ok} ok, {n_err} errors", file=sys.stderr)
    return 1 if n_err else 0
