"""Pull Elastic/Kibana artifacts via their REST APIs.

Discovery hits the four sources e2d can convert:
  * Kibana dashboards      GET {kibana}/api/saved_objects/_find?type=dashboard
  * Kibana alerting rules  GET {kibana}/api/alerting/rules/_find
  * ES ingest pipelines    GET {es}/_ingest/pipeline
  * ES watchers            GET {es}/_watcher/_query/watches  (POST on some versions)

`pull` then fetches each selected item's raw JSON/NDJSON, ready for the offline
converter. Everything is best-effort: a source that errors or 404s is skipped, so
one missing API never sinks the whole discovery. Auth is an API key or bearer
token, held only for the lifetime of the call.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class Connection:
    kibana_url: str = ""        # e.g. https://kibana.example:5601
    es_url: str = ""            # e.g. https://es.example:9200
    token: str = ""             # API key (base64) or bearer token
    auth_scheme: str = "ApiKey"  # ApiKey | Bearer
    verify_tls: bool = True


@dataclass
class DiscoveredItem:
    kind: str                   # dashboard | rule | pipeline | watcher
    id: str
    name: str


def _session(conn: Connection):
    import requests
    s = requests.Session()
    s.headers.update({"Authorization": f"{conn.auth_scheme} {conn.token}",
                      "kbn-xsrf": "e2d", "Content-Type": "application/json"})
    s.verify = conn.verify_tls
    return s


def _get(sess, url: str, timeout: int = 30):
    r = sess.get(url, timeout=timeout)
    r.raise_for_status()
    return r.json()


# --------------------------------------------------------------------------- #
# discovery
# --------------------------------------------------------------------------- #

def discover(conn: Connection) -> Dict[str, Any]:
    """Return {"items": [DiscoveredItem...], "errors": {source: message}}.

    Never raises: each source is probed independently and failures are reported
    so the GUI can show a partial result.
    """
    try:
        import requests  # noqa: F401
    except ImportError:
        return {"items": [], "errors": {"_": "requests not installed (pip install ...[push])"}}

    sess = _session(conn)
    items: List[DiscoveredItem] = []
    errors: Dict[str, str] = {}

    if conn.kibana_url:
        kb = conn.kibana_url.rstrip("/")
        _probe(errors, "dashboards", lambda: items.extend(
            DiscoveredItem("dashboard", o["id"], o.get("attributes", {}).get("title", o["id"]))
            for o in _get(sess, f"{kb}/api/saved_objects/_find?type=dashboard&per_page=1000")
            .get("saved_objects", [])))
        _probe(errors, "rules", lambda: items.extend(
            DiscoveredItem("rule", o["id"], o.get("name", o["id"]))
            for o in _get(sess, f"{kb}/api/alerting/rules/_find?per_page=1000").get("data", [])))

    if conn.es_url:
        es = conn.es_url.rstrip("/")
        _probe(errors, "pipelines", lambda: items.extend(
            DiscoveredItem("pipeline", name, name)
            for name in _get(sess, f"{es}/_ingest/pipeline").keys()))
        _probe(errors, "watchers", lambda: items.extend(
            DiscoveredItem("watcher", h["_id"], h["_id"])
            for h in _get(sess, f"{es}/_watcher/_query/watches").get("watches", [])))

    return {"items": [i.__dict__ for i in items], "errors": errors}


def _probe(errors: Dict[str, str], name: str, fn) -> None:
    try:
        fn()
    except Exception as e:  # one bad source never sinks discovery
        errors[name] = str(e)


# --------------------------------------------------------------------------- #
# pull
# --------------------------------------------------------------------------- #

def pull(conn: Connection, selection: List[Dict[str, str]]) -> List[Tuple[str, str]]:
    """Fetch each selected item; return (filename, content) pairs ready to write
    into the converter's input directory."""
    sess = _session(conn)
    kb = conn.kibana_url.rstrip("/") if conn.kibana_url else ""
    es = conn.es_url.rstrip("/") if conn.es_url else ""
    out: List[Tuple[str, str]] = []
    for item in selection:
        kind, oid = item.get("kind"), item.get("id")
        try:
            if kind == "dashboard":
                # export as NDJSON (what the dashboard track consumes)
                body = json.dumps({"objects": [{"type": "dashboard", "id": oid}],
                                   "includeReferencesDeep": True})
                r = sess.post(f"{kb}/api/saved_objects/_export", data=body, timeout=60)
                r.raise_for_status()
                out.append((f"{_safe(oid)}.ndjson", r.text))
            elif kind == "rule":
                doc = _get(sess, f"{kb}/api/alerting/rule/{oid}")
                out.append((f"rule_{_safe(oid)}.json", json.dumps(doc)))
            elif kind == "pipeline":
                doc = _get(sess, f"{es}/_ingest/pipeline/{oid}")
                out.append((f"{_safe(oid)}.json", json.dumps(doc.get(oid, doc))))
            elif kind == "watcher":
                doc = _get(sess, f"{es}/_watcher/watch/{oid}")
                out.append((f"watch_{_safe(oid)}.json", json.dumps(doc.get("watch", doc))))
        except Exception as e:
            out.append((f"ERROR_{_safe(str(oid))}.txt", f"pull failed: {e}"))
    return out


def _safe(name: str) -> str:
    import re
    return re.sub(r"[^A-Za-z0-9._-]", "_", str(name)) or "item"
