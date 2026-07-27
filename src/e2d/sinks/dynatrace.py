"""Push dashboards to Dynatrace via the Document Service API.

POST {env}/platform/document/v1/documents  (multipart/form-data)
  form : name, type=dashboard
  file : content  (the dashboard content JSON)
Auth : Bearer platform token, scope `document:documents:write`.

Defaults to a **dry run** (outward-facing, not bulk-reversible); pass apply=True
to actually create documents.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

DOC_PATH = "/platform/document/v1/documents"
SETTINGS_PATH = "/platform/classic/environment-api/v2/settings/objects"
ANOMALY_SCHEMA = "builtin:davis.anomaly-detectors"
_STATIC_ANALYZER = "dt.statistics.ui.anomaly_detection.StaticThresholdAnomalyDetectionAnalyzer"


@dataclass
class DeployResult:
    name: str
    ok: bool
    detail: str = ""          # document id on success, error on failure
    dry_run: bool = False


def _content_payload(doc: Dict[str, Any],
                     fallback_name: str = "Imported dashboard") -> Tuple[str, Dict[str, Any]]:
    """(name, content) from either a full dashboard wrapper or a bare content doc.

    Converted files hold only the content document (so the Dashboards app can
    import them directly); their display name travels in the filename.
    """
    if isinstance(doc, dict) and "content" in doc and "name" in doc:
        return doc["name"], doc["content"]
    name = doc.get("name") if isinstance(doc, dict) else None
    return (name or fallback_name), doc


def push_dashboard(env_url: str, token: Optional[str], name: str, content: Dict[str, Any],
                   apply: bool = False, timeout: int = 60) -> DeployResult:
    """Create one dashboard document. Best-effort: never raises."""
    if not apply:
        tiles = len(content.get("tiles", {})) if isinstance(content, dict) else "?"
        return DeployResult(name, True, f"dry run — would create ({tiles} tiles)", dry_run=True)
    if not env_url or not token:
        return DeployResult(name, False, "missing env URL or token")
    try:
        import requests
    except ImportError:
        return DeployResult(name, False, "requests not installed (pip install ...[push])")
    try:
        resp = requests.post(
            env_url.rstrip("/") + DOC_PATH,
            headers={"Authorization": f"Bearer {token}"},
            data={"name": name, "type": "dashboard"},
            files={"content": (name + ".json", json.dumps(content).encode("utf-8"), "application/json")},
            timeout=timeout,
        )
    except Exception as e:
        return DeployResult(name, False, f"request failed: {e}")
    if resp.status_code in (200, 201):
        doc_id = ""
        try:
            doc_id = resp.json().get("documentMetadata", {}).get("id", "")
        except Exception:
            pass
        return DeployResult(name, True, f"created id={doc_id}")
    return DeployResult(name, False, f"HTTP {resp.status_code}: {resp.text[:200]}")


def deploy_dashboards(env_url: str, token: Optional[str],
                      dashboards: List[Tuple[str, Dict[str, Any]]], apply: bool = False) -> List[DeployResult]:
    """Push a batch of (filename, dashboard-doc) pairs."""
    results: List[DeployResult] = []
    for fname, doc in dashboards:
        stem = fname.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
        stem = stem[:-5] if stem.lower().endswith(".json") else stem
        name, content = _content_payload(doc, fallback_name=stem or "Imported dashboard")
        results.append(push_dashboard(env_url, token, name, content, apply=apply))
    return results


# --------------------------------------------------------------------------- #
# Davis anomaly detectors via the Settings Objects API
# (schema builtin:davis.anomaly-detectors — analyzer.input and eventTemplate.
#  properties are ARRAYS of {key,value} string pairs, provider-source-confirmed)
# --------------------------------------------------------------------------- #

def _is_numeric(value: str) -> bool:
    try:
        float(str(value).strip().strip('"'))
        return True
    except ValueError:
        return False


def detector_settings_value(alert_name: str, det) -> Dict[str, Any]:
    """Build the `builtin:davis.anomaly-detectors` settings value from a Detector.

    A non-numeric (dynamic) threshold ships disabled with a 0 placeholder so the
    create still succeeds."""
    raw = str(det.threshold).strip().strip('"')
    numeric = _is_numeric(raw)
    title = f"{alert_name}: {det.title}"
    sev = "warning" if getattr(det, "severity", "critical") == "warning" else "error"
    desc = "Migrated from Elastic by e2d" + ("" if numeric else " — DISABLED: set a real threshold")
    return {
        "enabled": bool(numeric),
        "title": title[:500],
        "description": desc,
        "source": "e2d",
        "analyzer": {
            "name": _STATIC_ANALYZER,
            "input": [
                {"key": "query", "value": det.query},
                {"key": "alertCondition", "value": det.alert_condition},
                {"key": "threshold", "value": raw if numeric else "0"},
                {"key": "violatingSamples", "value": "3"},
                {"key": "slidingWindow", "value": "5"},
                {"key": "dealertingSamples", "value": "5"},
                {"key": "alertOnMissingData", "value": "false"},
            ],
        },
        "eventTemplate": {
            "properties": [
                {"key": "event.name", "value": title[:500]},
                {"key": "event.type", "value": "CUSTOM_ALERT"},
                {"key": "dt.davis.event.severity_level", "value": sev},
            ],
        },
        "executionSettings": {},
    }


def push_settings_object(env_url: str, token: Optional[str], schema_id: str, value: Dict[str, Any],
                         label: str, apply: bool = False, timeout: int = 60) -> DeployResult:
    if not apply:
        return DeployResult(label, True, "dry run — would create", dry_run=True)
    if not env_url or not token:
        return DeployResult(label, False, "missing env URL or token")
    try:
        import requests
    except ImportError:
        return DeployResult(label, False, "requests not installed (pip install ...[push])")
    body = [{"schemaId": schema_id, "scope": "environment", "value": value}]
    try:
        resp = requests.post(env_url.rstrip("/") + SETTINGS_PATH,
                             headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
                             json=body, timeout=timeout)
    except Exception as e:
        return DeployResult(label, False, f"request failed: {e}")
    try:
        arr = resp.json()
        first = arr[0] if isinstance(arr, list) and arr else {}
    except ValueError:
        first = {}
    if resp.status_code in (200, 207) and str(first.get("code", "")).startswith("2"):
        return DeployResult(label, True, f"created id={first.get('objectId', '')}")
    if resp.status_code in (200, 201) and first.get("objectId"):
        return DeployResult(label, True, f"created id={first['objectId']}")
    detail = first.get("error", {}).get("message") if isinstance(first.get("error"), dict) else None
    return DeployResult(label, False, detail or f"HTTP {resp.status_code}: {resp.text[:200]}")


def deploy_detectors(env_url: str, token: Optional[str], specs, apply: bool = False) -> List[DeployResult]:
    """Push every detector of every AlertSpec as a Davis anomaly-detector settings object."""
    results: List[DeployResult] = []
    for spec in specs:
        for det in getattr(spec, "detectors", []):
            value = detector_settings_value(spec.name, det)
            results.append(push_settings_object(env_url, token, ANOMALY_SCHEMA, value,
                                                 label=value["title"], apply=apply))
    return results
