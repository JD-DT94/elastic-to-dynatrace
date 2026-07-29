"""Beats configs -> the Dynatrace collection edge.

Real migrations start at the shippers, not the dashboards: nothing in
Dynatrace lights up until data flows. This module converts the collection
edge configs:

* ``filebeat.yml``   -> an OpenTelemetry Collector config: one ``filelog``
  receiver per input (paths, excludes, multiline), OTLP export to Dynatrace.
* ``heartbeat.yml``  -> Dynatrace Synthetic HTTP monitor definitions plus a
  guide (TCP/ICMP monitors are flagged for the UI's network availability
  monitors; browser journeys don't exist in Heartbeat).
* ``metricbeat.yml`` -> a written guide: OneAgent covers host/process
  metrics out of the box; remaining modules map to Extensions Hub entries.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from e2d.report import Report


def detect_beat(doc: Any) -> Optional[str]:
    if not isinstance(doc, dict):
        return None
    def has(beat: str, section: str) -> bool:
        if f"{beat}.{section}" in doc:
            return True
        sub = doc.get(beat)
        return isinstance(sub, dict) and section in sub
    if has("filebeat", "inputs") or "filebeat.prospectors" in doc:
        return "filebeat"
    if has("heartbeat", "monitors"):
        return "heartbeat"
    if has("metricbeat", "modules"):
        return "metricbeat"
    return None


def _section(doc: Dict[str, Any], beat: str, section: str) -> List[Dict[str, Any]]:
    items = doc.get(f"{beat}.{section}")
    if items is None and isinstance(doc.get(beat), dict):
        items = doc[beat].get(section)
    return [i for i in (items or []) if isinstance(i, dict)]


# --------------------------------------------------------------------------- #
# filebeat -> OpenTelemetry Collector
# --------------------------------------------------------------------------- #

@dataclass
class ShipperResult:
    otel_yaml: str = ""
    report: Report = field(default_factory=Report)


def _receiver_name(inp: Dict[str, Any], i: int) -> str:
    raw = str(inp.get("id") or inp.get("type") or f"input{i}")
    return re.sub(r"[^a-z0-9_]", "_", raw.lower()).strip("_") or f"input{i}"


def _yaml_str(s: str) -> str:
    return json.dumps(str(s))  # JSON string escaping is valid YAML


def translate_filebeat(doc: Dict[str, Any], name: str = "filebeat") -> ShipperResult:
    res = ShipperResult()
    inputs = _section(doc, "filebeat", "inputs")
    if not inputs:
        res.report.manual("No filebeat.inputs found; nothing to convert.")
        return res

    L: List[str] = [f"# OpenTelemetry Collector config generated from {name}",
                    "# Fill in <env-id> and export DT_API_TOKEN (scope: logs.ingest).",
                    "receivers:"]
    names: List[str] = []
    for i, inp in enumerate(inputs, 1):
        itype = str(inp.get("type", "log"))
        rname = _receiver_name(inp, i)
        if itype not in ("filestream", "log", "container", "filelog"):
            res.report.manual(f"Input `{rname}` has type `{itype}`, which has no "
                              "filelog equivalent; wire it to the matching OTel "
                              "receiver (syslog/tcp/kafka) by hand.")
            continue
        if inp.get("enabled") is False:
            res.report.info(f"Input `{rname}` is disabled in filebeat; it was "
                            "converted anyway but left out of the pipeline notes.")
        names.append(rname)
        L.append(f"  filelog/{rname}:")
        L.append("    include:")
        for p in inp.get("paths") or []:
            L.append(f"      - {_yaml_str(p)}")
        excludes = inp.get("exclude_files") or []
        if excludes:
            L.append("    exclude:")
            for p in excludes:
                L.append(f"      - {_yaml_str(p)}")
        pattern = inp.get("multiline.pattern") or _nested(inp, "multiline", "pattern")
        if pattern:
            negate = bool(inp.get("multiline.negate", _nested(inp, "multiline", "negate")))
            L.append("    multiline:")
            L.append(f"      line_start_pattern: {_yaml_str(pattern)}")
            if not negate:
                res.report.warn(f"Input `{rname}` uses multiline with negate: false "
                                "(continuation lines MATCH the pattern). filelog's "
                                "line_start_pattern assumes the opposite; invert "
                                "the regex before relying on it.")
        fields = inp.get("fields")
        if isinstance(fields, dict) and fields:
            L.append("    attributes:")
            for k, v in fields.items():
                L.append(f"      {k}: {_yaml_str(v)}")
        if inp.get("exclude_lines"):
            res.report.warn(f"Input `{rname}` uses exclude_lines; replicate it as "
                            "a drop processor in OpenPipeline (cheaper) or a "
                            "filter operator in the filelog receiver.")
        if any(str(k).startswith("json") for k in inp):
            res.report.info(f"Input `{rname}` parses JSON at the edge; OpenPipeline "
                            "parses JSON server-side, so no receiver operator is "
                            "usually needed.")

    if not names:
        res.report.manual("No convertible inputs; the collector config was not written.")
        return res

    if doc.get("processors"):
        res.report.info("Beat-level processors (add_host_metadata etc.) map to "
                        "OTel resourcedetection/attributes processors; host "
                        "metadata is added automatically when OneAgent runs on "
                        "the same host.")

    L += ["processors:",
          "  batch: {}",
          "exporters:",
          "  otlphttp/dynatrace:",
          "    endpoint: https://<env-id>.live.dynatrace.com/api/v2/otlp",
          "    headers:",
          "      Authorization: Api-Token ${env:DT_API_TOKEN}",
          "service:",
          "  pipelines:",
          "    logs:",
          f"      receivers: [{', '.join('filelog/' + n for n in names)}]",
          "      processors: [batch]",
          "      exporters: [otlphttp/dynatrace]"]
    res.otel_yaml = "\n".join(L) + "\n"
    return res


def _nested(d: Dict[str, Any], *path: str) -> Any:
    cur: Any = d
    for k in path:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(k)
    return cur


# --------------------------------------------------------------------------- #
# heartbeat -> Synthetic monitors
# --------------------------------------------------------------------------- #

@dataclass
class SyntheticResult:
    monitors: List[dict] = field(default_factory=list)
    report: Report = field(default_factory=Report)


_EVERY = re.compile(r"^@every\s+(\d+)(s|m|h)$")


def _frequency_min(schedule: Any, report: Report, label: str) -> int:
    m = _EVERY.match(str(schedule or "").strip())
    if not m:
        report.warn(f"Monitor `{label}`: schedule {schedule!r} is not a plain "
                    "@every interval; defaulting to 5 minutes.")
        return 5
    n, unit = int(m.group(1)), m.group(2)
    minutes = n * {"s": 1 / 60, "m": 1, "h": 60}[unit]
    return max(1, round(minutes))


def translate_heartbeat(doc: Dict[str, Any]) -> SyntheticResult:
    res = SyntheticResult()
    monitors = _section(doc, "heartbeat", "monitors")
    if not monitors:
        res.report.manual("No heartbeat.monitors found; nothing to convert.")
        return res
    for mon in monitors:
        label = str(mon.get("name") or mon.get("id") or "monitor")
        mtype = str(mon.get("type", "")).lower()
        if mtype != "http":
            res.report.manual(f"Monitor `{label}` is `{mtype or '?'}`; recreate it "
                              "as a Dynatrace network availability monitor "
                              "(TCP/ICMP) in the Synthetic app.")
            continue
        statuses = mon.get("check.response.status") \
            or _nested(mon, "check", "response", "status") or [200]
        if not isinstance(statuses, list):
            statuses = [statuses]
        method = str(mon.get("check.request.method")
                     or _nested(mon, "check", "request", "method") or "GET").upper()
        urls = mon.get("urls") or mon.get("hosts") or []
        for url in urls:
            res.monitors.append({
                "name": label if len(urls) == 1 else f"{label} ({url})",
                "type": "HTTP",
                "enabled": True,
                "frequencyMin": _frequency_min(mon.get("schedule"), res.report, label),
                "script": {"version": "1.0", "requests": [{
                    "description": label,
                    "url": str(url),
                    "method": method,
                    "validation": {"rules": [{
                        "type": "httpStatusesList",
                        "passIfMatch": True,
                        "value": ", ".join(str(s) for s in statuses),
                    }]},
                }]},
                "locations": [],
            })
    if res.monitors:
        res.report.info("Location IDs are environment-specific: list them with "
                        "GET /api/v1/synthetic/locations, add them to each "
                        "monitor's `locations`, then POST via the Synthetic "
                        "monitors API. Review each definition against the API "
                        "schema before creating it.")
    return res


def render_shipper_guide(name: str, kind: str, res: "ShipperResult | SyntheticResult",
                         modules: Optional[List[str]] = None) -> str:
    L: List[str] = [f"# {kind}: {name}", ""]
    if kind == "filebeat":
        L.append("The generated `.otel.yaml` next to this file replaces this "
                 "Filebeat instance with an OpenTelemetry Collector shipping "
                 "straight to Dynatrace.")
        L.append("")
        L.append("1. Fill in `<env-id>` and export `DT_API_TOKEN` (scope `logs.ingest`).")
        L.append("2. Run it side by side with Filebeat during the dual-ship window "
                 "(see CUTOVER-PLAN.md if present), then retire Filebeat.")
        L.append("3. Keep parsing in OpenPipeline, not at the edge; the converted "
                 "pipelines already carry the field extractions.")
    elif kind == "heartbeat":
        L.append("The `.monitors.json` next to this file holds Dynatrace Synthetic "
                 "HTTP monitor definitions derived from the Heartbeat monitors.")
        L.append("")
        L.append("1. List location IDs: `GET /api/v1/synthetic/locations`.")
        L.append("2. Add locations to each definition, then create the monitors "
                 "via the Synthetic monitors API (token scope "
                 "`ExternalSyntheticIntegration` or the Synthetic app).")
        L.append("3. TCP/ICMP monitors are listed in the migration notes; recreate "
                 "them as network availability monitors in the Synthetic app.")
    else:  # metricbeat
        L.append("Metricbeat is not converted mechanically: OneAgent collects "
                 "host, process and container metrics out of the box, which "
                 "covers the `system` module. For the modules below, check the "
                 "Dynatrace Extensions Hub for a first-party integration:")
        L.append("")
        for m in modules or []:
            L.append(f"- `{m}`")
    return "\n".join(L) + "\n"
