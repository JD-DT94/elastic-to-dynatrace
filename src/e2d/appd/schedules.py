"""AppDynamics schedules -> Dynatrace maintenance windows.

AppD health rules reference a named schedule to decide when they evaluate, and
policies reference one to suppress actions. Dynatrace detectors run
continuously, so the suppression intent has to move somewhere — a maintenance
window (`builtin:alerting.maintenance-window`).

This produces a deployable Settings object rather than advice, because the
mapping is real: a recurring window with a start time, a duration and a day
selection exists on both sides. What does *not* survive is AppD's timezone
handling subtleties and any schedule built from many disjoint ranges, and both
are reported rather than approximated.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from e2d.report import Report

SCHEMA = "builtin:alerting.maintenance-window"

_DAYS = {
    "MONDAY": "MONDAY", "TUESDAY": "TUESDAY", "WEDNESDAY": "WEDNESDAY",
    "THURSDAY": "THURSDAY", "FRIDAY": "FRIDAY", "SATURDAY": "SATURDAY",
    "SUNDAY": "SUNDAY",
    "MON": "MONDAY", "TUE": "TUESDAY", "WED": "WEDNESDAY", "THU": "THURSDAY",
    "FRI": "FRIDAY", "SAT": "SATURDAY", "SUN": "SUNDAY",
}


def _get(d: Any, *names, default=None):
    if not isinstance(d, dict):
        return default
    for n in names:
        if n in d:
            return d[n]
        for k in d:
            if k.lower() == n.lower():
                return d[k]
    return default


def _records(doc: Any) -> List[dict]:
    if isinstance(doc, list):
        return [r for r in doc if isinstance(r, dict)]
    if isinstance(doc, dict):
        for key in ("schedules", "items"):
            v = _get(doc, key)
            if isinstance(v, list):
                return [r for r in v if isinstance(r, dict)]
        return [doc]
    return []


def looks_like_schedules(doc: Any) -> bool:
    """AppD schedule export. Narrow on purpose — `name` plus a schedule-shaped
    body, so it cannot swallow a health rule or a policy."""
    records = _records(doc)
    if not records:
        return False
    for rec in records[:50]:
        if _get(rec, "name") is None:
            return False
        if _get(rec, "timezone", "timeZone") is not None and (
                _get(rec, "scheduleType") is not None
                or _get(rec, "recurrenceType") is not None
                or _get(rec, "occurrence") is not None
                or _get(rec, "startCron") is not None):
            return True
    return False


def _time(value, default="00:00") -> str:
    """Normalise whatever the export used into HH:MM."""
    if value is None:
        return default
    if isinstance(value, dict):
        hour = _get(value, "hour", "hourOfDay", default=0) or 0
        minute = _get(value, "minute", default=0) or 0
        try:
            return f"{int(hour):02d}:{int(minute):02d}"
        except (TypeError, ValueError):
            return default
    text = str(value).strip()
    m = re.match(r"^(\d{1,2}):(\d{2})", text)
    if m:
        return f"{int(m.group(1)):02d}:{m.group(2)}"
    if text.isdigit():
        return f"{int(text):02d}:00"
    return default


def _minutes_between(start: str, end: str) -> int:
    try:
        sh, sm = (int(x) for x in start.split(":"))
        eh, em = (int(x) for x in end.split(":"))
    except (ValueError, AttributeError):
        return 60
    delta = (eh * 60 + em) - (sh * 60 + sm)
    if delta <= 0:              # window crosses midnight
        delta += 24 * 60
    return delta


def _days(rec: dict) -> List[str]:
    raw = _get(rec, "days", "daysOfWeek", "weekDays", default=None)
    out: List[str] = []
    if isinstance(raw, list):
        for d in raw:
            key = str(d).strip().upper()
            if key in _DAYS and _DAYS[key] not in out:
                out.append(_DAYS[key])
    elif isinstance(raw, str):
        for part in re.split(r"[,\s]+", raw):
            key = part.strip().upper()
            if key in _DAYS and _DAYS[key] not in out:
                out.append(_DAYS[key])
    return out


@dataclass
class ScheduleResult:
    windows: List[dict] = field(default_factory=list)   # Settings API bodies
    names: List[str] = field(default_factory=list)
    report: Report = field(default_factory=Report)


def translate_schedules(text_or_doc) -> ScheduleResult:
    doc = json.loads(text_or_doc) if isinstance(text_or_doc, (str, bytes)) else text_or_doc
    res = ScheduleResult()

    for rec in _records(doc):
        name = str(_get(rec, "name", "displayName", default="schedule") or "schedule")
        res.names.append(name)
        timezone = _get(rec, "timezone", "timeZone", default="") or ""

        start = _time(_get(rec, "startTime", "start", "beginTime"))
        end = _time(_get(rec, "endTime", "end", "finishTime"), default="")
        duration = _get(rec, "durationInMinutes", "duration", default=None)
        if duration is None:
            duration = _minutes_between(start, end) if end else 60
        try:
            duration = max(1, int(duration))
        except (TypeError, ValueError):
            duration = 60

        days = _days(rec)
        occurrences = _get(rec, "occurrence", "occurrences", default=None)
        if isinstance(occurrences, list) and len(occurrences) > 1:
            res.report.warn(
                f"Schedule `{name}` has {len(occurrences)} separate occurrence blocks. "
                "One maintenance window is emitted from the first; create additional "
                "windows for the rest, or a single broader one if that is simpler.")

        value: Dict[str, Any] = {
            "enabled": True,
            "generalProperties": {
                "name": name[:500],
                "description": "Migrated from an AppDynamics schedule",
                "maintenanceType": "PLANNED",
                "suppression": "DONT_DETECT_PROBLEMS",
                "disableSyntheticMonitorExecution": False,
            },
            "schedule": {
                "scheduleType": "WEEKLY" if days else "DAILY",
                "recurrenceRange": {},
                "dailyRecurrence": None,
                "weeklyRecurrence": None,
            },
            "filters": [],
        }
        recurrence = {
            "timeWindow": {"startTime": start, "durationMinutes": duration,
                           "timeZone": timezone or "UTC"},
        }
        if days:
            value["schedule"]["weeklyRecurrence"] = dict(recurrence, days=days)
        else:
            value["schedule"]["dailyRecurrence"] = recurrence

        res.windows.append({"schemaId": SCHEMA, "scope": "environment", "value": value})

        if not timezone:
            res.report.warn(
                f"Schedule `{name}` carries no timezone, so the window is emitted as UTC. "
                "Check this before deploying — an eight-hour offset turns a maintenance "
                "window into an outage nobody was told about.")
        else:
            res.report.info(
                f"Schedule `{name}` uses timezone `{timezone}`. Dynatrace expects an IANA "
                "zone name (e.g. `Europe/London`); adjust if AppD used a different form.")
        if not days and not end and duration == 60:
            res.report.warn(
                f"Schedule `{name}` had no readable start/end, so a one-hour daily window "
                "is emitted as a placeholder. Set the real window before deploying.")

    if not res.windows:
        res.report.manual("No schedules recognised in this export.")
    else:
        res.report.info(
            "Maintenance windows suppress problem *detection* by default "
            "(`DONT_DETECT_PROBLEMS`). If you only want to stop notifications while still "
            "recording problems, switch the suppression mode before deploying.")
    return res


def render_schedules(res: ScheduleResult, source: str = "") -> str:
    L: List[str] = ["# Maintenance windows (from AppDynamics schedules)", ""]
    if source:
        L += [f"Source: `{source}`", ""]
    L += ["AppD schedules decide when a health rule evaluates or an action is suppressed. "
          "Dynatrace detectors run continuously, so that intent moves to a maintenance "
          "window.", ""]

    if res.windows:
        L += [f"## Windows ({len(res.windows)})", "",
              "| Name | Starts | Duration | Days | Timezone |", "|---|---|---|---|---|"]
        for body in res.windows:
            v = body["value"]
            sched = v["schedule"]
            block = sched.get("weeklyRecurrence") or sched.get("dailyRecurrence") or {}
            tw = block.get("timeWindow", {})
            days = ", ".join(d[:3].title() for d in block.get("days", [])) or "every day"
            L.append(f"| {v['generalProperties']['name']} | {tw.get('startTime', '—')} | "
                     f"{tw.get('durationMinutes', '—')} min | {days} | "
                     f"{tw.get('timeZone', '—')} |")
        L += ["",
              "Deploy by POSTing the accompanying `.windows.json` to "
              "`{env}/api/v2/settings/objects` with the `settings.write` scope.", ""]

    notes = res.report.format_deduped()
    if notes:
        L += ["## Notes", ""] + [f"- {n}" for n in notes] + [""]
    return "\n".join(L)
