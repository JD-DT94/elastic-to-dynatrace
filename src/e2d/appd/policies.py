"""AppDynamics policies and actions -> Dynatrace notification plan.

AppD separates *what fires* (a policy binding events to entities) from *what
happens* (an action: email, HTTP request, script, diagnostic capture). Dynatrace
splits the same job between problem notifications and Workflows.

Most of it translates. The interesting part is what does not: AppD's
diagnostic-capture actions — start a diagnostic session, take a thread dump,
snapshot on demand — exist because AppD captures deeply only when asked.
Dynatrace captures continuously, so those actions have no counterpart and need
no replacement. Reporting that as "nothing to build" rather than as a gap is the
difference between a migration plan that looks daunting and one that is honest.

Credentials referenced by HTTP actions are named, never copied into output.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from e2d.alerts.model import Action
from e2d.report import Report

# AppD action type -> (Dynatrace landing spot, how to build it)
_ACTION_MAP: Dict[str, tuple] = {
    "EMAIL": ("Workflow: send-email action, or a problem notification",
              "Recreate the recipient list on a Dynatrace problem notification (simplest) or a "
              "Workflow `send-email` task when the alert needs routing logic."),
    "SMS": ("Third-party notification integration",
            "Dynatrace has no built-in SMS channel; route via an existing integration "
            "(PagerDuty, ServiceNow, Opsgenie) or a Workflow HTTP task to your SMS gateway."),
    "HTTP_REQUEST": ("Workflow: http-function task",
                     "Recreate as a Workflow HTTP task. Store any auth as a Dynatrace "
                     "credential and reference it — never inline the secret."),
    "CUSTOM_ACTION": ("Workflow: run-javascript task",
                      "AppD custom actions run a script on the Controller host. The Dynatrace "
                      "equivalent is a Workflow JavaScript task; review what the script did "
                      "before assuming it is still needed."),
    "RUN_SCRIPT": ("Workflow: run-javascript task",
                   "Review the original script — much of what AppD scripts did (fetching extra "
                   "diagnostics) is captured continuously by Dynatrace and may be redundant."),
}

# Actions that exist only because AppD captures on demand.
_ALWAYS_ON: Dict[str, str] = {
    "DIAGNOSTIC_SESSION": "start a diagnostic session",
    "START_DIAGNOSTIC_SESSION": "start a diagnostic session",
    "THREAD_DUMP": "take a thread dump",
    "TAKE_THREAD_DUMP": "take a thread dump",
    "CREATE_SNAPSHOT": "force a transaction snapshot",
    "REQUEST_SNAPSHOT": "force a transaction snapshot",
}


@dataclass
class PolicyResult:
    actions: List[Action] = field(default_factory=list)
    policies: List[dict] = field(default_factory=list)
    always_on: List[str] = field(default_factory=list)   # actions Dynatrace makes unnecessary
    report: Report = field(default_factory=Report)


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
        for key in ("actions", "policies", "items"):
            v = _get(doc, key)
            if isinstance(v, list):
                return [r for r in v if isinstance(r, dict)]
        return [doc]
    return []


def looks_like_policy_export(doc: Any) -> bool:
    records = _records(doc)
    if not records:
        return False
    for r in records[:50]:
        if _get(r, "actionType") is not None:
            return True
        if _get(r, "events") is not None and _get(r, "actions") is not None:
            return True
    return False


def _recipients(rec: dict) -> str:
    for key in ("toAddress", "to", "recipients", "toAddresses"):
        v = _get(rec, key)
        if isinstance(v, list) and v:
            return ", ".join(str(x) for x in v[:6]) + ("…" if len(v) > 6 else "")
        if isinstance(v, str) and v:
            return v
    return ""


def translate_policies(text_or_doc) -> PolicyResult:
    """Parse an AppD actions and/or policies export."""
    result = PolicyResult()
    report = result.report
    doc = json.loads(text_or_doc) if isinstance(text_or_doc, (str, bytes)) else text_or_doc

    for rec in _records(doc):
        action_type = str(_get(rec, "actionType", default="") or "").upper()
        name = str(_get(rec, "name", "actionName", default="") or "action")

        if not action_type and _get(rec, "events") is not None:
            # a policy: record the binding, actions are resolved from the action export
            bound = _get(rec, "actions", default=[]) or []
            bound_names = [str(_get(a, "actionName", "name", default="?")) for a in bound
                           if isinstance(a, dict)]
            result.policies.append({
                "name": name,
                "enabled": bool(_get(rec, "enabled", default=True)),
                "actions": bound_names,
            })
            continue

        if action_type in _ALWAYS_ON:
            result.always_on.append(f"`{name}` ({_ALWAYS_ON[action_type]})")
            continue

        if action_type in _ACTION_MAP:
            target, how = _ACTION_MAP[action_type]
            kind = {"EMAIL": "email", "HTTP_REQUEST": "webhook"}.get(action_type, "unknown")
            recipients = _recipients(rec)
            secret = None
            for key in ("credentialName", "credentials", "authType", "password", "token"):
                if _get(rec, key):
                    secret = key
                    break
            result.actions.append(Action(kind=kind, target=recipients or name, secret=secret))
            report.info(f"Action `{name}` ({action_type}) -> {target}. {how}")
            if secret:
                report.warn(
                    f"Action `{name}` references a credential (`{secret}`). It is NOT copied "
                    "into any output — create the equivalent Dynatrace credential and "
                    "reference it from the Workflow.")
        elif action_type:
            report.manual(
                f"Action `{name}` has AppD type `{action_type}`, which has no documented "
                "Dynatrace equivalent. Decide whether it is still needed before rebuilding.")

    if result.always_on:
        report.info(
            f"{len(result.always_on)} action(s) exist only to make AppD capture diagnostics on "
            f"demand ({', '.join(result.always_on[:4])}"
            + ("…" if len(result.always_on) > 4 else "")
            + "). Dynatrace captures method-level detail and snapshots continuously, so these "
              "need no equivalent — drop them rather than rebuilding them.")

    if not (result.actions or result.policies or result.always_on):
        report.manual("No actions or policies recognised in this export.")
    return result


def render_policy_plan(result: PolicyResult, source: str = "") -> str:
    L: List[str] = ["# Alert routing (AppD policies and actions)", ""]
    if source:
        L += [f"Source: `{source}`", ""]

    L += ["In Dynatrace, a Davis problem is raised by a detector and routed by a **problem "
          "notification** (simple channels) or a **Workflow** (anything conditional). "
          "The AppD policy-to-action binding maps onto that split.", ""]

    if result.policies:
        L += ["## Policies", "", "| Policy | Enabled | Actions |", "|---|---|---|"]
        for p in result.policies:
            acts = ", ".join(f"`{a}`" for a in p["actions"]) or "—"
            L.append(f"| {p['name']} | {'yes' if p['enabled'] else 'no'} | {acts} |")
        L.append("")

    if result.actions:
        L += ["## Actions to rebuild", "", "| Action | Type | Target | Credential |",
              "|---|---|---|---|"]
        for a in result.actions:
            L.append(f"| {a.target or '—'} | {a.kind} | {a.target or '—'} | "
                     f"{'`' + a.secret + '` (recreate in Dynatrace)' if a.secret else '—'} |")
        L.append("")

    if result.always_on:
        L += ["## Actions you do not need to rebuild", "",
              "These exist because AppD captures deep diagnostics only when triggered. "
              "Dynatrace captures continuously, so there is nothing to recreate:", ""]
        L += [f"- {a}" for a in result.always_on]
        L.append("")

    notes = result.report.format_deduped()
    if notes:
        L += ["## Notes", ""] + [f"- {n}" for n in notes] + [""]
    return "\n".join(L)
