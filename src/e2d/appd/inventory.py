"""AppDynamics application/tier/node inventory -> a OneAgent onboarding plan.

This is the piece that answers "how do we get N applications onboarded", and it
starts by correcting the unit of work.

AppD needs an agent per JVM/CLR **process**, each carrying its own
application/tier/node identity, which is why an AppD estate is counted in
applications and nodes. Dynatrace OneAgent installs once per **host** and
deep-monitors every process on it automatically. So the rollout is sized by
distinct machines, not by applications — and one host carrying twelve AppD nodes
across three applications is a single install, not twelve.

The plan therefore: dedupes nodes down to hosts, batches those hosts into waves,
carries the AppD Application/Tier identity across as host-group and tag naming
(so the topology survives without recreating it), and flags the two constraints
that bite at scale — the management-zone rule ceiling, and the fact that AppD
history cannot be backfilled so parity needs a dual-run window.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

from e2d.report import Report

# Dynatrace caps entity-selector/rule counts per management zone configuration.
# One management zone per AppD application stops scaling around here, which is
# why the plan recommends tag-driven zones instead.
MZ_RULE_CEILING = 300
# Hosts per rollout wave. Big enough to be worth a change window, small enough
# that a bad wave is recoverable.
DEFAULT_WAVE_SIZE = 50


@dataclass
class Node:
    name: str
    tier: str = ""
    application: str = ""
    machine: str = ""
    agent_type: str = ""
    node_type: str = ""


@dataclass
class Inventory:
    applications: List[str] = field(default_factory=list)
    tiers: Dict[str, Set[str]] = field(default_factory=dict)      # app -> tiers
    nodes: List[Node] = field(default_factory=list)
    hosts: Dict[str, Set[str]] = field(default_factory=dict)      # machine -> apps on it

    @property
    def host_count(self) -> int:
        return len(self.hosts)

    @property
    def node_count(self) -> int:
        return len(self.nodes)

    @property
    def tier_count(self) -> int:
        return sum(len(t) for t in self.tiers.values())


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


def _as_records(doc: Any) -> List[dict]:
    if isinstance(doc, list):
        return [r for r in doc if isinstance(r, dict)]
    if isinstance(doc, dict):
        for key in ("nodes", "tiers", "applications", "items", "data"):
            v = _get(doc, key)
            if isinstance(v, list):
                return [r for r in v if isinstance(r, dict)]
        return [doc]
    return []


def looks_like_inventory(doc: Any) -> bool:
    """True when this JSON is an AppD application/tier/node listing.

    Kept strict: an entity list has `name` on every record plus at least one
    AppD-specific companion key, so it cannot collide with a Kibana export or a
    health rule.
    """
    records = _as_records(doc)
    if not records or len(records) > 100000:
        return False
    appd_keys = {"tiername", "machinename", "appagentversion", "machineagentpresent",
                 "numberofnodes", "agenttype", "tierid", "applicationname",
                 "appagentpresent", "nodeuniquelocalid"}
    named = 0
    hit = False
    for r in records[:200]:
        if _get(r, "name") is None:
            return False
        named += 1
        if any(k.lower() in appd_keys for k in r):
            hit = True
    return bool(named) and hit


def translate_inventory(text_or_doc, default_application: str = "") -> "InventoryResult":
    """Parse an AppD inventory export (applications, tiers, or nodes)."""
    report = Report()
    doc = json.loads(text_or_doc) if isinstance(text_or_doc, (str, bytes)) else text_or_doc
    records = _as_records(doc)
    inv = Inventory()

    node_records, tier_records, app_records = [], [], []
    for r in records:
        if _get(r, "machineName", "machineId", "appAgentVersion", "nodeUniqueLocalId") is not None:
            node_records.append(r)
        elif _get(r, "numberOfNodes", "agentType", "tierId") is not None:
            tier_records.append(r)
        else:
            app_records.append(r)

    for r in app_records:
        name = str(_get(r, "name", default="") or "").strip()
        if name:
            inv.applications.append(name)

    for r in tier_records:
        app = str(_get(r, "applicationName", default=default_application) or default_application).strip()
        name = str(_get(r, "name", default="") or "").strip()
        if name:
            inv.tiers.setdefault(app or "(unknown application)", set()).add(name)

    for r in node_records:
        app = str(_get(r, "applicationName", default=default_application) or default_application).strip()
        tier = str(_get(r, "tierName", default="") or "").strip()
        machine = str(_get(r, "machineName", "machineOSType", default="") or "").strip()
        node = Node(
            name=str(_get(r, "name", default="") or "").strip(),
            tier=tier,
            application=app or "(unknown application)",
            machine=machine,
            agent_type=str(_get(r, "agentType", default="") or ""),
            node_type=str(_get(r, "type", "nodeType", default="") or ""),
        )
        inv.nodes.append(node)
        if tier:
            inv.tiers.setdefault(node.application, set()).add(tier)
        if machine:
            inv.hosts.setdefault(machine, set()).add(node.application)

    if node_records and not any(n.machine for n in inv.nodes):
        report.warn(
            "No `machineName` on any node record, so hosts cannot be deduplicated and the "
            "rollout is sized by node instead. Re-export nodes from "
            "`/controller/rest/applications/{app}/nodes?output=JSON`, which includes the "
            "machine name — one host may carry many nodes, and OneAgent installs per host.")

    if not (app_records or tier_records or node_records):
        report.manual("No application, tier or node records recognised in this export.")

    return InventoryResult(inventory=inv, report=report)


@dataclass
class InventoryResult:
    inventory: Inventory
    report: Report


def _host_group(application: str, tier: str = "") -> str:
    """A Dynatrace host-group name carrying the AppD identity.

    Host groups accept letters, digits, hyphen, underscore and dot; anything
    else is folded to `_` so the value is usable verbatim in the installer's
    `--set-host-group=` argument.
    """
    parts = [p for p in (application, tier) if p]
    raw = "_".join(parts) or "UNASSIGNED"
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "_", raw)
    cleaned = re.sub(r"_+", "_", cleaned).strip("_")
    return cleaned[:80].upper() or "UNASSIGNED"


def build_waves(inv: Inventory, wave_size: int = DEFAULT_WAVE_SIZE) -> List[dict]:
    """Batch hosts into rollout waves, smallest applications first.

    Smallest-first is deliberate: the first waves are the cheapest place to
    discover that a host group name, a firewall rule or a change process is
    wrong, and they build evidence before the large applications are touched.
    """
    by_app: Dict[str, Set[str]] = {}
    for machine, apps in inv.hosts.items():
        for app in apps:
            by_app.setdefault(app, set()).add(machine)

    if not by_app and inv.nodes:
        # No machine names: fall back to nodes so the plan still sizes the work.
        for node in inv.nodes:
            by_app.setdefault(node.application, set()).add(node.name)

    ordered = sorted(by_app.items(), key=lambda kv: (len(kv[1]), kv[0]))
    waves: List[dict] = []
    current: List[dict] = []
    current_hosts = 0

    def flush():
        nonlocal current, current_hosts
        if current:
            waves.append({"wave": len(waves) + 1,
                          "applications": current,
                          "hosts": current_hosts})
            current, current_hosts = [], 0

    for app, machines in ordered:
        entry = {"application": app, "host_count": len(machines),
                 "hosts": sorted(machines)[:200],
                 "host_group": _host_group(app)}
        if current_hosts and current_hosts + len(machines) > wave_size:
            flush()
        current.append(entry)
        current_hosts += len(machines)
        if current_hosts >= wave_size:
            flush()
    flush()
    return waves


def render_onboarding_plan(inv: Inventory, waves: List[dict],
                           wave_size: int = DEFAULT_WAVE_SIZE) -> str:
    """The human-facing rollout plan."""
    app_count = len(set(inv.applications) | set(inv.tiers) |
                    {n.application for n in inv.nodes if n.application})
    L: List[str] = [
        "# OneAgent onboarding plan",
        "",
        "Generated from the AppDynamics application/tier/node inventory.",
        "",
        "## What you are actually rolling out",
        "",
    ]

    if inv.host_count:
        ratio = inv.node_count / inv.host_count if inv.host_count else 0
        L += [
            f"- **{app_count} AppD application(s)**, {inv.tier_count} tier(s), "
            f"{inv.node_count} node(s)",
            f"- **{inv.host_count} distinct host(s)** — this is the number that matters",
            "",
            f"AppD runs an agent per JVM/CLR process, so this estate counts "
            f"{inv.node_count} nodes. OneAgent installs once per host and deep-monitors every "
            f"process on it automatically, so the rollout is {inv.host_count} installs, not "
            f"{inv.node_count}"
            + (f" — an average of {ratio:.1f} AppD nodes per host." if ratio > 1 else "."),
            "",
        ]
        shared = {m: apps for m, apps in inv.hosts.items() if len(apps) > 1}
        if shared:
            L += [
                f"{len(shared)} host(s) carry more than one AppD application. Those are "
                "onboarded once and appear under every relevant application via tagging — "
                "schedule them with the *earliest* wave that touches them, not once per "
                "application.",
                "",
            ]
    else:
        L += [f"- **{app_count} AppD application(s)**, {inv.tier_count} tier(s), "
              f"{inv.node_count} node(s)",
              "- Host count unknown (no machine names in the export)", ""]

    L += [
        "## Carrying the AppD topology across",
        "",
        "Do not recreate AppD's Application/Tier/Node tree. Dynatrace derives topology from "
        "observed traffic; what you carry across is the *naming*, so the estate stays "
        "navigable:",
        "",
        "- **Host group** at install time — `--set-host-group=<APP>_<TIER>`. This is the "
        "durable carrier of AppD identity and also drives update policy and anomaly-detection "
        "overrides.",
        "- **Automatic tags** derived from the host group, so `Application` and `Tier` become "
        "filterable dimensions.",
        "- **Management zones driven by those tags**, not one zone per application. A rule-per-"
        f"application design runs into the ~{MZ_RULE_CEILING}-rule ceiling per environment"
        + (f", and this estate has {app_count} applications." if app_count > MZ_RULE_CEILING
           else "; tag-driven rules stay well clear of it."),
        "",
        "## Rollout waves",
        "",
        f"Hosts are batched into waves of about {wave_size}, smallest applications first — the "
        "cheapest place to find out a host group name or change process is wrong.",
        "",
    ]

    if waves:
        L += ["| Wave | Applications | Hosts | Host groups |", "|---|---|---|---|"]
        for w in waves:
            apps = ", ".join(a["application"] for a in w["applications"][:6])
            if len(w["applications"]) > 6:
                apps += f" (+{len(w['applications']) - 6} more)"
            groups = ", ".join(f"`{a['host_group']}`" for a in w["applications"][:3])
            if len(w["applications"]) > 3:
                groups += " …"
            L.append(f"| {w['wave']} | {apps} | {w['hosts']} | {groups} |")
        L.append("")
    else:
        L += ["_No hosts resolved from the inventory — export nodes with machine names to "
              "generate waves._", ""]

    L += [
        "## How each wave runs",
        "",
        "1. Install OneAgent on the wave's hosts with the Ansible collection "
        "(`dynatrace.oneagent`), passing that host's group. Ansible is the only "
        "config-management path Dynatrace still maintains — the Puppet and Chef modules are "
        "archived.",
        "2. Restart the application processes on those hosts. Newly detected process groups "
        "need one restart before deep monitoring engages; this is usually the only "
        "app-team-visible step and is what wave scheduling is really negotiating.",
        "3. Confirm services appear and carry the expected tags before starting the next wave.",
        "",
        "Containerised workloads do not need any of this: the Dynatrace Operator's "
        "cloud-native mode injects automatically at pod admission, so those applications are "
        "onboarded by deploying the operator once per cluster and need no per-application work.",
        "",
        "## Two constraints worth planning around now",
        "",
        "**AppD history does not come with you.** Dynatrace rejects metric data timestamped "
        "more than one hour in the past, so there is no backfill. Any before/after comparison "
        "means running both stacks over the same window — budget a dual-run period per wave, "
        "and expect double agent footprint and licensing during it.",
        "",
        "**Parallelism comes from waves, not from the converter.** Independent waves can run "
        "concurrently across app teams as soon as host groups and the Ansible inventory are "
        "agreed; nothing in the config conversion blocks them.",
        "",
    ]
    return "\n".join(L)


def render_host_group_map(inv: Inventory) -> str:
    """A machine-readable host -> host-group mapping for the Ansible inventory."""
    rows: Dict[str, Dict[str, Any]] = {}
    for node in inv.nodes:
        if not node.machine:
            continue
        entry = rows.setdefault(node.machine, {"host": node.machine, "applications": set(),
                                               "tiers": set(), "nodes": 0})
        entry["applications"].add(node.application)
        if node.tier:
            entry["tiers"].add(node.tier)
        entry["nodes"] += 1
    out = []
    for host, entry in sorted(rows.items()):
        apps = sorted(entry["applications"])
        tiers = sorted(entry["tiers"])
        out.append({
            "host": host,
            "host_group": _host_group(apps[0] if apps else "", tiers[0] if len(tiers) == 1 else ""),
            "appd_applications": apps,
            "appd_tiers": tiers,
            "appd_node_count": entry["nodes"],
        })
    return json.dumps(out, indent=2) + "\n"
