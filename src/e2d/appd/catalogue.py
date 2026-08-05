"""The AppDynamics -> Dynatrace configuration catalogue.

Every kind of thing an AppDynamics estate holds, what it becomes in Dynatrace,
and — the part that decides how big the project really is — whether it needs
migrating at all.

A large share of an AppD configuration exists only because AppD requires manual
setup for things Dynatrace derives automatically: service detection, dependency
mapping, baselining, snapshot capture. Those items are marked `NOT_NEEDED`, and
counting them honestly is usually the difference between a migration that looks
impossible and one that fits the window. Treating the estate as a 1:1 port is
the single most expensive mistake available.

The catalogue drives two outputs: the coverage report (what your export
contains, against everything that exists) and the phased sequencing guide.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

# How an item moves across.
AUTOMATIC = "automatic"     # this tool converts it into a deployable artifact
ASSISTED = "assisted"       # this tool writes a plan; a person executes it
REBUILD = "rebuild"         # must be rebuilt by hand, by design
NOT_NEEDED = "not-needed"   # Dynatrace does this automatically; nothing to migrate

APPROACH_LABEL = {
    AUTOMATIC: "Converted by this tool",
    ASSISTED: "Guided — plan generated, you apply it",
    REBUILD: "Rebuild by hand",
    NOT_NEEDED: "Nothing to migrate",
}

# Migration phases. Order is the running order: data first, configuration
# second, decommission last.
PHASES: List[Tuple[int, str, str]] = [
    (1, "Discovery and inventory",
     "Audit what exists and decide what to replicate, re-architect or retire. "
     "Most estates carry legacy configuration nobody has read in years; migrating "
     "it costs the same as migrating something useful."),
    (2, "Platform setup",
     "Tenant, ActiveGates for private networks, connectivity, SSO and IAM groups. "
     "Nothing else can start until this is done."),
    (3, "Instrumentation, running in parallel",
     "Deploy OneAgent alongside the AppD agents. Both run at once — do not remove "
     "anything yet. Validate that services, hosts and processes are auto-discovered."),
    (4, "Entity modelling and enrichment",
     "Management zones, auto-tagging and alerting profiles. This is where the AppD "
     "Application and Tier naming is carried across, without recreating the tree."),
    (5, "Alerting and anomaly detection",
     "Let Davis baseline first, then migrate the health rules that genuinely need a "
     "static threshold, critical ones first. Wire notifications and maintenance windows."),
    (6, "Dashboards",
     "Rebuild the priority dashboards around Dynatrace's entity model rather than "
     "copying layouts. Executive health, then service health, then infrastructure, "
     "then business KPIs."),
    (7, "Advanced configuration",
     "Business events, request attributes, SLOs, synthetic monitors, calculated "
     "service metrics and custom metric ingestion."),
    (8, "Integrations",
     "ITSM, CI/CD, CMDB and notification integrations; validate any auto-remediation "
     "workflows."),
    (9, "Validation and parallel running",
     "Run both platforms together for a defined window per wave and confirm alert "
     "parity before anyone signs off."),
    (10, "Decommission",
     "Remove AppD agents wave by wave, then the controllers, then the licensing. "
     "Last, and only once each wave is signed off."),
]

PHASE_TITLE = {n: title for n, title, _ in PHASES}


@dataclass
class Item:
    """One migratable thing."""
    appd: str
    dynatrace: str
    area: str
    approach: str
    phase: int
    note: str = ""
    # classify() kinds whose presence proves this item exists in the export.
    detected_by: Tuple[str, ...] = field(default_factory=tuple)


AREAS: List[Tuple[str, str]] = [
    ("instrumentation", "Instrumentation and agents"),
    ("scope", "Application and scope definition"),
    ("transactions", "Business transactions"),
    ("alerting", "Health rules and alerting"),
    ("dashboards", "Dashboards and reporting"),
    ("metrics", "Custom metrics"),
    ("slo", "SLAs and service levels"),
    ("integrations", "Integrations"),
    ("access", "Access control"),
]

AREA_TITLE = dict(AREAS)


CATALOGUE: List[Item] = [
    # -- 1. instrumentation ------------------------------------------------ #
    Item("App server agents (Java, .NET, Node, PHP, Python)", "OneAgent",
         "instrumentation", ASSISTED, 3,
         "Full replacement. OneAgent installs once per host and auto-discovers services, "
         "dependencies and topology with no per-application configuration. The onboarding "
         "plan sizes this by host and batches it into waves.",
         ("appd_inventory",)),
    Item("Machine agents", "OneAgent (infrastructure monitoring)",
         "instrumentation", ASSISTED, 3,
         "Host, process, disk and network metrics are collected by the same OneAgent — "
         "there is no separate infrastructure agent to deploy.",
         ("appd_inventory",)),
    Item("Browser RUM agent", "Dynatrace RUM",
         "instrumentation", ASSISTED, 3,
         "Auto-injected by OneAgent for most stacks, so the manual JavaScript tag placement "
         "AppD needs usually disappears. Verify injection rather than porting tags."),
    Item("Mobile agents", "Dynatrace Mobile RUM",
         "instrumentation", REBUILD, 3,
         "An SDK swap in the app source and a new app store release. This has the longest "
         "lead time of anything in the migration — start it early, not in phase 3."),
    Item("Cluster agent (Kubernetes)", "Dynatrace Operator",
         "instrumentation", ASSISTED, 3,
         "Helm-deployed. Cloud-native full-stack mode injects at pod admission, so "
         "containerised applications need no per-application onboarding work at all."),

    # -- 2. scope ---------------------------------------------------------- #
    Item("Applications, tiers and nodes", "Services and process groups (auto-detected)",
         "scope", NOT_NEEDED, 4,
         "Dynatrace derives topology from observed traffic. Do not recreate the "
         "Application/Tier/Node tree — carry the naming across as host groups and tags "
         "so the estate stays navigable.",
         ("appd_inventory",)),
    Item("Namespaces", "Management zones",
         "scope", ASSISTED, 4,
         "Management zones define scope, access control and notification routing. Drive "
         "them from tags rather than one zone per application — a rule-per-application "
         "design hits the per-environment rule ceiling on a large estate.",
         ("appd_inventory",)),
    Item("Application naming rules", "Automatic tagging rules",
         "scope", ASSISTED, 4,
         "Tag-based entity grouping replaces naming conventions. The onboarding plan "
         "derives the tag scheme from the AppD Application and Tier names.",
         ("appd_inventory",)),
    Item("Tiers", "Process group instances (auto-grouped)",
         "scope", NOT_NEEDED, 4,
         "Auto-grouped from the processes actually running. No manual mapping needed in "
         "most cases.",
         ("appd_inventory",)),

    # -- 3. business transactions ------------------------------------------ #
    Item("Business transactions", "Services and request attributes",
         "transactions", NOT_NEEDED, 7,
         "Dynatrace detects every service endpoint automatically and has no per-application "
         "BT quota, so the AppD BT list — already shaped by its 200-per-application limit — "
         "should not be recreated. Only genuinely custom naming needs request attribute rules."),
    Item("Business transaction groups", "Service naming rules and management zones",
         "transactions", ASSISTED, 4,
         "Grouping is expressed through tags and management zones rather than a fixed "
         "hierarchy."),
    Item("Transaction snapshots", "Distributed traces (PurePaths)",
         "transactions", NOT_NEEDED, 3,
         "Captured continuously with full context, rather than triggered on a threshold. "
         "Any AppD action that exists to start a capture has nothing to migrate to."),
    Item("Information points", "Business events (Business Analytics)",
         "transactions", REBUILD, 7,
         "Not a 1:1 migration. Define capture rules and metric transformations from "
         "scratch, driven by what the business actually needs to see.",
         ("appd_infopoints",)),
    Item("HTTP data collectors (parameters, headers, cookies, session attributes)",
         "Request attributes",
         "transactions", AUTOMATIC, 7,
         "Converted directly. Cookies become a `Cookie` header capture with a value-extractor "
         "regex, since Dynatrace has no cookie source.",
         ("appd_datacollectors",)),
    Item("Method invocation data collectors (argument / return value capture)",
         "Request attributes with a method rule",
         "transactions", REBUILD, 7,
         "Inventoried, not generated. A Dynatrace method rule also needs the return type and "
         "visibility, which the AppD export does not carry, and it matches a process group "
         "where AppD matched a tier — a rule built from guesses applies cleanly and captures "
         "nothing. Build these in the UI where the class browser confirms the signature.",
         ("appd_datacollectors",)),
    Item("Transaction detection rules and custom match rules",
         "Automatic service detection, plus custom services where needed",
         "transactions", ASSISTED, 7,
         "Most detection rules exist to make AppD see a framework it does not know. "
         "Dynatrace detects the mainstream stacks natively; only genuinely unusual entry "
         "points need a custom service definition.",
         ("appd_txn_rules",)),
    Item("Service endpoints", "Service endpoints (detected automatically)",
         "transactions", NOT_NEEDED, 7,
         "Every endpoint on a service is detected, with no per-application quota. Keep the "
         "AppD list as a checklist for confirming the same endpoints appear after "
         "instrumentation, not as configuration to port.",
         ("appd_service_endpoints",)),
    Item("Backends and remote services", "Smartscape topology (detected automatically)",
         "transactions", NOT_NEEDED, 3,
         "Databases, queues and outbound HTTP dependencies are discovered from trace data "
         "and the dependency map builds itself. Use the AppD list to verify the same "
         "dependencies appear once agents report.",
         ("appd_backends",)),
    Item("Database collectors", "Database monitoring via the calling services, plus an "
         "extension for instance-level metrics",
         "transactions", ASSISTED, 7,
         "Configured differently rather than migrated: deep visibility comes from the "
         "services calling the database. Decide per database whether instance-level metrics "
         "justify an extension.",
         ("appd_db_collectors",)),

    # -- 4. alerting -------------------------------------------------------- #
    Item("Health rules with static thresholds", "Davis anomaly detectors",
         "alerting", AUTOMATIC, 5,
         "Converted directly, with AppD units rescaled to Dynatrace units.",
         ("appd_health_rule",)),
    Item("Health rules with baseline conditions",
         "Built-in Davis anomaly detection",
         "alerting", NOT_NEEDED, 5,
         "Davis baselines automatically and seasonally. These rules have no static "
         "threshold to carry across, and porting them would duplicate coverage and add "
         "noise. Tune sensitivity in anomaly detection settings instead.",
         ("appd_health_rule",)),
    Item("Policies (conditions bound to actions)",
         "Alerting profiles and problem notifications, or Workflows",
         "alerting", ASSISTED, 5,
         "Alerting profiles filter which problems route where; Workflows handle anything "
         "conditional.",
         ("appd_policies",)),
    Item("Email, PagerDuty and ServiceNow actions", "Problem notification integrations",
         "alerting", ASSISTED, 5,
         "Native connectors exist for the common destinations. Credentials are flagged by "
         "the converter and must be recreated in Dynatrace, never copied.",
         ("appd_policies",)),
    Item("Diagnostic actions (thread dumps, diagnostic sessions, forced snapshots)",
         "Continuous capture",
         "alerting", NOT_NEEDED, 5,
         "These exist because AppD captures deeply only when told to. Dynatrace captures "
         "method-level detail continuously, so there is nothing to rebuild.",
         ("appd_policies",)),
    Item("Action suppression", "Maintenance windows and alerting profile filters",
         "alerting", ASSISTED, 5,
         "Scheduled suppression becomes a maintenance window; conditional suppression "
         "becomes an alerting profile filter.",
         ("appd_policies", "appd_health_rule")),
    Item("Schedules", "Maintenance windows",
         "alerting", AUTOMATIC, 5,
         "AppD schedules decide when a rule evaluates; Dynatrace detectors run "
         "continuously, so the intent becomes a maintenance window. Converted to a "
         "Settings body — check the timezone before deploying, since an offset turns a "
         "maintenance window into an unannounced blind spot.",
         ("appd_schedules",)),
    Item("Baselines (dynamic thresholds)", "Davis auto-adaptive and seasonal baselines",
         "alerting", NOT_NEEDED, 5,
         "Built in. No baseline configuration to migrate — but Davis needs 7 to 14 days of "
         "data before its baselines are trustworthy, which is why alerting comes after "
         "instrumentation, not with it."),

    # -- 5. dashboards ------------------------------------------------------ #
    Item("Custom dashboards", "Dynatrace dashboards (DQL)",
         "dashboards", AUTOMATIC, 6,
         "Widgets are converted to DQL tiles as a starting point. Treat the output as a "
         "migration aid, not a finished dashboard — approach with intent, not replication.",
         ("appd_dashboard",)),
    Item("Metric graphs", "Timeseries tiles",
         "dashboards", AUTOMATIC, 6,
         "Metric paths are mapped to Grail metric keys where a documented equivalent "
         "exists, and reported as manual where it does not.",
         ("appd_dashboard",)),
    Item("Business transaction dashboards", "Service and trace level dashboards",
         "dashboards", REBUILD, 6,
         "The entity model differs enough that a direct copy misleads. Rebuild around "
         "services and endpoints."),
    Item("Health status tiles with baselines", "Davis problem tiles",
         "dashboards", REBUILD, 6,
         "Davis status and baseline values cannot always be shown together, so these need "
         "a different visual approach rather than a translated tile."),
    Item("Reports", "Scheduled dashboard exports",
         "dashboards", REBUILD, 6,
         "Recreate against the rebuilt dashboards, once those have settled."),

    # -- 6. custom metrics -------------------------------------------------- #
    Item("Custom metrics (SDK or API)",
         "Metrics Ingest API, OpenTelemetry, or Extensions 2.0",
         "metrics", REBUILD, 7,
         "Repoint whatever emits them. The ingestion path changes; the metric itself "
         "usually survives unchanged."),
    Item("Analytics metrics", "Metric extraction in OpenPipeline",
         "metrics", ASSISTED, 7,
         "Extract metrics from log or trace data at ingest rather than querying raw events "
         "repeatedly."),
    Item("Calculated service metrics", "Calculated service metrics",
         "metrics", ASSISTED, 7,
         "The same concept with a different configuration surface."),

    # -- 7. SLAs ------------------------------------------------------------ #
    Item("SLA definitions", "Dynatrace SLOs",
         "slo", ASSISTED, 7,
         "Define target, warning threshold and evaluation window. Deployable through the "
         "SLO app, the API, or the dynatrace_slo Terraform resource. AppD has no clean "
         "SLA export, so this one has to be inventoried by hand from the controller."),

    # -- 8. integrations ---------------------------------------------------- #
    Item("ServiceNow integration", "ServiceNow integration or Workflows",
         "integrations", ASSISTED, 8),
    Item("Jira and other ticketing", "Workflows with an HTTP action",
         "integrations", ASSISTED, 8),
    Item("CI/CD pipeline integration", "REST API, Workflows, or Monaco",
         "integrations", ASSISTED, 8,
         "Configuration as code through Monaco or the Terraform provider is usually a "
         "better landing spot than recreating pipeline scripts."),
    Item("CMDB sync", "Entity API and tagging",
         "integrations", ASSISTED, 8),
    Item("SNMP and infrastructure polling", "Extensions 2.0",
         "integrations", REBUILD, 8),

    # -- 9. access control -------------------------------------------------- #
    Item("Roles (view, configure, admin)", "IAM policies",
         "access", ASSISTED, 2,
         "Belongs in platform setup, before anyone needs access to validate their wave."),
    Item("Account level permissions", "Account Management IAM", "access", ASSISTED, 2),
    Item("Application scoped permissions", "Management zone scoped IAM policies",
         "access", ASSISTED, 2,
         "Depends on the management zone design from phase 4, so agree the zone scheme "
         "before granting scoped access."),
    Item("SSO (SAML)", "Dynatrace SSO configuration",
         "access", ASSISTED, 2),
]


def by_area() -> Dict[str, List[Item]]:
    out: Dict[str, List[Item]] = {}
    for item in CATALOGUE:
        out.setdefault(item.area, []).append(item)
    return out


def by_phase() -> Dict[int, List[Item]]:
    out: Dict[int, List[Item]] = {}
    for item in CATALOGUE:
        out.setdefault(item.phase, []).append(item)
    return out


def detected(kinds) -> List[Item]:
    """Catalogue items proven present by the artifact kinds in an export."""
    seen = set(kinds)
    return [i for i in CATALOGUE if seen.intersection(i.detected_by)]


def counts_by_approach() -> Dict[str, int]:
    out: Dict[str, int] = {}
    for item in CATALOGUE:
        out[item.approach] = out.get(item.approach, 0) + 1
    return out
