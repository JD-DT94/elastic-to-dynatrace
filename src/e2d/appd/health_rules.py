"""AppDynamics health rules -> Dynatrace alerting.

A health rule reduces to the shared `AlertSpec`, so once translated it reuses
the whole existing alert pipeline: `alerts/tf.py` for Terraform, the Settings
body in `sinks/dynatrace.py`, the push panel, the report and the scorecard.

Three judgement calls decide whether the output is correct or merely plausible:

**Baseline conditions do not become static detectors.** An AppD condition of
"more than 3 standard deviations above the All Data baseline" has no static
number in it. Dynatrace's answer to that is built-in Davis anomaly detection,
which baselines automatically. Inventing a static threshold to fill the gap
would produce a detector that deploys cleanly and alerts on the wrong thing,
so these are classified as already-covered and deliberately emit no detector.

**Multi-condition ALL rules do not become several detectors.** Davis detectors
evaluate independently, so emitting one per condition turns an AND into an OR
and the alert fires far too often. Those are reported MANUAL with the
conditions listed, for a single combined DQL query or a Workflow.

**Metrics that do not map are not guessed.** `metrics.resolve` returns a reason
instead of a lookalike key; the rule is reported MANUAL with that reason.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from e2d.alerts.model import Action, AlertSpec, Detector, Threshold
from e2d.appd import metrics as appd_metrics
from e2d.dql.validate import lint_into_report
from e2d.report import Report

# Where this rule should land in Dynatrace.
TARGET_BUILTIN_DAVIS = "Built-in Davis anomaly detection (no config to migrate)"
TARGET_DETECTOR = "Davis anomaly detector"
TARGET_MANUAL = "Manual rebuild"

# AppD comparator -> (DQL comparator, Davis alertCondition)
_COMPARATORS: Dict[str, Tuple[str, str]] = {
    "GREATER_THAN": (">", "ABOVE"),
    "GREATER_OR_EQUAL_TO": (">=", "ABOVE"),
    "GREATER_THAN_OR_EQUAL_TO": (">=", "ABOVE"),
    "LESS_THAN": ("<", "BELOW"),
    "LESS_OR_EQUAL_TO": ("<=", "BELOW"),
    "LESS_THAN_OR_EQUAL_TO": ("<=", "BELOW"),
    "EQUALS": ("==", "ABOVE"),
    "NOT_EQUALS": ("!=", "ABOVE"),
}

# Affected-entity types whose signal Dynatrace derives automatically.
_ENTITY_LABEL = {
    "BUSINESS_TRANSACTION_PERFORMANCE": "business transactions",
    "OVERALL_APPLICATION_PERFORMANCE": "the application overall",
    "TIER_NODE_TRENDS": "tiers/nodes",
    "TIER_NODE_HARDWARE": "node hardware",
    "SERVICE_ENDPOINTS": "service endpoints",
    "ERRORS": "errors",
    "DATABASES": "databases",
    "SERVERS": "servers",
    "JMX": "JMX metrics",
    "INFORMATION_POINTS": "information points",
}


@dataclass
class HealthRuleResult:
    spec: AlertSpec
    report: Report
    # covered-by-davis | converted | manual — drives the report's advice and is
    # the number worth quoting: how much of the estate needs no work at all.
    classification: str = "converted"
    appd_scope: Dict[str, str] = field(default_factory=dict)


def _get(d: Any, *names, default=None):
    """Tolerant key lookup — AppD JSON casing varies between API versions."""
    if not isinstance(d, dict):
        return default
    for n in names:
        if n in d:
            return d[n]
        for k in d:
            if k.lower() == n.lower():
                return d[k]
    return default


def _conditions(criteria: Any) -> List[dict]:
    conds = _get(criteria, "conditions", default=[]) or []
    return [c for c in conds if isinstance(c, dict)]


def _aggregation_type(criteria: Any) -> str:
    return str(_get(criteria, "conditionAggregationType", default="ANY") or "ANY").upper()


def _describe_scope(rule: dict) -> Dict[str, str]:
    """What the AppD rule was scoped to, for the review note."""
    affects = _get(rule, "affects", default={}) or {}
    scope: Dict[str, str] = {}
    ent = _get(affects, "affectedEntityType")
    if ent:
        scope["entity_type"] = str(ent)
    for key, label in (("affectedBusinessTransactions", "business_transactions"),
                       ("affectedTiers", "tiers"), ("affectedNodes", "nodes"),
                       ("affectedServiceEndpoints", "service_endpoints")):
        block = _get(affects, key)
        if not isinstance(block, dict):
            continue
        for scope_key in ("businessTransactionScope", "tierScope", "nodeScope",
                          "serviceEndpointScope", "scope"):
            v = _get(block, scope_key)
            if v:
                scope[label] = str(v)
                break
        for list_key in ("businessTransactions", "tiers", "nodes", "serviceEndpoints"):
            items = _get(block, list_key)
            if isinstance(items, list) and items:
                named = [str(i.get("name", i)) if isinstance(i, dict) else str(i)
                         for i in items]
                scope[label] = ", ".join(named[:8]) + ("…" if len(named) > 8 else "")
                break
    return scope


def _scope_sentence(scope: Dict[str, str], metric_scope: Dict[str, str]) -> str:
    bits = []
    ent = scope.get("entity_type")
    if ent:
        bits.append(_ENTITY_LABEL.get(ent, ent))
    for label, key in (("tier", "tier"), ("business transaction", "business_transaction"),
                       ("node", "node")):
        if metric_scope.get(key):
            bits.append(f"{label} `{metric_scope[key]}`")
    for label, key in (("business transactions", "business_transactions"),
                       ("tiers", "tiers"), ("nodes", "nodes")):
        if scope.get(key) and key not in ("entity_type",):
            bits.append(f"{label}: {scope[key]}")
    return "; ".join(dict.fromkeys(bits)) if bits else "the whole application"


def _convert_condition(cond: dict, severity: str, rule_name: str,
                       report: Report) -> Tuple[Optional[Detector], Optional[Threshold],
                                                Optional[str], Dict[str, str]]:
    """One AppD condition -> at most one Detector.

    Returns `(detector, threshold, davis_builtin, metric_scope)`. A returned
    `davis_builtin` (with no detector) means Dynatrace already covers it.
    """
    name = str(_get(cond, "name", "shortName", default="condition"))
    detail = _get(cond, "evalDetail", default={}) or {}
    detail_type = str(_get(detail, "evalDetailType", default="SINGLE_METRIC") or "").upper()

    if detail_type == "METRIC_EXPRESSION":
        expr = _get(detail, "metricExpression", default="")
        report.manual(
            f"Condition `{name}` uses an AppD metric EXPRESSION"
            f"{(' (' + str(expr)[:120] + ')') if expr else ''}, which combines several metric "
            "paths arithmetically. Rebuild it as a single DQL query — DQL does the same "
            "arithmetic element-wise on timeseries arrays, e.g. `a[] / b[] * 100`.")
        return None, None, None, {}

    metric_path = _get(detail, "metricPath", default="") or ""
    metric_scope = appd_metrics.scope_from_path(metric_path)
    mapping, reason = appd_metrics.resolve(metric_path)
    if mapping is None:
        report.manual(f"Condition `{name}` watches `{metric_path or '(no metric path)'}` — {reason}")
        return None, None, None, metric_scope

    eval_detail = _get(detail, "metricEvalDetail", default={}) or {}
    eval_type = str(_get(eval_detail, "metricEvalDetailType", default="") or "").upper()

    # -- baseline conditions: Davis already does this ----------------------- #
    if eval_type == "BASELINE_TYPE" or _get(eval_detail, "baselineCondition"):
        baseline_name = _get(eval_detail, "baselineName", default="")
        unit = str(_get(eval_detail, "baselineUnit", default="") or "").lower()
        amount = _get(eval_detail, "compareValue", default="")
        covered = mapping.davis_builtin or (
            "Davis automatic baselining for " + mapping.dt_metric)
        report.info(
            f"Condition `{name}` compares against an AppD baseline "
            f"({amount} {unit or 'units'} from `{baseline_name or 'baseline'}`). There is no "
            f"static threshold to carry across, and none should be invented — this is "
            f"covered by {covered}. Tune sensitivity there rather than recreating the rule.")
        return None, None, covered, metric_scope

    # -- static thresholds: the real conversion ----------------------------- #
    raw_comparator = str(_get(eval_detail, "compareCondition", default="GREATER_THAN") or "").upper()
    if raw_comparator not in _COMPARATORS:
        report.manual(
            f"Condition `{name}` uses comparator `{raw_comparator}`, which has no Davis "
            "equivalent (detectors alert ABOVE or BELOW a threshold). Rebuild by hand.")
        return None, None, None, metric_scope
    dql_cmp, alert_condition = _COMPARATORS[raw_comparator]

    raw_value = _get(eval_detail, "compareValue", default=None)
    if raw_value is None:
        report.manual(f"Condition `{name}` has no comparison value to migrate.")
        return None, None, None, metric_scope

    scaled = appd_metrics.convert_threshold(raw_value, mapping)
    if mapping.rescales:
        report.info(
            f"Condition `{name}`: threshold {raw_value} {mapping.source_unit} converted to "
            f"{scaled} {mapping.dt_unit} — AppD reports {mapping.source_unit} where "
            f"`{mapping.dt_metric}` is in {mapping.dt_unit}.")

    agg_fn = str(_get(detail, "metricAggregateFunction", default="") or "").upper()
    if agg_fn and agg_fn not in ("VALUE", "CURRENT"):
        report.warn(
            f"Condition `{name}` aggregates with AppD's `{agg_fn}` over the rule window; the "
            f"detector uses `{mapping.aggregation}` per minute. Check the detector's sliding "
            "window if the two disagree.")

    alias = "value"
    dql = appd_metrics.build_series_dql(mapping, alias)
    if mapping.note:
        report.info(f"Condition `{name}`: {mapping.note}")

    detector = Detector(
        title=name if name and name != "condition" else rule_name,
        query=dql,
        alert_condition=alert_condition,
        threshold=scaled,
        severity=severity,
        metric_key=mapping.dt_metric,
    )
    threshold = Threshold(subject=mapping.dt_metric, comparator=dql_cmp,
                          value=scaled, severity=severity)
    return detector, threshold, None, metric_scope


def translate_health_rule(text_or_doc, name: Optional[str] = None) -> HealthRuleResult:
    """Translate one AppD health rule (JSON text or already-parsed dict)."""
    import json

    report = Report()
    doc = json.loads(text_or_doc) if isinstance(text_or_doc, (str, bytes)) else text_or_doc
    if isinstance(doc, list):
        doc = doc[0] if doc else {}
    if not isinstance(doc, dict):
        doc = {}

    rule_name = str(_get(doc, "name", default=None) or name or "health rule")
    spec = AlertSpec(name=rule_name, source_kind="AppDynamics health rule")

    if _get(doc, "enabled", default=True) is False:
        report.info("This health rule is DISABLED in AppD. Converted anyway so the estate is "
                    "complete — the emitted detector is enabled, so drop it if you do not want it.")

    window = _get(doc, "useDataFromLastNMinutes", default=None)
    if window:
        spec.window = f"{window}m"
    wait = _get(doc, "waitTimeAfterViolation", default=None)
    if wait:
        spec.suppression = f"{wait}m"
    schedule = _get(doc, "scheduleName", default=None)
    if schedule and str(schedule).lower() not in ("always", "always (default)"):
        report.warn(
            f"The rule only evaluates on AppD schedule `{schedule}`. Davis detectors run "
            "continuously — if the schedule mattered (e.g. suppressing overnight batch), "
            "reproduce it as a maintenance window in Dynatrace.")

    scope = _describe_scope(doc)
    eval_criteria = _get(doc, "evalCriterias", "evalCriteria", default={}) or {}

    detectors: List[Detector] = []
    thresholds: List[Threshold] = []
    covered_by: List[str] = []
    metric_scope: Dict[str, str] = {}
    saw_condition = False

    for criteria_key, severity in (("criticalCriteria", "critical"),
                                   ("warningCriteria", "warning")):
        criteria = _get(eval_criteria, criteria_key)
        conds = _conditions(criteria)
        if not conds:
            continue
        saw_condition = True
        agg = _aggregation_type(criteria)

        if agg == "ALL" and len(conds) > 1:
            names = ", ".join(f"`{_get(c, 'name', 'shortName', default='?')}`" for c in conds)
            report.manual(
                f"The {severity} criteria require ALL {len(conds)} conditions to be true "
                f"({names}). Davis detectors evaluate independently, so emitting one per "
                "condition would turn the AND into an OR and alert far too often. Build a "
                "single DQL query that expresses the combined condition, then create one "
                "detector from it.")
            continue

        for cond in conds:
            detector, threshold, covered, mscope = _convert_condition(
                cond, severity, rule_name, report)
            metric_scope.update(mscope)
            if covered:
                covered_by.append(covered)
            if detector:
                detectors.append(detector)
            if threshold:
                thresholds.append(threshold)

    if not saw_condition:
        report.manual("No evaluation criteria found in this health rule — nothing to convert. "
                      "Check the export came from the Health Rule API rather than a list view "
                      "(the list endpoint returns only id/name/enabled).")

    spec.detectors = detectors
    spec.thresholds = thresholds
    spec.dql = detectors[0].query if detectors else ""

    # Scope is described, never silently applied: AppD names tiers and business
    # transactions, and there is no reliable offline mapping to Dynatrace
    # entities. A wrong filter yields an empty series and a detector that never
    # fires, which is worse than an explicit review note.
    if detectors:
        where = _scope_sentence(scope, metric_scope)
        report.warn(
            f"In AppD this rule watched {where}. The generated detector is NOT scoped to any "
            "entity — it evaluates the metric across everything reporting it. Add an entity "
            "filter for the migrated service(s) before enabling, or it will alert too broadly.")

    if covered_by and not detectors:
        spec.target = TARGET_BUILTIN_DAVIS
        classification = "covered-by-davis"
    elif detectors:
        spec.target = TARGET_DETECTOR
        classification = "converted"
    else:
        spec.target = TARGET_MANUAL
        classification = "manual"

    for d in detectors:
        lint_into_report(d.query, report)

    return HealthRuleResult(spec=spec, report=report, classification=classification,
                            appd_scope={**scope, **metric_scope})


def render_health_rule(result: HealthRuleResult) -> str:
    """Plain-English migration note for one health rule."""
    spec = result.spec
    L: List[str] = [f"# {spec.name}", "",
                    f"Source: {spec.source_kind}", f"Lands in Dynatrace as: **{spec.target}**", ""]

    if result.classification == "covered-by-davis":
        L += ["## No migration needed", "",
              "Every condition in this rule compares against an AppD baseline, which Dynatrace "
              "does automatically. Recreating it would duplicate coverage and add noise.",
              "",
              "Tune sensitivity under Settings > Anomaly detection instead of porting the rule; "
              "the notes below name the built-in detection covering each condition.", ""]

    if spec.window:
        L.append(f"- Evaluation window in AppD: {spec.window}")
    if spec.suppression:
        L.append(f"- Wait after violation: {spec.suppression}")
    if result.appd_scope:
        pretty = ", ".join(f"{k.replace('_', ' ')}: {v}" for k, v in result.appd_scope.items())
        L.append(f"- AppD scope: {pretty}")
    if spec.window or spec.suppression or result.appd_scope:
        L.append("")

    if spec.detectors:
        L += [f"## Detectors ({len(spec.detectors)})", ""]
        for d in spec.detectors:
            L += [f"### {d.title} ({d.severity})", "",
                  "```dql", d.query, "```", "",
                  f"Alerts **{d.alert_condition}** `{d.threshold}`.", ""]

    notes = result.report.format_deduped()
    if notes:
        L += ["## Notes", ""] + [f"- {n}" for n in notes] + [""]
    return "\n".join(L)
