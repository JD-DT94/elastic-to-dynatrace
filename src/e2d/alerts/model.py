"""Dialect-neutral model an Elastic Watcher or Kibana alerting rule reduces to.

Both sources describe the same four things, so both parse into an `AlertSpec`
which the renderer turns into a DQL query + a plain-English plan.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class Threshold:
    subject: str                 # what is compared: "count", a metric alias, or a metric key
    comparator: str              # DQL comparator: >  >=  <  <=  ==  !=
    value: str                   # rendered comparison value
    severity: str = "critical"   # critical | warning


@dataclass
class Action:
    kind: str                    # email | webhook | slack | index | unknown
    target: str                  # recipient list / host / connector summary
    secret: Optional[str] = None # a credential reference seen (flagged, never copied)


@dataclass
class Detector:
    """A single Davis anomaly detector: one DQL series + one static threshold.

    Maps directly to a `dynatrace_davis_anomaly_detectors` resource. The query is
    a `timeseries`/`makeTimeseries` projecting exactly one series at `interval:1m`
    (what the analyzer requires)."""
    title: str
    query: str
    alert_condition: str          # ABOVE | BELOW
    threshold: str
    severity: str = "critical"    # critical | warning
    metric_key: Optional[str] = None  # set when the series reads a metric (Phase 2 existence check)


# Recommended Dynatrace landing spot for the alert ("alerting is just a DQL query").
TARGET_ANOMALY_DETECTOR = "Davis anomaly detector (Terraform)"   # any DQL threshold
TARGET_WORKFLOW = "Workflow (Terraform)"                          # actions / chains / scripted logic
# kept as an alias so older call sites/tests keep working
TARGET_LOG_EVENT = TARGET_ANOMALY_DETECTOR
TARGET_METRIC_EVENT = TARGET_ANOMALY_DETECTOR


@dataclass
class AlertSpec:
    name: str
    source_kind: str                       # watcher | rule
    dql: str = ""                          # the query the alert evaluates
    data_object: str = "logs"
    window: Optional[str] = None           # evaluation window, e.g. "5m"
    schedule: Optional[str] = None         # interval ("1m") or a cron string
    thresholds: List[Threshold] = field(default_factory=list)
    group_by: List[str] = field(default_factory=list)
    actions: List[Action] = field(default_factory=list)
    suppression: Optional[str] = None      # throttle / dedup window
    target: str = TARGET_ANOMALY_DETECTOR  # recommended Dynatrace construct
    detectors: List[Detector] = field(default_factory=list)  # deployable anomaly detectors
