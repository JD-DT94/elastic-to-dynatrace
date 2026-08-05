"""AppDynamics metric paths -> Dynatrace Grail metrics.

An AppD metric path is a `|`-delimited tree address whose LAST segment names the
metric, e.g.::

    Business Transaction Performance|Business Transactions|checkout|/cart|Average Response Time (ms)
    Application Infrastructure Performance|web|Individual Nodes|node1|Hardware Resources|CPU|%Busy

so resolution keys off the leaf, with the preceding segments giving the entity
scope (which tier / business transaction / node the number belongs to).

Two things in here are load-bearing for correctness:

**Units.** AppD reports response times in **milliseconds**; the Grail metric
`dt.service.request.response_time` is in **microseconds**. A health rule that
fires above 2000 ms becomes 2000000 in Dynatrace. Carrying a threshold across
unscaled is the single easiest way to produce an alert that looks migrated and
never fires (or fires constantly), so every mapping states its scale explicitly
and `convert_threshold` is the only supported way to move a number across.

**Refusal to guess.** An unrecognised leaf returns `None` rather than a
plausible-looking metric. The caller reports it as MANUAL. A wrong metric key
produces a detector that deploys cleanly and watches the wrong thing.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

# Grail metric keys confirmed against the Dynatrace built-in metric
# documentation; response time's microsecond granularity is what drives the
# ms -> us scaling below.
MS_TO_US = 1000.0
MB_TO_BYTES = 1048576.0
SEC_TO_US = 1000000.0


@dataclass
class MetricMapping:
    """How one AppD metric leaf lands in Dynatrace."""
    dt_metric: str
    aggregation: str = "avg"          # avg | sum | max | min
    scale: float = 1.0                # AppD value * scale = Dynatrace value
    source_unit: str = ""
    dt_unit: str = ""
    entity: str = "service"           # service | host | process | database
    # Built-in Dynatrace detection that already covers this signal. When set, a
    # baseline-type AppD health rule on this metric is redundant: Davis does it
    # automatically, with better baselining than a static port-over.
    davis_builtin: Optional[str] = None
    note: str = ""

    @property
    def rescales(self) -> bool:
        return self.scale != 1.0


# Leaf metric name -> mapping. Keys are matched case-insensitively after
# whitespace collapsing. Only metrics whose Dynatrace equivalent is documented
# and unambiguous appear here; everything else is deliberately absent so it
# surfaces as MANUAL rather than as a confident guess.
_LEAF_MAP: Dict[str, MetricMapping] = {
    # -- service / business transaction performance ------------------------- #
    "average response time (ms)": MetricMapping(
        "dt.service.request.response_time", "avg", MS_TO_US, "ms", "microseconds",
        davis_builtin="Service response time degradation (built-in Davis anomaly detection)"),
    "95th percentile response time (ms)": MetricMapping(
        "dt.service.request.response_time", "percentile", MS_TO_US, "ms", "microseconds",
        note="Emitted as percentile(.., 95); a metric `timeseries` percentile needs `rollup:`."),
    "99th percentile response time (ms)": MetricMapping(
        "dt.service.request.response_time", "percentile", MS_TO_US, "ms", "microseconds",
        note="Emitted as percentile(.., 99); a metric `timeseries` percentile needs `rollup:`."),
    "max response time (ms)": MetricMapping(
        "dt.service.request.response_time", "max", MS_TO_US, "ms", "microseconds"),
    "calls per minute": MetricMapping(
        "dt.service.request.count", "sum", 1.0, "calls/min", "count per interval",
        davis_builtin="Service load drop / load spike (built-in Davis anomaly detection)",
        note="At `interval:1m` the summed count IS calls-per-minute, so no rescale."),
    "total calls": MetricMapping("dt.service.request.count", "sum", 1.0, "calls", "count"),
    "errors per minute": MetricMapping(
        "dt.service.request.failure_count", "sum", 1.0, "errors/min", "count per interval",
        davis_builtin="Service failure rate increase (built-in Davis anomaly detection)",
        note="At `interval:1m` the summed failure count IS errors-per-minute."),
    "number of errors": MetricMapping("dt.service.request.failure_count", "sum"),
    "average cpu used (ms)": MetricMapping(
        "dt.service.request.cpu_time", "avg", MS_TO_US, "ms", "microseconds",
        note="Verify `dt.service.request.cpu_time` exists in your tenant; service CPU "
             "time is not part of the guaranteed built-in set on every version."),

    # -- host / infrastructure ---------------------------------------------- #
    "%busy": MetricMapping(
        "dt.host.cpu.usage", "avg", 1.0, "percent", "percent", entity="host",
        davis_builtin="Host CPU saturation (built-in infrastructure anomaly detection)"),
    "cpu utilization %": MetricMapping(
        "dt.host.cpu.usage", "avg", 1.0, "percent", "percent", entity="host",
        davis_builtin="Host CPU saturation (built-in infrastructure anomaly detection)"),
    "used %": MetricMapping(
        "dt.host.memory.usage", "avg", 1.0, "percent", "percent", entity="host",
        davis_builtin="Host memory saturation (built-in infrastructure anomaly detection)"),
    "memory utilization %": MetricMapping(
        "dt.host.memory.usage", "avg", 1.0, "percent", "percent", entity="host",
        davis_builtin="Host memory saturation (built-in infrastructure anomaly detection)"),
    "disk usage %": MetricMapping(
        "dt.host.disk.used.percent", "avg", 1.0, "percent", "percent", entity="host",
        davis_builtin="Disk space low (built-in infrastructure anomaly detection)"),

    "disk queue length": MetricMapping(
        "dt.host.disk.queue_length", "avg", 1.0, "count", "count", entity="host"),
    "kb read/sec": MetricMapping(
        "dt.host.disk.read.bytes", "sum", 1024.0, "KB/s", "bytes", entity="host"),
    "kb written/sec": MetricMapping(
        "dt.host.disk.write.bytes", "sum", 1024.0, "KB/s", "bytes", entity="host"),
    "incoming kb/sec": MetricMapping(
        "dt.host.net.nic.bytes_rx", "sum", 1024.0, "KB/s", "bytes", entity="host"),
    "outgoing kb/sec": MetricMapping(
        "dt.host.net.nic.bytes_tx", "sum", 1024.0, "KB/s", "bytes", entity="host"),

    # -- JVM ------------------------------------------------------------------ #
    "current usage (mb)": MetricMapping(
        "dt.runtime.jvm.memory_pool.used", "avg", MB_TO_BYTES, "MB", "bytes",
        entity="process"),
    "used (mb)": MetricMapping(
        "dt.runtime.jvm.memory_pool.used", "avg", MB_TO_BYTES, "MB", "bytes",
        entity="process"),
    "committed (mb)": MetricMapping(
        "dt.runtime.jvm.memory_pool.committed", "avg", MB_TO_BYTES, "MB", "bytes",
        entity="process"),
    "gc time spent per min (ms)": MetricMapping(
        "dt.runtime.jvm.gc.collection_time", "sum", 1.0, "ms", "milliseconds",
        entity="process",
        note="Verify the GC metric key and unit in your tenant before enabling."),
    "number of times gc per min": MetricMapping(
        "dt.runtime.jvm.gc.collection_count", "sum", 1.0, "count", "count",
        entity="process"),
    "current no. of threads": MetricMapping(
        "dt.runtime.jvm.threads", "avg", 1.0, "count", "count", entity="process"),

    # -- .NET CLR -------------------------------------------------------------- #
    "% time in gc": MetricMapping(
        "dt.runtime.dotnet.gc.time", "avg", 1.0, "percent", "percent", entity="process",
        note="Verify the .NET GC metric key in your tenant; CLR metric names vary by "
             "OneAgent version."),
    "total bytes in all heaps": MetricMapping(
        "dt.runtime.dotnet.gc.heap_size", "avg", 1.0, "bytes", "bytes", entity="process"),

    # -- databases ------------------------------------------------------------- #
    "average query response time (ms)": MetricMapping(
        "dt.service.request.response_time", "avg", MS_TO_US, "ms", "microseconds",
        entity="database",
        davis_builtin="Database service response time degradation (built-in Davis)",
        note="Filter to database services; Dynatrace models a database as a service."),
    "queries per minute": MetricMapping(
        "dt.service.request.count", "sum", 1.0, "queries/min", "count per interval",
        entity="database"),
}

# Leaves we recognise but deliberately refuse to map, with the reason. These
# produce a MANUAL note naming the Dynatrace construct to build instead — far
# more useful than silence, and honest that no metric swap exists.
_KNOWN_UNMAPPED: Dict[str, str] = {
    "error percentage": (
        "Dynatrace has no single error-percentage metric. Build it in DQL as "
        "`failure_count[] / count[] * 100` (element-wise on the timeseries arrays), "
        "or alert on failure count directly."),
    "number of slow calls": (
        "AppD's slow/very-slow buckets come from its own dynamic baseline. Dynatrace "
        "detects response-time degradation automatically via Davis; there is no "
        "equivalent counter to threshold."),
    "number of very slow calls": (
        "AppD's slow/very-slow buckets come from its own dynamic baseline. Dynatrace "
        "detects response-time degradation automatically via Davis; there is no "
        "equivalent counter to threshold."),
    "stall count": (
        "Stalls are an AppD construct. The nearest Dynatrace signal is a "
        "response-time or failure-rate anomaly on the same service."),
    "average block time (ms)": (
        "No built-in Dynatrace equivalent. Available per-request via method hotspots; "
        "needs a custom approach rather than a metric threshold."),
    "average request size (bytes)": (
        "Not a built-in Dynatrace service metric; capture it as a request attribute "
        "first if you need to alert on it."),
    "art (ms)": (
        "Ambiguous abbreviation in an AppD metric path — it usually means Average "
        "Response Time, but rename the metric in the export (or map it by hand) rather "
        "than have the converter assume."),
    "calls": (
        "Ambiguous: AppD uses bare `Calls` for both totals and rates depending on the "
        "path. Use `Calls per Minute` or `Total Calls` so the conversion is unambiguous."),
    "nodes available": (
        "An AppD availability counter with no Dynatrace equivalent — Dynatrace tracks "
        "host and process availability directly. Alert on the entity, not a count."),
    "hardware resources|cpu|%idle": (
        "Dynatrace reports CPU as usage, not idle. Invert the condition and alert on "
        "`dt.host.cpu.usage` going ABOVE (100 - your idle threshold)."),
    "%idle": (
        "Dynatrace reports CPU as usage, not idle. Invert the condition and alert on "
        "`dt.host.cpu.usage` going ABOVE (100 - your idle threshold)."),
}


def _normalise(leaf: str) -> str:
    return re.sub(r"\s+", " ", leaf.strip().lower())


def split_path(metric_path: str) -> List[str]:
    """The `|`-delimited segments of an AppD metric path, whitespace-trimmed."""
    return [seg.strip() for seg in str(metric_path or "").split("|") if seg.strip()]


def leaf_of(metric_path: str) -> str:
    segs = split_path(metric_path)
    return segs[-1] if segs else ""


def resolve(metric_path: str) -> Tuple[Optional[MetricMapping], Optional[str]]:
    """Resolve an AppD metric path.

    Returns `(mapping, None)` when it maps, or `(None, reason)` when it does
    not — `reason` is a plain-English explanation for the migration report.
    Never returns a speculative mapping.
    """
    leaf = _normalise(leaf_of(metric_path))
    if not leaf:
        return None, "empty metric path"
    if leaf in _LEAF_MAP:
        return _LEAF_MAP[leaf], None
    if leaf in _KNOWN_UNMAPPED:
        return None, _KNOWN_UNMAPPED[leaf]
    return None, (f"`{leaf}` has no known Dynatrace equivalent. Find the closest metric with "
                  "`fetch dt.semantic.dictionary` or the Metrics app, then set the threshold "
                  "in that metric's own units.")


def convert_threshold(value, mapping: MetricMapping):
    """Move an AppD threshold into Dynatrace units.

    The ONLY supported way to carry a number across. Returns the value as a
    string with trailing `.0` trimmed, so `2000 ms` becomes `"2000000"`.
    """
    try:
        scaled = float(value) * mapping.scale
    except (TypeError, ValueError):
        return str(value)
    if scaled == int(scaled):
        return str(int(scaled))
    return str(scaled)


def scope_from_path(metric_path: str) -> Dict[str, str]:
    """Pull the entity scope out of the leading segments of a metric path.

    Best-effort and reported as such: AppD path grammar varies by metric family,
    so this is used to describe scope to a human, never to build a filter that
    silently narrows a query.
    """
    segs = split_path(metric_path)
    scope: Dict[str, str] = {}
    if not segs:
        return scope
    root = segs[0].lower()
    if root.startswith("business transaction performance") and len(segs) >= 5:
        # ...|Business Transactions|<tier>|<bt>|<leaf>
        scope["tier"] = segs[-3]
        scope["business_transaction"] = segs[-2]
    elif root.startswith("overall application performance") and len(segs) >= 3:
        scope["tier"] = segs[1]
    elif root.startswith("application infrastructure performance") and len(segs) >= 2:
        scope["tier"] = segs[1]
        if "individual nodes" in [s.lower() for s in segs] and len(segs) >= 4:
            idx = [s.lower() for s in segs].index("individual nodes")
            if idx + 1 < len(segs):
                scope["node"] = segs[idx + 1]
    elif root.startswith("service endpoints") and len(segs) >= 3:
        scope["tier"] = segs[1]
        scope["service_endpoint"] = segs[2]
    elif root.startswith("errors") and len(segs) >= 2:
        scope["tier"] = segs[1]
    return scope


def build_series_dql(mapping: MetricMapping, alias: str = "value",
                     interval: str = "1m") -> str:
    """A single-series metric `timeseries` for a Davis anomaly detector.

    Deliberately emitted WITHOUT an entity filter. AppD scopes by tier/BT name,
    and there is no reliable offline translation from those names to Dynatrace
    entities — inventing one would silently narrow the query to nothing. The
    caller attaches the AppD scope as a review note instead, so a human scopes
    it with real entity knowledge.
    """
    alias = re.sub(r"[^A-Za-z0-9_]", "_", alias) or "value"
    if mapping.aggregation == "percentile":
        pct = 99 if "99" in mapping.note else 95
        return (f"timeseries {alias} = percentile({mapping.dt_metric}, {pct}), "
                f"interval:{interval}, rollup: avg")
    return f"timeseries {alias} = {mapping.aggregation}({mapping.dt_metric}), interval:{interval}"
