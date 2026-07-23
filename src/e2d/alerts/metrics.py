"""Metric-existence check + OpenPipeline metric creation.

A `metrics.alert.threshold` rule references an Elastic metric name (e.g.
`system.cpu.total.norm.pct`). That key almost never exists verbatim in Grail, so
firing an anomaly detector on it would silently return nothing. So we **check**
every metric a detector reads and, for the ones that don't look like Dynatrace
metrics, emit a starter **OpenPipeline `value_metric` processor** (with a matcher)
that *creates* the metric from logs — the supported way to make a metric in
Dynatrace (`dynatrace_openpipeline_v2_logs_pipelines`).
"""

from __future__ import annotations

import re
from typing import List, Tuple

from e2d.alerts.model import AlertSpec, Detector

# A metric the platform already provides: the `dt.` namespace, or a Grail
# builtin (`builtin:`). Anything else (Elastic/metricbeat names) needs creating.
_KNOWN_PREFIXES = ("dt.", "builtin:")


def is_dynatrace_metric(key: str) -> bool:
    return bool(key) and key.startswith(_KNOWN_PREFIXES)


def missing_metrics(spec: AlertSpec) -> List[Tuple[str, Detector]]:
    """(metric_key, detector) for every detector reading a non-Dynatrace metric."""
    seen, out = set(), []
    for d in spec.detectors:
        if d.metric_key and not is_dynatrace_metric(d.metric_key) and d.metric_key not in seen:
            seen.add(d.metric_key)
            out.append((d.metric_key, d))
    return out


def _safe_key(metric: str) -> str:
    # a creatable Grail metric key under a clear migration namespace
    cleaned = re.sub(r"[^a-z0-9_.]", "_", metric.lower()).strip("._")
    return f"log.{cleaned}" if not cleaned.startswith("log.") else cleaned


def render_metric_creation(spec: AlertSpec) -> str:
    """Markdown guide + a starter OpenPipeline `value_metric` processor per missing
    metric. It is *not* a standalone Terraform file (the processor block drops into
    an existing logs pipeline's `processing { processors { ... } }`), so it is
    emitted as Markdown with HCL snippets — keeping it out of `terraform validate`
    on the detector module beside it."""
    missing = missing_metrics(spec)
    if not missing:
        return ""
    L = [f"# Metric creation for `{spec.name}`", "",
         "These metrics are referenced by the alert but are **not** Dynatrace metrics, so the anomaly "
         "detector won't fire until they exist. Create each via OpenPipeline — paste the `processor` "
         "into a `dynatrace_openpipeline_v2_logs_pipelines` pipeline's `processing { processors { ... } }` "
         "block, then point the detector at the new `metric_key`. **Review the matcher and source "
         "field** — the numeric value must be present on a matching log record.", ""]
    for i, (metric, _det) in enumerate(missing):
        key = _safe_key(metric)
        # one `dimensions` block containing one `dimension` entry per group field
        dims = ""
        if spec.group_by:
            entries = "\n".join(
                f'''      dimension {{
        extraction_type   = "field"
        strategy          = "equals"
        source_field_name = "{g}"
      }}''' for g in spec.group_by)
            dims = f'''
    dimensions {{
{entries}
    }}'''
        L.append(f"## `{metric}` → `{key}`")
        L.append("")
        L.append("```hcl")
        L.append(f'''processor {{
  type        = "valueMetric"
  id          = "create_{re.sub(r"[^a-z0-9_]", "_", key)}_{i}"
  description = "Create {key} (was Elastic {metric}) for the migrated alert"
  matcher     = "true"   // TODO: scope to the records carrying this value
  value_metric {{
    metric_key    = "{key}"
    field         = "{metric}"   // TODO: the log field holding the numeric value{dims}
  }}
  enabled = true
}}''')
        L.append("```")
        L.append("")
    return "\n".join(L)


def check_metrics(spec: AlertSpec, report) -> None:
    """Fold the existence check into the alert's report (called during translate)."""
    for metric, _ in missing_metrics(spec):
        report.warn(f"Metric `{metric}` is not a Dynatrace metric (no `dt.*`); the detector won't fire "
                    "until it exists. `e2d alert --terraform` also emits an OpenPipeline `value_metric` "
                    "processor to create it — review its matcher and source field.")
