"""Render converted artifacts as Terraform resource bodies for the child module.

Bodies only — no `terraform {}`, no `provider {}`, no wrapping `resource` line.
`TerraformModule` owns the file layout and the identifiers; these functions own
what goes inside a block. Keeping the split means resource naming, collision
handling and provider requirements are decided in exactly one place.

Titles are wired through `var.name_prefix` and detectors through
`var.detectors_enabled`, so the caller can rename and stage a rollout without
editing generated files.
"""

from __future__ import annotations

from typing import List, Optional

from e2d.terraform.module import Resource, hcl_str

_ANALYZER = "dt.statistics.ui.anomaly_detection.StaticThresholdAnomalyDetectionAnalyzer"


def _prefixed(title: str) -> str:
    """An HCL expression interpolating the name prefix in front of a title."""
    inner = str(title).replace("\\", "\\\\").replace('"', '\\"')
    inner = inner.replace("${", "$${").replace("%{", "%%{")
    return f'"${{var.name_prefix}}{inner}"'


def _is_numeric(value) -> bool:
    try:
        float(str(value).strip().strip('"'))
        return True
    except ValueError:
        return False


# --------------------------------------------------------------------------- #
# Davis anomaly detectors
# --------------------------------------------------------------------------- #

def detector_resource(spec, det, index: int) -> Resource:
    """One `dynatrace_davis_anomaly_detectors` body from a Detector."""
    title = f"{spec.name}: {det.title}"
    raw = str(det.threshold).strip().strip('"')
    numeric = _is_numeric(raw)
    threshold = raw if numeric else "0"

    description = f"Migrated from {spec.source_kind}"
    if not numeric:
        description += (f" — threshold was dynamic in the source ({raw}); set a real value "
                        "before enabling")

    fields = [
        ("alertCondition", det.alert_condition),
        ("alertOnMissingData", "false"),
        ("violatingSamples", "3"),
        ("slidingWindow", "5"),
        ("dealertingSamples", "5"),
        ("query", det.query),
        ("threshold", threshold),
    ]
    inputs = "\n".join(
        f'      analyzer_input_field {{\n'
        f'        key   = {hcl_str(k)}\n'
        f'        value = {hcl_str(v)}\n'
        f'      }}'
        for k, v in fields)

    # A non-numeric threshold means the detector cannot be correct yet, so it
    # stays off regardless of what the caller sets.
    enabled = "false" if not numeric else "var.detectors_enabled"
    severity = "warning" if det.severity == "warning" else "error"

    body = f'''  title       = {_prefixed(title)}
  description = {hcl_str(description)}
  enabled     = {enabled}
  source      = "Davis Anomaly Detection"

  analyzer {{
    name = {hcl_str(_ANALYZER)}
    input {{
{inputs}
    }}
  }}

  event_template {{
    properties {{
      property {{
        key   = "event.type"
        value = "CUSTOM_ALERT"
      }}
      property {{
        key   = "event.name"
        value = {_prefixed(title)}
      }}
      property {{
        key   = "dt.davis.event.severity_level"
        value = {hcl_str(severity)}
      }}
    }}
  }}

  execution_settings {{
    query_offset = 1
  }}'''

    comment = ("Threshold was dynamic in the source — this detector is pinned off until a "
               "real value is set." if not numeric else "")
    return Resource(type="dynatrace_davis_anomaly_detectors",
                    name=f"{spec.name}_{index}" if index else spec.name,
                    body=body, group="detectors", comment=comment)


# --------------------------------------------------------------------------- #
# OpenPipeline
# --------------------------------------------------------------------------- #

def pipeline_resource(name: str, res) -> Resource:
    """One `dynatrace_openpipeline_v2_logs_pipelines` body."""
    from pathlib import Path

    stem = Path(name).stem
    lines: List[str] = [
        f"  display_name = {_prefixed(stem[:100])}",
        f"  custom_id    = {hcl_str(('pipeline_' + stem)[:60])}",
        "",
        "  processing {",
        "    processors {",
    ]
    counter = 0
    for stage in res.stages:
        if stage.kind not in ("dql", "drop"):
            if stage.kind == "manual":
                lines.append(f"      # MANUAL: {stage.description} — add an AppEngine "
                             "function, or drop this step")
            elif stage.description:
                lines.append(f"      # {stage.description}")
            continue
        counter += 1
        ptype = "drop" if stage.kind == "drop" else "dql"
        desc = stage.description or (stage.dql if stage.kind == "dql"
                                     else "drop matching records")
        lines += [
            "      processor {",
            f'        type        = {hcl_str(ptype)}',
            f'        id          = {hcl_str(f"p{counter:03d}")}',
            f"        description = {hcl_str(desc[:120])}",
            f"        enabled     = {'true' if stage.enabled else 'false'}",
            f"        matcher     = {hcl_str(stage.matcher)}",
        ]
        if stage.kind == "dql":
            lines += ["        dql {",
                      f"          script = {hcl_str(stage.dql)}",
                      "        }"]
        lines.append("      }")
    lines += ["    }", "  }"]
    return Resource(type="dynatrace_openpipeline_v2_logs_pipelines", name=stem,
                    body="\n".join(lines), group="pipelines")


# --------------------------------------------------------------------------- #
# Request attributes
# --------------------------------------------------------------------------- #

def _aligned(pairs: List[tuple], indent: int) -> List[str]:
    """Assignments with `=` aligned, so the output is already `terraform fmt` clean."""
    if not pairs:
        return []
    width = max(len(k) for k, _ in pairs)
    pad = " " * indent
    return [f"{pad}{k.ljust(width)} = {v}" for k, v in pairs]


def request_attribute_resource(attr) -> Resource:
    """One `dynatrace_request_attribute` body.

    Only HTTP-derived sources reach here. Method rules are excluded upstream
    because the provider requires a return type and visibility the AppD export
    does not carry, and a guessed rule applies cleanly while capturing nothing.
    """
    lines: List[str] = _aligned([
        ("name", _prefixed(attr.name)),
        ("enabled", "true" if attr.enabled else "false"),
        ("data_type", hcl_str(attr.data_type)),
        ("normalization", hcl_str(attr.normalization)),
        ("aggregation", hcl_str(attr.aggregation)),
        ("confidential", "true" if attr.confidential else "false"),
    ], indent=2)

    for src in attr.data_sources:
        lines.append("")
        lines.append("  data_sources {")
        pairs = [("enabled", "true"), ("source", hcl_str(src.get("source", "")))]
        if src.get("parameterName"):
            pairs.append(("parameter_name", hcl_str(src["parameterName"])))
        if src.get("technology"):
            pairs.append(("technology", hcl_str(src["technology"])))
        if src.get("capturingAndStorageLocation"):
            pairs.append(("capturing_and_storage_location",
                          hcl_str(src["capturingAndStorageLocation"])))
        lines += _aligned(pairs, indent=4)

        vp = src.get("valueProcessing")
        if isinstance(vp, dict) and vp.get("valueExtractorRegex"):
            lines.append("")
            lines.append("    value_processing {")
            lines += _aligned([
                ("value_extractor_regex", hcl_str(vp["valueExtractorRegex"])),
                ("trim", "true" if vp.get("trim") else "false"),
            ], indent=6)
            lines.append("    }")
        lines.append("  }")

    return Resource(type="dynatrace_request_attribute", name=attr.name,
                    body="\n".join(lines), group="request_attributes")


# --------------------------------------------------------------------------- #
# Workflows
# --------------------------------------------------------------------------- #

_ACTION_MAP = {
    "email": "dynatrace.automations:send-email-action",
    "webhook": "dynatrace.automations:http-function",
    "slack": "dynatrace.automations:http-function",
    "index": "dynatrace.automations:run-javascript",
    "unknown": "dynatrace.automations:run-javascript",
}


def workflow_resource(spec) -> Optional[Resource]:
    """A `dynatrace_automation_workflow` triggered by this alert's Davis event."""
    from e2d.alerts.model import Action

    actions = spec.actions or [Action("unknown", "notify")]
    lines: List[str] = [
        f"  title = {_prefixed(spec.name + ' (migrated)')}",
        "",
        "  trigger {",
        "    event {",
        "      active = true",
        "      config {",
        "        davis_event {",
        f'          custom_filter = "matchesPhrase(event.name, \\"{spec.name}\\")"',
        "        }",
        "      }",
        "    }",
        "  }",
        "",
        "  tasks {",
    ]
    for i, a in enumerate(actions):
        action = _ACTION_MAP.get(a.kind, _ACTION_MAP["unknown"])
        if a.kind == "email":
            payload = {"to": a.target, "subject": f"[{spec.name}] {{{{event.name}}}}",
                       "body": "Migrated alert. See the event for details."}
        elif a.kind in ("webhook", "slack"):
            payload = {"method": "POST", "url": f"https://{a.target}"}
            if a.secret:
                payload["credentialId"] = "REPLACE_WITH_DYNATRACE_CREDENTIAL_ID"
        else:
            payload = {"note": f"Original action `{a.kind}` — review"}
        inner = ", ".join(f'{k} = {hcl_str(v)}' for k, v in payload.items())
        secret_note = (f"      # set a Dynatrace credential for `{a.secret}`\n"
                       if a.secret else "")
        lines += [
            "    task {",
            f'      name   = {hcl_str(a.kind + "_" + str(i))}',
            f"      action = {hcl_str(action)}",
            secret_note.rstrip("\n") if secret_note else "",
            f"      input  = jsonencode({{ {inner} }})",
            "      position {",
            "        x = 0",
            f"        y = {i}",
            "      }",
            "    }",
        ]
    lines.append("  }")
    body = "\n".join(line for line in lines if line != "")
    return Resource(type="dynatrace_automation_workflow", name=spec.name,
                    body=body, group="workflows")
