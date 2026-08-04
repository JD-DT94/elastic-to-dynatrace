"""Emit a deployable `dynatrace_openpipeline_v2_logs_pipelines` Terraform module
from the translated pipeline stages.

The v2 resource is **flat** (one resource = one pipeline): required `display_name`
+ `custom_id`, then `processing { processors { processor { ... } } }`. Each
processor carries a `type` discriminator (`"dql"`/`"drop"`), the common fields
(`id`/`description`/`enabled`/`matcher`), and a type block — DQL goes in
`dql { script = "..." }` (parsing/DPL is expressed through the DQL `parse`
command). `manual`/`note` stages become HCL comments so nothing is silently
dropped.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Dict, List

from e2d.pipelines.translate import PipelineResult, Stage

_MAIN_TF = """\
terraform {
  required_providers {
    dynatrace = {
      source  = "dynatrace-oss/dynatrace"
      version = ">= 1.70.0"
    }
  }
}

# OpenPipeline configuration uses an OAuth client (NOT an API token):
#   export DT_ENV_URL="https://<env-id>.apps.dynatrace.com"
#   export DT_CLIENT_ID="dt0s02.XXXX"
#   export DT_CLIENT_SECRET="dt0s02.XXXX.YYYY"
#   export DT_ACCOUNT_ID="<account-uuid>"
# Scopes: openpipeline:configurations:read, openpipeline:configurations:write
provider "dynatrace" {}
"""


def _hcl_str(s: str) -> str:
    # JSON string escaping matches HCL for `"` and `\`; guard interpolation sequences.
    return json.dumps(s).replace("${", "$${").replace("%{", "%%{")


def _ident(name: str, prefix: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9]+", "_", name).strip("_").lower() or "x"
    return f"{prefix}_{slug}"[:60]


def _processor_block(stage: Stage, pid: str, indent: str) -> List[str]:
    """One v2 `processor { type=..., ..., <type block> }` (or a comment)."""
    i, i2, i3 = indent, indent + "  ", indent + "    "
    if stage.kind == "manual":
        return [f"{i}# MANUAL ({pid}): {stage.description} — add an AppEngine function or drop"]
    if stage.kind == "note":
        return [f"{i}# {stage.description}"]

    ptype = "drop" if stage.kind == "drop" else "dql"
    lines = [f"{i}processor {{",
             f'{i2}type        = "{ptype}"',
             f'{i2}id          = {_hcl_str(pid)}']
    desc = stage.description or (stage.dql if stage.kind == "dql" else "drop matching records")
    lines.append(f"{i2}description = {_hcl_str(desc[:120])}")
    lines.append(f"{i2}enabled     = {'true' if stage.enabled else 'false'}")
    lines.append(f"{i2}matcher     = {_hcl_str(stage.matcher)}")
    if stage.kind == "dql":
        lines.append(f"{i2}dql {{")
        lines.append(f"{i3}script = {_hcl_str(stage.dql)}")
        lines.append(f"{i2}}}")
    lines.append(f"{i}}}")
    return lines


def generate_openpipeline_tf(name: str, res: PipelineResult, resource_name: str = "") -> Dict[str, str]:
    rn = resource_name or _ident(Path(name).stem, "logs")
    cid = (_ident(Path(name).stem, "pipeline") + "_tf")[:60]
    body: List[str] = [
        f'resource "dynatrace_openpipeline_v2_logs_pipelines" "{rn}" {{',
        f"  display_name = {_hcl_str(Path(name).stem[:100])}",
        f"  custom_id    = {_hcl_str(cid)}",
        "  processing {",
        "    processors {",
    ]
    counter = 0
    for stage in res.stages:
        if stage.kind in ("dql", "drop"):
            counter += 1
            body += _processor_block(stage, f"p{counter:03d}_{rn}"[:60], "      ")
        else:  # manual / note -> HCL comment
            body += _processor_block(stage, "", "      ")
    body += ["    }", "  }", "}", ""]
    return {"main.tf": _MAIN_TF, "pipeline.tf": "\n".join(body)}


_SETTINGS_SCHEMA = "builtin:openpipeline.logs.pipelines"


def generate_openpipeline_settings(name: str, res: PipelineResult) -> List[dict]:
    """Settings-API request body for the same pipeline — the no-Terraform path.

    One object of schema `builtin:openpipeline.logs.pipelines` (the schema that
    replaced the deprecated OpenPipeline configurations API); upload the file
    verbatim as the body of `POST {env}/api/v2/settings/objects`. The customId
    is suffixed `_api` so a Terraform deploy of the same pipeline never fights
    over the identifier. Manual/note stages have no JSON representation — the
    caller reports them so they are not silently lost.
    """
    rn = _ident(Path(name).stem, "logs")
    processors: List[dict] = []
    counter = 0
    for stage in res.stages:
        if stage.kind not in ("dql", "drop"):
            continue
        counter += 1
        desc = stage.description or (stage.dql if stage.kind == "dql" else "drop matching records")
        proc = {
            "id": f"p{counter:03d}_{rn}"[:60],
            "type": "drop" if stage.kind == "drop" else "dql",
            "description": desc[:120],
            "enabled": stage.enabled,
            "matcher": stage.matcher,
        }
        if stage.kind == "dql":
            proc["dql"] = {"script": stage.dql}
        processors.append(proc)
    value = {
        "customId": (_ident(Path(name).stem, "pipeline") + "_api")[:60],
        "displayName": Path(name).stem[:100],
        "metadataList": [],
        "processing": {"processors": processors},
    }
    return [{"schemaId": _SETTINGS_SCHEMA, "scope": "environment", "value": value}]


def write_openpipeline_tf(name: str, res: PipelineResult, out_dir: str) -> Dict[str, object]:
    files = generate_openpipeline_tf(name, res)
    d = Path(out_dir)
    d.mkdir(parents=True, exist_ok=True)
    for fname, content in files.items():
        (d / fname).write_text(content, encoding="utf-8")
    n_proc = sum(1 for s in res.stages if s.kind in ("dql", "drop"))
    return {"dir": str(d), "processors": n_proc, "files": list(files)}
