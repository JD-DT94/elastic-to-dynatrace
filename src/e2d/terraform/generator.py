"""Emit a Terraform module that creates the converted dashboards as Dynatrace
Platform documents.

Layout produced in <out_dir>:

    main.tf                  provider + terraform blocks
    dashboards.tf            one `dynatrace_document` resource per dashboard
    documents/<name>.json    the dashboard content payload (referenced via file())

`terraform apply` (with DYNATRACE_ENV_URL + DYNATRACE_API_TOKEN in the env)
uploads them — so this single artifact is both the "config/terraform" and the
"upload to Dynatrace" path.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Tuple

PROVIDER_VERSION = ">= 1.70.0"

_MAIN_TF = f'''terraform {{
  required_providers {{
    dynatrace = {{
      source  = "dynatrace-oss/dynatrace"
      version = "{PROVIDER_VERSION}"
    }}
  }}
}}

# Authentication is read from the environment:
#   export DYNATRACE_ENV_URL="https://<env-id>.apps.dynatrace.com"
#   export DYNATRACE_API_TOKEN="dt0c01.XXXX..."   # platform token with
#                                                 # document:documents:write
provider "dynatrace" {{}}
'''


def _resource_name(name: str, used: set) -> str:
    base = re.sub(r"[^a-zA-Z0-9_]", "_", name).strip("_").lower()
    base = re.sub(r"_+", "_", base) or "dashboard"
    if base[0].isdigit():
        base = "d_" + base
    candidate = base
    i = 2
    while candidate in used:
        candidate = f"{base}_{i}"
        i += 1
    used.add(candidate)
    return candidate


def _hcl_escape(s: str) -> str:
    return s.replace("\\", "\\\\").replace('"', '\\"')


def generate_terraform(dashboards: List[Tuple[str, Dict[str, Any]]], out_dir: str) -> Dict[str, Any]:
    """dashboards: list of (display_name, dashboard_dict). Returns a summary."""
    out = Path(out_dir)
    docs = out / "documents"
    docs.mkdir(parents=True, exist_ok=True)

    (out / "main.tf").write_text(_MAIN_TF, encoding="utf-8")

    used: set = set()
    resources: List[str] = []
    for display_name, dashboard in dashboards:
        rname = _resource_name(display_name, used)
        # The Document API payload for a dashboard is its `content` object.
        content = dashboard.get("content", dashboard)
        (docs / f"{rname}.json").write_text(json.dumps(content, indent=2), encoding="utf-8")
        resources.append(
            f'resource "dynatrace_document" "{rname}" {{\n'
            f'  type    = "dashboard"\n'
            f'  name    = "{_hcl_escape(display_name)}"\n'
            f'  content = file("${{path.module}}/documents/{rname}.json")\n'
            f'}}\n'
        )

    (out / "dashboards.tf").write_text("\n".join(resources), encoding="utf-8")
    return {"resources": len(resources), "dir": str(out)}
