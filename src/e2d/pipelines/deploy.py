"""Drive `terraform` on a generated OpenPipeline module.

The validated deploy path for OpenPipeline is Terraform (see `tf.py`), so rather
than re-implement the OAuth + OpenPipeline config API, `e2d pipeline --apply`
shells out to the `terraform` CLI on the module we just wrote. Mirroring
`push`, it is a dry run (`terraform plan`) unless `--apply` is given.

`dynatrace_openpipeline_logs` authenticates with an OAuth client, so the
following must be present in the environment (consumed by the provider):
`DT_CLIENT_ID`, `DT_CLIENT_SECRET`, `DT_ACCOUNT_ID`, and an env URL
(`DT_ENV_URL` or `DYNATRACE_ENV_URL`).
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from typing import List

_OAUTH_VARS = ["DT_CLIENT_ID", "DT_CLIENT_SECRET", "DT_ACCOUNT_ID"]
_URL_VARS = ["DT_ENV_URL", "DYNATRACE_ENV_URL"]


def missing_env(env: dict) -> List[str]:
    """Required provider env vars that are absent/empty (URL counts once)."""
    missing = [v for v in _OAUTH_VARS if not env.get(v)]
    if not any(env.get(u) for u in _URL_VARS):
        missing.append("DT_ENV_URL")
    return missing


def terraform_steps(apply: bool) -> List[List[str]]:
    """The terraform commands to run: always init, then plan (dry-run) or apply."""
    steps = [["terraform", "init", "-input=false", "-no-color"]]
    if apply:
        steps.append(["terraform", "apply", "-auto-approve", "-input=false", "-no-color"])
    else:
        steps.append(["terraform", "plan", "-input=false", "-no-color"])
    return steps


def run_deploy(out_dir: str, apply: bool, env: dict) -> int:
    if shutil.which("terraform") is None:
        print("error: 'terraform' CLI not found on PATH; install it to use --apply.", file=sys.stderr)
        return 2
    missing = missing_env(env)
    if missing:
        msg = "missing provider credentials: " + ", ".join(missing)
        if apply:
            print(f"error: {msg} (required for --apply).", file=sys.stderr)
            return 2
        print(f"warning: {msg}; `terraform plan` will likely fail at provider auth.", file=sys.stderr)

    for cmd in terraform_steps(apply):
        print(f"\n$ {' '.join(cmd)}  (in {out_dir})", file=sys.stderr)
        rc = subprocess.run(cmd, cwd=out_dir).returncode
        if rc != 0:
            print(f"error: `{cmd[0]} {cmd[1]}` exited {rc}", file=sys.stderr)
            return rc
    return 0
