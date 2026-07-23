"""Deploy sinks — push converted artifacts to a Dynatrace tenant.

Only the Document API path (dashboards) is a direct API call; anomaly detectors,
workflows and pipelines deploy through their Terraform resources (the provider
handles the settings-object schema), so those are left to `terraform apply`.

Credentials are passed per-call and never persisted.
"""

from e2d.sinks.dynatrace import deploy_dashboards, push_dashboard

__all__ = ["deploy_dashboards", "push_dashboard"]
