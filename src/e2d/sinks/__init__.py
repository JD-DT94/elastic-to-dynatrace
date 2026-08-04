"""Deploy sinks — push converted artifacts to a Dynatrace tenant.

Dashboards go through the Document API and anomaly detectors through the
Settings Objects API (both direct calls, also exported as upload-ready JSON by
`migrate` when emit includes "json"); workflows deploy through their Terraform
resources, so those are left to `terraform apply`.

Credentials are passed per-call and never persisted.
"""

from e2d.sinks.dynatrace import deploy_dashboards, push_dashboard

__all__ = ["deploy_dashboards", "push_dashboard"]
