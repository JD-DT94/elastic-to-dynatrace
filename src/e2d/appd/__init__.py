"""AppDynamics -> Dynatrace conversion.

The second source product. Everything downstream of the translation — the
`AlertSpec` model, Davis-detector Terraform/Settings emission, dashboard
document push, the report, the scorecard and the deployment plan — is shared
with the Elastic track; only the front ends in this package are AppD-specific.

Extraction reality (drives what each module assumes it will be handed):

* Health rules, policies, actions and the application/tier/node inventory have
  documented Controller REST APIs and stable JSON.
* Custom dashboards export **by ID only** through an undocumented servlet, and
  the widget JSON schema is not published anywhere. `dashboards.py` therefore
  reads defensively rather than assuming a fixed shape.
"""

from e2d.appd.health_rules import translate_health_rule
from e2d.appd.dashboards import convert_appd_dashboard
from e2d.appd.inventory import translate_inventory, render_onboarding_plan
from e2d.appd.policies import translate_policies

__all__ = [
    "translate_health_rule",
    "convert_appd_dashboard",
    "translate_inventory",
    "render_onboarding_plan",
    "translate_policies",
]
