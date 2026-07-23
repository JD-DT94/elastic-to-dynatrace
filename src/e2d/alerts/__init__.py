"""Track E — Elastic Watchers and Kibana alerting rules -> Dynatrace.

An alert is, structurally, *a query + a threshold + a schedule + an action*. The
query half is already solved (and DQL-validated) by the query track, so this
track reuses it and adds the wrapper: it extracts the threshold, the evaluation
window, the grouping dimensions, and the notification action, then recommends
where the alert belongs in Dynatrace — a **Davis metric event**, a **log/custom
event on DQL**, or a **Workflow** for the cases that carry actions or chained
inputs.

The first increment emits the DQL plus a plain-English `*.alert.md` plan (the
same "plan before deployable artifact" pattern the pipeline track uses); emitting
a deployable Workflow / metric-event resource is a later step.
"""

from e2d.alerts.translate import translate_alert, render_alert, AlertResult

__all__ = ["translate_alert", "render_alert", "AlertResult"]
