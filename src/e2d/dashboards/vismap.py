"""Map a Kibana visualization type + structural hint to a Dynatrace Platform
visualization id."""

from __future__ import annotations

# Kibana viz type -> default Dynatrace visualization (overridden by structure below)
_BASE = {
    "metric": "singleValue",
    "metrics": "singleValue",
    "table": "table",
    "pie": "pieChart",
    "donut": "donutChart",
    "horizontal_bar": "categoricalBarChart",
    "histogram": "categoricalBarChart",
    "line": "lineChart",
    "area": "areaChart",
    "gauge": "gauge",
    "heatmap": "heatmap",
    "tagcloud": "table",
}


def dt_visualization(kibana_type: str, viz_hint: str) -> str:
    """Resolve the Dynatrace visualization id.

    `viz_hint` from the agg plan ('lineChart' for time series, 'categorical',
    'single', 'table') takes priority because the data shape — not the original
    chart style — determines what renders.
    """
    if viz_hint == "lineChart":
        # time-series data: keep area/bar style if the original was such
        if kibana_type in ("area",):
            return "areaChart"
        if kibana_type in ("horizontal_bar", "histogram"):
            return "barChart"
        return "lineChart"
    if viz_hint == "single":
        return "singleValue"
    if viz_hint == "categorical":
        if kibana_type in ("pie",):
            return "pieChart"
        if kibana_type in ("donut",):
            return "donutChart"
        return "categoricalBarChart"
    return _BASE.get(kibana_type, "table")
