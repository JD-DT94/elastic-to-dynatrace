"""AppDynamics custom dashboards -> Dynatrace dashboard documents.

The AppD widget JSON schema is not published anywhere, and exports differ
between Controller versions and between classic Custom Dashboards and Dash
Studio. So this reads **defensively**: it looks for widgets under any of the
container keys AppD is known to use, pulls geometry and titles through tolerant
lookups, and finds metric bindings by walking the widget subtree for
`metricPath`-shaped keys rather than following a fixed path into it.

The trade-off is deliberate. A rigid parser tuned to one export either crashes
or silently produces an empty dashboard on the next Controller version; this one
degrades to a placeholder tile carrying the original widget type and metric
path, so nothing disappears without being named in the report.

Output is the same bare content document the Kibana track emits, so the
Document API push, Terraform `dynatrace_document` and the field audit all work
unchanged.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

from e2d.appd import metrics as appd_metrics
from e2d.dql.validate import lint_into_report
from e2d.report import Report

DASHBOARD_VERSION = 21
DT_GRID_WIDTH = 24
# AppD canvases are laid out in pixels. 1200px is the common default width; the
# real width is read from the export when present.
DEFAULT_CANVAS_WIDTH = 1200
DEFAULT_ROW_PX = 40          # px per Dynatrace grid row

# Widget type -> Dynatrace visualization. Anything absent becomes a placeholder
# tile with an explanatory note rather than a wrong chart.
_WIDGET_VIZ: Dict[str, str] = {
    "graphwidget": "lineChart",
    "timeseriesgraphwidget": "lineChart",
    "linegraphwidget": "lineChart",
    "areagraphwidget": "areaChart",
    "stackedareawidget": "areaChart",
    "barchartwidget": "barChart",
    "columnchartwidget": "barChart",
    "piewidget": "pieChart",
    "piechartwidget": "pieChart",
    "metriclabelwidget": "singleValue",
    "numberwidget": "singleValue",
    "gaugewidget": "singleValue",
    "scatterplotwidget": "scatterPlot",
    "tablewidget": "table",
    "gridwidget": "table",
}

# Widget types that carry no metric binding at all.
_TEXT_WIDGETS = {"textwidget", "richtextwidget", "labelwidget", "imagewidget", "iframewidget"}

# Widget types that render AppD-specific topology/health UI with no Dynatrace
# tile equivalent — named explicitly so the report can say what to build instead.
_NO_EQUIVALENT: Dict[str, str] = {
    "healthlistwidget": "an AppD health list. Use a Dynatrace problem feed tile or a DQL "
                        "query over `fetch events | filter event.kind == \"DAVIS_PROBLEM\"`.",
    "eventlistwidget": "an AppD event list. Query events directly with DQL.",
    "analyticswidget": "an AppD Analytics (ADQL) widget. Rewrite the ADQL as DQL — the "
                       "underlying data is usually logs or business events in Dynatrace.",
    "flowmapwidget": "an AppD flow map. Dynatrace builds service flow automatically; use "
                     "the Service flow / Smartscape views rather than a dashboard tile.",
    "applicationflowmapwidget": "an AppD flow map. Dynatrace builds this automatically.",
    "sunburstwidget": "an AppD sunburst. No direct Dynatrace tile equivalent.",
}


def _get(d: Any, *names, default=None):
    if not isinstance(d, dict):
        return default
    for n in names:
        if n in d:
            return d[n]
        for k in d:
            if k.lower() == n.lower():
                return d[k]
    return default


def _widgets(doc: dict) -> List[dict]:
    """Widgets, from whichever container this export version used."""
    for key in ("widgetTemplates", "widgets", "widgetList", "dashboardWidgetTemplates"):
        items = _get(doc, key)
        if isinstance(items, list) and items:
            return [w for w in items if isinstance(w, dict)]
    return []


def _collect_metric_paths(node: Any, found: Optional[List[str]] = None) -> List[str]:
    """Every metric-path string anywhere in a widget subtree.

    Walking rather than indexing is what makes this survive schema drift: the
    key has lived at several depths across versions and under both
    `metricExpressionTemplate` and `metricMatchCriteriaTemplate`.
    """
    if found is None:
        found = []
    if isinstance(node, dict):
        for key, value in node.items():
            if key.lower() in ("metricpath", "metricpathtemplate") and isinstance(value, str):
                if value.strip():
                    found.append(value.strip())
            else:
                _collect_metric_paths(value, found)
    elif isinstance(node, list):
        for item in node:
            _collect_metric_paths(item, found)
    return list(dict.fromkeys(found))


def _series_names(widget: dict) -> List[str]:
    out = []
    for series in (_get(widget, "dataSeriesTemplates", "dataSeries", default=[]) or []):
        if isinstance(series, dict):
            name = _get(series, "name", "seriesName", "displayName")
            if name:
                out.append(str(name))
    return out


def _layout(widget: dict, canvas_width: int, index: int) -> Dict[str, int]:
    """AppD pixel geometry -> Dynatrace 24-column grid."""
    try:
        px_x = float(_get(widget, "x", default=0) or 0)
        px_y = float(_get(widget, "y", default=0) or 0)
        px_w = float(_get(widget, "width", default=0) or 0)
        px_h = float(_get(widget, "height", default=0) or 0)
    except (TypeError, ValueError):
        px_x = px_y = px_w = px_h = 0

    if px_w <= 0 or canvas_width <= 0:
        # No usable geometry: fall back to a readable two-per-row flow.
        return {"x": (index % 2) * 12, "y": (index // 2) * 6, "w": 12, "h": 6}

    scale = DT_GRID_WIDTH / float(canvas_width)
    x = max(0, int(round(px_x * scale)))
    w = max(1, int(round(px_w * scale)))
    if x >= DT_GRID_WIDTH:
        x = 0
    if x + w > DT_GRID_WIDTH:
        w = DT_GRID_WIDTH - x
    y = max(0, int(round(px_y / DEFAULT_ROW_PX)))
    h = max(2, int(round((px_h or DEFAULT_ROW_PX * 4) / DEFAULT_ROW_PX)))
    return {"x": x, "y": y, "w": max(1, w), "h": h}


def _dql_for_paths(paths: List[str], report: Report,
                   widget_title: str) -> Tuple[Optional[str], List[str]]:
    """Build a tile query from a widget's metric paths.

    Returns `(dql, unmapped_reasons)`. Several mapped paths become several
    series in one `timeseries`, which is how AppD multi-series graphs read.
    """
    series: List[str] = []
    unmapped: List[str] = []
    interval_note = False
    for i, path in enumerate(paths):
        mapping, reason = appd_metrics.resolve(path)
        if mapping is None:
            unmapped.append(f"`{path}` — {reason}")
            continue
        alias = _alias_for(path, i)
        if mapping.aggregation == "percentile":
            pct = 99 if "99" in mapping.note else 95
            series.append(f"{alias} = percentile({mapping.dt_metric}, {pct})")
            interval_note = True
        else:
            series.append(f"{alias} = {mapping.aggregation}({mapping.dt_metric})")
        if mapping.rescales:
            report.info(
                f"Tile `{widget_title}`: `{appd_metrics.leaf_of(path)}` is "
                f"{mapping.source_unit} in AppD and {mapping.dt_unit} in Dynatrace. The chart "
                "is correct, but any axis label or threshold copied from AppD needs rescaling.")
    if not series:
        return None, unmapped
    dql = "timeseries " + ", ".join(series)
    if interval_note:
        dql += ", rollup: avg"
    return dql, unmapped


def _alias_for(path: str, index: int) -> str:
    leaf = appd_metrics.leaf_of(path) or f"series_{index}"
    alias = re.sub(r"[^A-Za-z0-9]+", "_", leaf).strip("_").lower()
    alias = re.sub(r"_+", "_", alias)
    if not alias or alias[0].isdigit():
        alias = f"s{index}_{alias}".rstrip("_")
    return alias[:40] or f"series_{index}"


def _safe_filename(name: str) -> str:
    keep = "".join(c if (c.isalnum() or c in " -_.,()[]&+'@!") else "_" for c in name)
    return re.sub(r"_+", "_", keep).strip() or "dashboard"


def convert_appd_dashboard(text_or_doc, name: Optional[str] = None):
    """Convert one AppD dashboard export.

    Returns `(dashboard_content, report, title)` where `dashboard_content` is
    the bare Dynatrace content document (importable via the Dashboards app and
    pushable through the Document API).
    """
    import json

    report = Report()
    doc = json.loads(text_or_doc) if isinstance(text_or_doc, (str, bytes)) else text_or_doc
    if isinstance(doc, list):
        if len(doc) > 1:
            report.info(f"Export holds {len(doc)} dashboards; converting the first. Export each "
                        "dashboard to its own file to convert them all.")
        doc = doc[0] if doc else {}
    if not isinstance(doc, dict):
        doc = {}

    title = str(_get(doc, "name", "title", "dashboardName", default=None) or name or "AppD dashboard")
    canvas_width = _get(doc, "width", "canvasWidth", default=None)
    try:
        canvas_width = int(canvas_width) if canvas_width else DEFAULT_CANVAS_WIDTH
    except (TypeError, ValueError):
        canvas_width = DEFAULT_CANVAS_WIDTH
    if canvas_width <= 0:
        canvas_width = DEFAULT_CANVAS_WIDTH

    widgets = _widgets(doc)
    if not widgets:
        report.manual(
            "No widgets found in this export. Confirm it came from "
            "`CustomDashboardImportExportServlet?dashboardId=<id>` (or the UI's dashboard "
            "Export) rather than a dashboard list response.")

    tiles: Dict[str, Any] = {}
    layouts: Dict[str, Any] = {}

    for index, widget in enumerate(widgets):
        tile_id = str(index)
        wtype = str(_get(widget, "widgetType", "type", default="") or "").lower().replace(" ", "")
        wtitle = str(_get(widget, "title", "label", "name", default="") or "").strip()
        grid = _layout(widget, canvas_width, index)

        # -- text / static widgets ------------------------------------------ #
        if wtype in _TEXT_WIDGETS:
            content = (_get(widget, "text", "html", "markdown", "content", default="") or "")
            content = re.sub(r"<[^>]+>", "", str(content)).strip()
            tiles[tile_id] = {"type": "markdown",
                              "content": content or (f"### {wtitle}" if wtitle else "")}
            layouts[tile_id] = grid
            continue

        paths = _collect_metric_paths(widget)
        display_title = wtitle or (" / ".join(_series_names(widget)) or f"Widget {index + 1}")

        # -- widgets with no Dynatrace tile equivalent ----------------------- #
        if wtype in _NO_EQUIVALENT:
            report.manual(
                f"Tile `{display_title}` is {_NO_EQUIVALENT[wtype]}")
            tiles[tile_id] = {
                "type": "markdown",
                "content": (f"### {display_title}\n\n_Not migrated automatically._\n\n"
                            f"AppD widget type `{_get(widget, 'widgetType', default=wtype)}` — "
                            f"{_NO_EQUIVALENT[wtype]}"),
            }
            layouts[tile_id] = grid
            continue

        if not paths:
            report.warn(
                f"Tile `{display_title}` (AppD `{_get(widget, 'widgetType', default=wtype) or 'unknown'}`) "
                "has no metric path in the export, so there is nothing to query. It is kept as a "
                "placeholder — rebuild it by hand if the tile mattered.")
            tiles[tile_id] = {"type": "markdown",
                              "content": f"### {display_title}\n\n_No metric binding found in "
                                         f"the AppD export; rebuild this tile manually._"}
            layouts[tile_id] = grid
            continue

        dql, unmapped = _dql_for_paths(paths, report, display_title)
        for reason in unmapped:
            report.manual(f"Tile `{display_title}` reads {reason}")

        if dql is None:
            tiles[tile_id] = {
                "type": "markdown",
                "content": (f"### {display_title}\n\n_Metrics could not be mapped automatically._\n\n"
                            + "\n".join(f"- `{p}`" for p in paths)),
            }
            layouts[tile_id] = grid
            continue

        visualization = _WIDGET_VIZ.get(wtype, "lineChart")
        if wtype not in _WIDGET_VIZ:
            report.info(
                f"Tile `{display_title}`: AppD widget type "
                f"`{_get(widget, 'widgetType', default=wtype) or 'unknown'}` is unrecognised; "
                "rendered as a line chart. Change the visualization in the tile if that is wrong.")

        lint_into_report(dql, report)
        tiles[tile_id] = {
            "type": "data",
            "title": display_title,
            "query": dql,
            "visualization": visualization,
            "visualizationSettings": {},
            "querySettings": {},
        }
        layouts[tile_id] = grid

    if tiles:
        report.warn(
            "AppD tiles were scoped by application/tier/business-transaction name. The converted "
            "queries are NOT entity-scoped — each one charts its metric across everything "
            "reporting it. Add a filter (or a dashboard variable) for the migrated services "
            "before anyone reads these numbers as if they were the AppD originals.")

    content = {
        "version": DASHBOARD_VERSION,
        "variables": [],
        "tiles": tiles,
        "layouts": layouts,
    }
    return content, report, title
