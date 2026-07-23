"""Assemble a Dynatrace Platform dashboard JSON from a Kibana dashboard.

Pipeline per panel:
  1. extract the visualization (inline savedVis or by-reference saved object)
  2. resolve its index pattern -> Dynatrace data object
  3. translate searchSource (KQL query + filter[]) -> base `filter`
  4. translate aggs -> summarize / makeTimeseries body
  5. choose a Dynatrace visualization and build the `data` tile + layout

Markdown panels become markdown tiles. Lens and TSVB panels get dedicated
converters (lens.py / tsvb.py). Kibana controls — legacy input_control_vis and
the modern dashboard-level controlGroupInput — become multi-select query
variables that are spliced into same-data-object tiles as
`filter in(field, array($Var))`. Vega and map panels become placeholder tiles
flagged for manual review.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from e2d.config import MappingConfig
from e2d.dashboards.aggs import build_agg_plan, translate_search_filters
from e2d.dashboards.field_audit import audit_dashboard_fields, render_field_manifest
from e2d.dashboards.kibana_loader import KibanaExport, SavedObject, _maybe_json
from e2d.dashboards.kql import translate_kql
from e2d.dashboards.tsvb import convert_tsvb
from e2d.dashboards.vismap import dt_visualization
from e2d.dql.validate import lint_into_report
from e2d.report import Report

DASHBOARD_VERSION = 21
KIBANA_GRID_WIDTH = 48
DT_GRID_WIDTH = 24
_SCALE = DT_GRID_WIDTH / KIBANA_GRID_WIDTH  # 0.5


@dataclass
class VizSpec:
    kibana_type: str
    aggs: List[Dict[str, Any]]
    query: str                      # KQL query string
    filters: List[Dict[str, Any]]   # ES filter DSL meta entries
    index_title: Optional[str]
    title: str
    colors: Dict[str, str] = None   # uiState `vis.colors`: series label -> color
    raw_params: Dict[str, Any] = None  # savedVis/visState params (Vega spec etc.)


def _ui_colors(container: Dict[str, Any], key: str) -> Dict[str, str]:
    ui = container.get(key)
    if isinstance(ui, dict):
        colors = (ui.get("vis") or {}).get("colors")
        if isinstance(colors, dict):
            return {str(k): str(v) for k, v in colors.items()}
    return {}


# --------------------------------------------------------------------------- #
# extraction
# --------------------------------------------------------------------------- #

def _search_source(obj_attrs_or_data: Dict[str, Any]) -> Tuple[str, List[Dict[str, Any]]]:
    """Pull (kuery query, filter[]) out of a searchSource-bearing structure."""
    ss = obj_attrs_or_data
    if "kibanaSavedObjectMeta" in ss:
        ss = ss.get("kibanaSavedObjectMeta", {}).get("searchSourceJSON", {})
    elif "searchSource" in ss:
        ss = ss.get("searchSource", {})
    if not isinstance(ss, dict):
        return "", []
    q = ss.get("query", {})
    query = q.get("query", "") if isinstance(q, dict) else ""
    return query, ss.get("filter", []) or []


def _index_title_from_refs(refs: List[Dict[str, Any]], export: KibanaExport) -> Optional[str]:
    for r in refs:
        if r.get("type") == "index-pattern":
            ip = export.resolve(r.get("id"))
            if ip:
                return ip.attributes.get("title")
    return None


def extract_inline(saved_vis: Dict[str, Any], panel_refs: List[Dict[str, Any]],
                   export: KibanaExport) -> VizSpec:
    data = saved_vis.get("data", {}) or {}
    query, filters = _search_source(data)
    return VizSpec(
        kibana_type=saved_vis.get("type", "?"),
        aggs=data.get("aggs", []) or [],
        query=query,
        filters=filters,
        index_title=_index_title_from_refs(panel_refs, export),
        title=saved_vis.get("title", "") or "",
        colors=_ui_colors(saved_vis, "uiState"),
        raw_params=saved_vis.get("params") or {},
    )


def extract_referenced(obj: SavedObject, export: KibanaExport) -> Optional[VizSpec]:
    if obj.type == "visualization":
        vs = obj.attributes.get("visState", {})
        if isinstance(vs, str):  # safety: should be decoded already
            vs = json.loads(vs)
        query, filters = _search_source(obj.attributes)
        return VizSpec(
            kibana_type=vs.get("type", "?"),
            aggs=vs.get("aggs", []) or [],
            query=query,
            filters=filters,
            index_title=_index_title_from_refs(obj.references, export),
            title=vs.get("title") or obj.title,
            colors=_ui_colors(obj.attributes, "uiStateJSON"),
            raw_params=vs.get("params") or {},
        )
    if obj.type == "search":
        query, filters = _search_source(obj.attributes)
        return VizSpec(
            kibana_type="table", aggs=[], query=query, filters=filters,
            index_title=_index_title_from_refs(obj.references, export),
            title=obj.title,
        )
    return None  # lens / unknown handled by caller


# --------------------------------------------------------------------------- #
# DQL assembly
# --------------------------------------------------------------------------- #

def _data_object(spec: VizSpec, config: MappingConfig, report: Report) -> str:
    if spec.index_title:
        do = config.resolve_data_object(spec.index_title)
        if do and do != "__metrics__":
            return do
        if do is None:
            report.warn(
                f"Index `{spec.index_title}` did not match any data-object rule; defaulting to `logs`. "
                "Add an index_map rule.", source=spec.index_title)
    else:
        report.warn("No index pattern resolved for panel; defaulting data object to `logs`.")
    return "logs"


def build_dql(spec: VizSpec, config: MappingConfig, report: Report) -> Tuple[str, str]:
    """Return (dql, viz_hint)."""
    data_object = _data_object(spec, config, report)
    lines = [f"fetch {data_object}"]

    # base filter from KQL query + ES filter DSL
    preds: List[str] = []
    if spec.query.strip():
        kql = translate_kql(spec.query, config, data_object, report)
        if kql:
            preds.append(kql)
    preds.extend(translate_search_filters(spec.filters, config, data_object, report))
    if preds:
        lines.append("filter " + " and ".join(f"({p})" if " or " in p else p for p in preds))

    if not spec.aggs:
        # saved search / table: just show records
        lines.append("limit 100")
        dql = _join(lines)
        lint_into_report(dql, report, data_object)
        return dql, "table"

    plan = build_agg_plan(spec.aggs, config, data_object, report)
    metrics = ", ".join(plan.metrics)
    if plan.mode == "makeTimeseries":
        body = f"makeTimeseries {{{metrics}}}, interval: {plan.interval}"
        if plan.by_fields:
            body += f", by: {{{', '.join(plan.by_fields)}}}"
        lines.append(body)
        lines.extend(plan.post)
    else:  # summarize / single
        body = f"summarize {metrics}"
        if plan.by_fields:
            body += f", by: {{{', '.join(plan.by_fields)}}}"
        lines.append(body)
        lines.extend(plan.post)
        if plan.sort:
            alias, order = plan.sort
            lines.append(f"sort {alias} {order}")
        if plan.limit:
            lines.append(f"limit {plan.limit}")
    dql = _join(lines)
    lint_into_report(dql, report, data_object)
    return dql, plan.viz_hint


def _join(lines: List[str]) -> str:
    out = lines[0]
    for ln in lines[1:]:
        out += "\n| " + ln
    return out


# --------------------------------------------------------------------------- #
# layout + tiles
# --------------------------------------------------------------------------- #

def _scale_layout(grid: Dict[str, Any]) -> Dict[str, int]:
    x = int(round(grid.get("x", 0) * _SCALE))
    w = max(1, int(round(grid.get("w", KIBANA_GRID_WIDTH) * _SCALE)))
    y = int(round(grid.get("y", 0) * _SCALE))
    h = max(2, int(round(grid.get("h", 15) * _SCALE)))
    if x + w > DT_GRID_WIDTH:
        w = DT_GRID_WIDTH - x
    return {"x": x, "y": y, "w": max(1, w), "h": h}


# --------------------------------------------------------------------------- #
# dashboard conversion
# --------------------------------------------------------------------------- #

# Dynatrace magic default for multi-select query variables: "all values selected".
_ALL_SELECTED = "3420b2ac-f1cf-4b24-b62d-61ba1ba8ed05*"


def _variable_from_field(field: str, label: Optional[str], data_object: str,
                         config: MappingConfig) -> Tuple[Dict[str, Any], str]:
    """Build a query variable for a Kibana control. Returns (variable, mapped field).

    Kibana controls do not filter until a value is picked, so every control
    becomes a multi-select with the all-selected default — the only Dynatrace
    shape that also shows everything until narrowed.
    """
    if field.endswith(".keyword"):
        field = field[: -len(".keyword")]
    label = (label or "").strip()
    if label.endswith(".keyword"):
        label = label[: -len(".keyword")]
    key = "".join(c if (c.isalnum() or c == "_") else "_"
                  for c in (label or field)).strip("_") or "var"
    mapped = config.resolve_field(field, data_object)
    var = {
        "version": 2, "key": key, "type": "query", "visible": True, "editable": True,
        "input": f'fetch {data_object} | filter isNotNull({mapped}) | filter {mapped} != "" '
                 f"| dedup {mapped} | fields {mapped} | sort {mapped} asc",
        "multiple": True,
        "defaultValue": _ALL_SELECTED,
    }
    return var, mapped


def _control_data_object(index_pattern_id: Optional[str], export: KibanaExport,
                         config: MappingConfig) -> str:
    title = None
    ip = export.resolve(index_pattern_id)
    if ip is not None:
        title = ip.attributes.get("title")
    if title:
        do = config.resolve_data_object(title)
        if do and do != "__metrics__":
            return do
    return "logs"


def _apply_variable_filters(tiles: Dict[str, Any],
                            var_filters: List[Tuple[str, str, str]]) -> None:
    """Splice `filter in(field, array($Key))` into each data tile on the same
    data object, right after `fetch` (before any aggregation)."""
    for key, mapped, data_object in var_filters:
        for tile in tiles.values():
            if tile.get("type") != "data":
                continue
            parts = tile["query"].split("\n| ")
            if parts[0] != f"fetch {data_object}":
                continue
            parts.insert(1, f"filter in({mapped}, array(${key}))")
            tile["query"] = "\n| ".join(parts)


def _convert_control_group(attrs: Dict[str, Any], refs_by_name: Dict[str, Any],
                           export: KibanaExport, config: MappingConfig, report: Report,
                           variables: List[Dict[str, Any]], seen_var_keys: set,
                           var_filters: List[Tuple[str, str, str]]) -> None:
    """Modern dashboard-level Controls (`controlGroupInput`) -> variables."""
    cgi = attrs.get("controlGroupInput")
    if not isinstance(cgi, dict):
        return
    panels = _maybe_json(cgi.get("panelsJSON")) or {}
    if not isinstance(panels, dict):
        return
    for cid, cp in panels.items():
        ctype = cp.get("type", "")
        ei = cp.get("explicitInput", {}) or {}
        field = ei.get("fieldName", "")
        label = ei.get("title") or ei.get("label")
        if ctype == "timeSliderControl":
            report.info("Time-slider control dropped; use the dashboard timeframe selector.")
            continue
        if not field:
            continue
        if ctype == "rangeSliderControl":
            report.manual(f"Range-slider control on `{field}` has no variable equivalent; "
                          "add a text variable + `filter {f} >= $min` clauses manually."
                          .format(f=field), source=field)
            continue
        # optionsListControl (and anything options-list shaped)
        ref = (refs_by_name.get(f"controlGroup_{cid}:optionsListDataView")
               or refs_by_name.get(f"controlGroup_{cid}:optionsListControlDataView"))
        data_object = _control_data_object(ref.get("id") if ref else None, export, config)
        var, mapped = _variable_from_field(field, label, data_object, config)
        if var["key"] not in seen_var_keys:
            variables.append(var)
            seen_var_keys.add(var["key"])
            var_filters.append((var["key"], mapped, data_object))


def _tsvb_index_title(params: Dict[str, Any], panel: Dict[str, Any],
                      refs_by_name: Dict[str, Any], refs: List[Dict[str, Any]],
                      export: KibanaExport) -> Optional[str]:
    """Resolve a TSVB panel's index pattern: an inline string, an inline
    ``{id}`` object, or an ``index_pattern_ref_name`` reference."""
    ip = params.get("index_pattern")
    if isinstance(ip, str) and ip.strip():
        return ip.strip()
    if isinstance(ip, dict) and ip.get("id"):
        obj = export.resolve(ip["id"])
        if obj is not None:
            return obj.attributes.get("title")
    ref_name = params.get("index_pattern_ref_name")
    if ref_name:
        ref = refs_by_name.get(ref_name) \
            or refs_by_name.get(f"{panel.get('panelIndex')}:{ref_name}")
        if ref is None:
            ref = next((r for r in refs_by_name.values()
                        if str(r.get("name", "")).endswith(":" + ref_name)), None)
        if ref is not None:
            obj = export.resolve(ref.get("id"))
            if obj is not None:
                return obj.attributes.get("title")
    return _index_title_from_refs(refs, export)


def _tsvb_tile(params: Dict[str, Any], index_title: Optional[str], title: str,
               config: MappingConfig, report: Report) -> Dict[str, Any]:
    res = convert_tsvb(params, config, report, index_title=index_title)
    if res["kind"] == "markdown":
        content = res["content"]
        if title and not content.lstrip().startswith("#"):
            content = f"### {title}\n\n{content}"
        return {"type": "markdown", "content": content}
    lint_into_report(res["dql"], report, res.get("data_object", "logs"))
    return {
        "type": "data", "title": title,
        "query": res["dql"], "visualization": res["visualization"],
        "visualizationSettings": res.get("settings") or {}, "querySettings": {},
    }


def _resolve_panel_ref(panel: Dict[str, Any], refs_by_name: Dict[str, Any],
                       export: KibanaExport) -> Optional[SavedObject]:
    """Resolve a panel's referenced saved object.

    Kibana names panel references either as the bare `panelRefName` or, commonly,
    prefixed with the panel index (`<panelIndex>:<panelRefName>`). Try both, then
    a suffix match, before giving up.
    """
    name = panel.get("panelRefName")
    if not name:
        return None
    ref = refs_by_name.get(name)
    if ref is None:
        ref = refs_by_name.get(f"{panel.get('panelIndex')}:{name}")
    if ref is None:
        for n, r in refs_by_name.items():
            if n == name or n.endswith(":" + name):
                ref = r
                break
    return export.resolve(ref.get("id")) if ref else None


def convert_dashboard(dash: SavedObject, export: KibanaExport, config: MappingConfig
                      ) -> Tuple[Dict[str, Any], Report]:
    report = Report()
    attrs = dash.attributes
    panels = attrs.get("panelsJSON", []) or []
    if not isinstance(panels, list):
        report.warn("The dashboard's panel list could not be read (malformed panelsJSON); "
                    "an empty dashboard was emitted — re-export it from Kibana.")
        panels = []
    panels = [p for p in panels if isinstance(p, dict)]
    refs_by_name = {r.get("name"): r for r in dash.references}

    tiles: Dict[str, Any] = {}
    layouts: Dict[str, Any] = {}
    variables: List[Dict[str, Any]] = []
    seen_var_keys: set = set()
    var_filters: List[Tuple[str, str, str]] = []  # (key, mapped field, data object)
    counter = 0

    # Kibana pins this dashboard to a saved time range; Dynatrace stores the
    # default timeframe outside the exportable document, so surface it.
    if attrs.get("timeRestore") and (attrs.get("timeFrom") or attrs.get("timeTo")):
        report.warn(f"Kibana opens this dashboard on a saved time range "
                    f"({attrs.get('timeFrom', '?')} → {attrs.get('timeTo', 'now')}). "
                    "Set the dashboard's default timeframe in Dynatrace after import "
                    "(timeframe selector → set as default).")

    for panel in panels:
        counter += 1
        tile_id = str(panel.get("panelIndex") or counter)
        grid = panel.get("gridData", {})
        panel_type = panel.get("type")
        ec = panel.get("embeddableConfig", {})

        # drilldowns (dynamic actions) have no automatic equivalent — flag them
        events = ((ec.get("enhancements") or {}).get("dynamicActions") or {}).get("events") or []
        if events:
            names = [((e.get("action") or {}).get("config") or {}).get("name") or "drilldown"
                     for e in events]
            report.warn(f"Panel `{ec.get('title') or tile_id}` has {len(events)} drilldown(s) "
                        f"({', '.join(names[:3])}{'…' if len(names) > 3 else ''}) that were not "
                        "carried over — recreate them as tile links "
                        "(tile → Edit → Link) or markdown links.")
        saved_vis = ec.get("savedVis")
        saved_vis_type = saved_vis.get("type") if saved_vis else None

        # markdown
        if saved_vis_type == "markdown":
            md = saved_vis.get("params", {}).get("markdown", "")
            tiles[tile_id] = {"type": "markdown", "content": md}
            layouts[tile_id] = _scale_layout(grid)
            continue

        # controls -> variables (wired into same-data-object tiles after the loop)
        if saved_vis_type == "input_control_vis":
            for ctrl in saved_vis.get("params", {}).get("controls", []):
                field = ctrl.get("fieldName", "")
                if not field:
                    continue
                data_object = _control_data_object(ctrl.get("indexPattern"), export, config)
                var, mapped = _variable_from_field(field, ctrl.get("label"), data_object, config)
                if var["key"] not in seen_var_keys:
                    variables.append(var)
                    seen_var_keys.add(var["key"])
                    var_filters.append((var["key"], mapped, data_object))
            continue

        # TSVB (inline savedVis type `metrics`) -> real DQL tile
        if saved_vis_type == "metrics":
            params = saved_vis.get("params", {}) or {}
            title = (ec.get("title") or saved_vis.get("title") or params.get("id")
                     or f"Panel {tile_id}")
            idx = _tsvb_index_title(params, panel, refs_by_name, dash.references, export)
            tiles[tile_id] = _tsvb_tile(params, idx, title, config, report)
            layouts[tile_id] = _scale_layout(grid)
            continue

        # maps have no automatic conversion; flag with the Dynatrace rebuild targets
        if panel_type == "map" or saved_vis_type in ("region_map", "tile_map"):
            title = ec.get("title") or (saved_vis.get("title") if saved_vis else "") \
                or f"Panel {tile_id}"
            report.manual(f"Map panel `{title}` needs manual rebuild — Dynatrace offers "
                          "choroplethMap/dotMap/bubbleMap visualizations; emitted a placeholder.",
                          source=title)
            tiles[tile_id] = {"type": "markdown",
                              "content": f"### {title}\n\n_Map visualization — rebuild manually "
                                         "(choroplethMap / dotMap / bubbleMap)._"}
            layouts[tile_id] = _scale_layout(grid)
            continue

        # resolve the visualization spec
        spec: Optional[VizSpec] = None
        # Lens is embedded inline (panel.type == 'lens' with
        # embeddableConfig.attributes) or referenced as a `lens` saved object.
        lens_attrs: Optional[dict] = None
        lens_refs: list = dash.references
        is_lens = panel_type == "lens" or (bool(ec.get("attributes")) and not saved_vis)
        if is_lens:
            lens_attrs = ec.get("attributes")            # inline Lens
            if not lens_attrs and panel.get("panelRefName"):
                target = _resolve_panel_ref(panel, refs_by_name, export)  # by-reference Lens
                if target is not None and target.type == "lens":
                    lens_attrs = target.attributes
                    lens_refs = target.references
        if not is_lens and saved_vis:
            spec = extract_inline(saved_vis, dash.references, export)
        elif not is_lens and panel.get("panelRefName"):
            target = _resolve_panel_ref(panel, refs_by_name, export)
            if target is None:
                report.warn(f"Panel reference `{panel['panelRefName']}` not in this export; skipped. "
                            "Re-export including related objects to convert it.")
                continue
            if target.type == "lens":
                is_lens = True
                lens_attrs = target.attributes
                lens_refs = target.references
            else:
                vs = target.attributes.get("visState", {})
                if isinstance(vs, dict) and vs.get("type") == "metrics":
                    # by-reference TSVB visualization
                    params = vs.get("params", {}) or {}
                    title = ec.get("title") or vs.get("title") or target.title
                    idx = _tsvb_index_title(params, panel, refs_by_name,
                                            target.references, export)
                    tiles[tile_id] = _tsvb_tile(params, idx, title, config, report)
                    layouts[tile_id] = _scale_layout(grid)
                    continue
                spec = extract_referenced(target, export)

        title = (ec.get("title") or (spec.title if spec else "")
                 or (lens_attrs.get("title") if lens_attrs else "") or f"Panel {tile_id}")

        # Lens -> real DQL tile (Track B); placeholder only if it can't be read.
        if is_lens:
            if lens_attrs and lens_attrs.get("state"):
                from e2d.dashboards.lens import convert_lens
                idx = _index_title_from_refs(lens_refs, export)
                dql, visualization, lens_title, lens_settings = \
                    convert_lens(lens_attrs, lens_refs, idx, config, report)
                tiles[tile_id] = {
                    "type": "data", "title": ec.get("title") or lens_title or title,
                    "query": dql, "visualization": visualization,
                    "visualizationSettings": lens_settings, "querySettings": {},
                }
                layouts[tile_id] = _scale_layout(grid)
                continue
            report.warn(f"Lens panel `{title}` had no readable state; emitted a placeholder.")
            tiles[tile_id] = {"type": "markdown",
                              "content": f"### {title}\n\n_Lens visualization — rebuild manually._"}
            layouts[tile_id] = _scale_layout(grid)
            continue

        if spec is not None and spec.kibana_type == "vega":
            from e2d.dashboards.vega import convert_vega
            res = convert_vega(spec.raw_params or {}, config, report,
                               fallback_index=spec.index_title)
            if res is not None:
                lint_into_report(res["dql"], report, res["data_object"])
                tiles[tile_id] = {
                    "type": "data", "title": title,
                    "query": res["dql"], "visualization": res["visualization"],
                    "visualizationSettings": {}, "querySettings": {},
                }
                layouts[tile_id] = _scale_layout(grid)
                continue
            report.manual(f"Vega panel `{title}` needs manual rebuild; emitted a placeholder tile.",
                          source=title)
            tiles[tile_id] = {"type": "markdown",
                              "content": f"### {title}\n\n_Vega visualization — rebuild manually._"}
            layouts[tile_id] = _scale_layout(grid)
            continue

        if spec is None:
            report.warn(f"Panel `{title}` has no recognizable visualization; skipped.")
            continue

        dql, viz_hint = build_dql(spec, config, report)
        visualization = dt_visualization(spec.kibana_type, viz_hint)

        viz_settings: Dict[str, Any] = {}
        if spec.colors and visualization in (
                "lineChart", "areaChart", "barChart", "categoricalBarChart",
                "pieChart", "donutChart"):
            from e2d.dashboards.aggs import _sanitize_alias
            from e2d.dashboards.colors import apply_series_colors
            # Kibana keys colors by series label: a term VALUE for split charts
            # (used as-is) or a metric/filter LABEL (which we sanitised into the
            # column alias) — register both spellings, extras are inert.
            cmap: Dict[str, str] = {}
            for label, col in spec.colors.items():
                cmap.setdefault(label, col)
                san = _sanitize_alias(label, label)
                if san and san != label:
                    cmap.setdefault(san, col)
            apply_series_colors(viz_settings, cmap)

        tiles[tile_id] = {
            "type": "data",
            "title": title,
            "query": dql,
            "visualization": visualization,
            "visualizationSettings": viz_settings,
            "querySettings": {},
        }
        layouts[tile_id] = _scale_layout(grid)

    # dashboard-level Controls (modern controlGroupInput) -> variables
    _convert_control_group(attrs, refs_by_name, export, config, report,
                           variables, seen_var_keys, var_filters)

    # Kibana controls filter every panel on their index pattern; replicate by
    # splicing a variable-driven filter into each same-data-object tile.
    if var_filters:
        _apply_variable_filters(tiles, var_filters)
        report.info("Control variables were wired into tiles as "
                    "`filter in(<field>, array($<var>))` (all values selected by default).")

    dashboard = {
        "name": attrs.get("title") or dash.title,
        "type": "dashboard",
        "content": {
            "version": DASHBOARD_VERSION,
            "variables": variables,
            "tiles": tiles,
            "layouts": layouts,
        },
    }

    # Flag custom attributes the tiles depend on: faithfully translated, but
    # only present in Grail if the ingest carries them. If absent, the tile
    # renders empty and an OpenPipeline extraction is needed at ingest.
    custom_fields = audit_dashboard_fields(dashboard)["custom"]
    if custom_fields:
        shown = ", ".join(f"`{f}`" for f in custom_fields[:6])
        more = f" (+{len(custom_fields) - 6} more)" if len(custom_fields) > 6 else ""
        report.warn(
            f"Tiles read {len(custom_fields)} custom field(s) — e.g. {shown}{more}. "
            "A tile shows NO DATA (without an error) if a field isn't ingested under that "
            "name. The `.fields.md` file next to this dashboard lists every field and how "
            "to fix missing ones.")

    return dashboard, report


# --------------------------------------------------------------------------- #
# CLI entry
# --------------------------------------------------------------------------- #

def _safe_filename(name: str) -> str:
    keep = "".join(c if (c.isalnum() or c in " -_") else "_" for c in name).strip()
    return (keep or "dashboard").replace(" ", "_")[:120]


def convert_dashboard_file(args) -> int:
    import sys
    from pathlib import Path
    from e2d.report import Severity

    config = MappingConfig.load(getattr(args, "config", None))
    export = KibanaExport.load(args.input)
    dashboards = export.dashboards
    if not dashboards:
        print("No dashboards found in export.", file=sys.stderr)
        return 1

    title_filter = getattr(args, "title", None)
    if title_filter:
        dashboards = [d for d in dashboards if title_filter.lower() in d.title.lower()]
        if not dashboards:
            print(f"No dashboard title matched '{title_filter}'.", file=sys.stderr)
            return 1

    out = getattr(args, "output", None)
    as_terraform = getattr(args, "terraform", False)
    single = (not as_terraform and len(dashboards) == 1 and out
              and not out.endswith(("/", "\\")) and not Path(out).is_dir())

    n_ok = n_review = n_manual = 0
    converted: List[Tuple[str, Dict[str, Any]]] = []
    manifests: List[Tuple[str, str]] = []  # (safe basename, markdown) for --terraform
    for d in dashboards:
        dashboard, report = convert_dashboard(d, export, config)
        if report.has_blocking:
            n_manual += 1
        elif report.needs_review:
            n_review += 1
        else:
            n_ok += 1
        converted.append((dashboard["name"], dashboard))

        tile_count = len(dashboard["content"]["tiles"])
        status = "MANUAL" if report.has_blocking else ("REVIEW" if report.needs_review else "OK")

        # Ingest companion: a field manifest + OpenPipeline extraction scaffolds,
        # emitted only when tiles depend on custom (non-dictionary) attributes.
        audit = audit_dashboard_fields(dashboard)
        manifest = (render_field_manifest(dashboard["name"], audit)
                    if audit["custom"] else None)

        if as_terraform:
            print(f"[{status:6}] {d.title}  ({tile_count} tiles)", file=sys.stderr)
            for w in report.warnings:
                if w.severity is Severity.INFO and not getattr(args, "verbose", False):
                    continue
                print(f"           {w.format()}", file=sys.stderr)
            if manifest:
                manifests.append((_safe_filename(d.title), manifest))
            continue

        payload = json.dumps(dashboard, indent=2)
        if single:
            Path(out).write_text(payload, encoding="utf-8")
            dest = Path(out)
        elif out:
            out_dir = Path(out)
            out_dir.mkdir(parents=True, exist_ok=True)
            dest = out_dir / f"{_safe_filename(d.title)}.json"
            dest.write_text(payload, encoding="utf-8")
        else:
            print(payload)
            dest = None

        if manifest and dest is not None:
            manifest_path = dest.with_suffix(".fields.md")
            manifest_path.write_text(manifest, encoding="utf-8")

        print(f"[{status:6}] {d.title}  ->  {dest or '(stdout)'}  ({tile_count} tiles)", file=sys.stderr)
        if manifest and dest is not None:
            print(f"           [FIELDS] {len(audit['custom'])} custom attribute(s) -> {manifest_path}",
                  file=sys.stderr)
        for w in report.warnings:
            if w.severity is Severity.INFO and not getattr(args, "verbose", False):
                continue
            print(f"           {w.format()}", file=sys.stderr)

    if as_terraform:
        if not out:
            print("error: --terraform requires -o <output directory>", file=sys.stderr)
            return 2
        from e2d.terraform.generator import generate_terraform
        summary = generate_terraform(converted, out)
        for basename, text in manifests:
            (Path(out) / f"{basename}.fields.md").write_text(text, encoding="utf-8")
        print(f"\nWrote Terraform module ({summary['resources']} dynatrace_document resources) "
              f"-> {summary['dir']}", file=sys.stderr)
        if manifests:
            print(f"Wrote {len(manifests)} field manifest(s) (.fields.md) into {out}", file=sys.stderr)

    print(f"\nDashboards: {len(dashboards)}  |  OK: {n_ok}  REVIEW: {n_review}  MANUAL: {n_manual}",
          file=sys.stderr)
    return 0
