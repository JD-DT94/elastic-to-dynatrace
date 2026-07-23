"""Carry Kibana series colors into Dynatrace visualizationSettings.

Kibana stores explicit color choices in three places:

  * TSVB: each series carries ``color: "rgba(255,0,4,1)"``
  * legacy visualizations: ``uiStateJSON.vis.colors`` — ``{"series label": "#hex"}``
  * Lens (lnsXY): ``state.visualization.layers[].yConfig`` — ``[{forAccessor, color}]``

Dynatrace persists per-series overrides as (shape confirmed against real
exported platform dashboards):

    visualizationSettings.chartSettings.seriesOverrides:
        [{"seriesId": ["<series name or dimension value>"],
          "override": {"color": {"Default": "#rrggbb"}}}]

``seriesId`` matches either a metric column alias (multi-metric charts) or a
dimension value (split charts) — exactly the two things Kibana keys its colors
by. Only explicit user choices are carried; palette defaults are left to
Dynatrace.
"""

from __future__ import annotations

import re
from typing import Dict, Optional

_RGBA = re.compile(r"rgba?\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)(?:\s*,\s*[\d.]+)?\s*\)", re.I)
_HEX = re.compile(r"^#(?:[0-9a-f]{3}|[0-9a-f]{6})$", re.I)


def to_hex(color: Optional[str]) -> Optional[str]:
    """Normalise a Kibana color (#hex / rgb() / rgba()) to #rrggbb; None if not
    a usable explicit color."""
    if not color or not isinstance(color, str):
        return None
    color = color.strip()
    if _HEX.match(color):
        if len(color) == 4:  # #abc -> #aabbcc
            color = "#" + "".join(c * 2 for c in color[1:])
        return color.lower()
    m = _RGBA.match(color)
    if m:
        r, g, b = (min(255, int(x)) for x in m.groups())
        return f"#{r:02x}{g:02x}{b:02x}"
    return None


def apply_series_colors(settings: Dict, color_map: Dict[str, str]) -> Dict:
    """Merge per-series color overrides into a tile's visualizationSettings.
    ``color_map`` maps series name / dimension value -> raw Kibana color."""
    overrides = []
    seen = set()
    for name, raw in color_map.items():
        hexcol = to_hex(raw)
        if not hexcol or not str(name).strip() or name in seen:
            continue
        seen.add(name)
        overrides.append({"seriesId": [str(name)],
                          "override": {"color": {"Default": hexcol}}})
    if overrides:
        settings.setdefault("chartSettings", {})["seriesOverrides"] = overrides
    return settings
