"""Load and normalise Kibana saved-object exports.

Kibana exports are NDJSON: one saved object per line, each with `id`, `type`,
`attributes`, and `references`. Several attributes are *strings of JSON*
(`panelsJSON`, `visState`, `searchSourceJSON`, `optionsJSON`, Lens `state`),
which this module decodes eagerly so the rest of the converter sees plain dicts.

It also builds an id->object index and resolves panel references so a dashboard
panel can be linked to the visualization/search/lens it embeds.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


def _maybe_json(value: Any) -> Any:
    """Decode a value that may be a JSON-encoded string; otherwise return as-is."""
    if isinstance(value, str):
        s = value.strip()
        if s and s[0] in "{[":
            try:
                return json.loads(s)
            except json.JSONDecodeError:
                return value
    return value


@dataclass
class SavedObject:
    id: str
    type: str
    attributes: Dict[str, Any]
    references: List[Dict[str, Any]] = field(default_factory=list)
    raw: Dict[str, Any] = field(default_factory=dict)

    @property
    def title(self) -> str:
        return self.attributes.get("title") or self.attributes.get("name") or self.id

    def ref_id(self, name: str) -> Optional[str]:
        for r in self.references:
            if r.get("name") == name:
                return r.get("id")
        return None

    def ref_by_type(self, type_: str) -> Optional[str]:
        for r in self.references:
            if r.get("type") == type_:
                return r.get("id")
        return None


# Attribute keys whose values are JSON-encoded strings.
_DECODE_KEYS = ("panelsJSON", "visState", "uiStateJSON", "optionsJSON", "state",
                "controlGroupInput")


def _decode_attributes(attrs: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(attrs)
    for k in _DECODE_KEYS:
        if k in out:
            out[k] = _maybe_json(out[k])
    # kibanaSavedObjectMeta.searchSourceJSON is nested
    ksm = out.get("kibanaSavedObjectMeta")
    if isinstance(ksm, dict) and "searchSourceJSON" in ksm:
        ksm = dict(ksm)
        ksm["searchSourceJSON"] = _maybe_json(ksm["searchSourceJSON"])
        out["kibanaSavedObjectMeta"] = ksm
    return out


@dataclass
class KibanaExport:
    objects: List[SavedObject]
    by_id: Dict[str, SavedObject] = field(default_factory=dict)

    @classmethod
    def load(cls, path: str) -> "KibanaExport":
        p = Path(path)
        text = p.read_text(encoding="utf-8")
        raw_objs: List[Dict[str, Any]] = []

        # NDJSON first (one object per line)
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                raw_objs.append(json.loads(line))
            except json.JSONDecodeError:
                raw_objs = []
                break
        # Fallback: a single JSON object or array
        if not raw_objs:
            data = json.loads(text)
            raw_objs = data if isinstance(data, list) else [data]

        objects: List[SavedObject] = []
        for o in raw_objs:
            if not isinstance(o, dict) or "type" not in o:
                continue
            obj = SavedObject(
                id=o.get("id", ""),
                type=o.get("type", ""),
                attributes=_decode_attributes(o.get("attributes", {}) or {}),
                references=o.get("references", []) or [],
                raw=o,
            )
            objects.append(obj)

        export = cls(objects=objects)
        export.by_id = {o.id: o for o in objects if o.id}
        return export

    # -- accessors --------------------------------------------------------
    def of_type(self, type_: str) -> List[SavedObject]:
        return [o for o in self.objects if o.type == type_]

    @property
    def dashboards(self) -> List[SavedObject]:
        return self.of_type("dashboard")

    def resolve(self, obj_id: Optional[str]) -> Optional[SavedObject]:
        if not obj_id:
            return None
        return self.by_id.get(obj_id)


def index_pattern_title(export: KibanaExport, ip_id: Optional[str]) -> Optional[str]:
    """Return the title (index name pattern) of an index-pattern object."""
    obj = export.resolve(ip_id)
    if obj and obj.type == "index-pattern":
        return obj.attributes.get("title")
    return None
