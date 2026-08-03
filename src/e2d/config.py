"""Mapping configuration: index -> Dynatrace data object, and Elastic field ->
DQL field. All defaults are overridable via a JSON config file so each migration
can encode its own index naming conventions and ECS->Dynatrace field choices.

Override file shape (all keys optional)::

    {
      "index_map": [
        {"pattern": "^myapp-logs-.*", "data_object": "logs"},
        {"pattern": "^myapp-traces-.*", "data_object": "spans"}
      ],
      "field_map": {"service.name": "service.name"},
      "data_object_field_map": {
        "logs": {"message": "content"},
        "spans": {"message": "span.name"}
      }
    }
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

# Dynatrace fetch-able data objects we know how to target.
METRICS_SENTINEL = "__metrics__"  # ES|QL metrics index -> DQL `timeseries`, handled specially.

# Ordered index-name -> data object rules. First regex match wins.
DEFAULT_INDEX_MAP: List[Tuple[str, str]] = [
    (r"(^|[-_.])(traces?|apm|spans?)([-_.]|$)", "spans"),
    (r"(^|[-_.])(metrics?|metricbeat)([-_.]|$)", METRICS_SENTINEL),
    (r"(^|[-_.])(logs?|filebeat|winlogbeat)([-_.]|$)", "logs"),
    (r"(^|[-_.])(events?|auditbeat)([-_.]|$)", "events"),
    (r"(^|[-_.])(rum|sessions?)([-_.]|$)", "user.events"),
]

# Field renames that apply regardless of data object (ECS -> DQL conventions
# that are stable across log/span/event data).
DEFAULT_FIELD_MAP: Dict[str, str] = {
    "@timestamp": "timestamp",
}

# Data-object-specific field renames. These take precedence over DEFAULT_FIELD_MAP.
# Based on the Dynatrace semantic dictionary: log body is `content`, severity is
# `loglevel` (NOT `log.level`).
DEFAULT_DATA_OBJECT_FIELD_MAP: Dict[str, Dict[str, str]] = {
    "logs": {
        "message": "content",
        "log.level": "loglevel",
        "log.logger": "log.source",
        "host.name": "host.name",
        # `service.name` is a real log field; keep it. (`dt.entity.*` is the
        # deprecated entity-ID namespace and has no `.name` member — grouping or
        # filtering on it silently yields nothing.)
        "service.name": "service.name",
    },
    "spans": {
        "message": "span.name",
        "trace.id": "trace.id",
        "span.id": "span.id",
        "service.name": "service.name",
        "transaction.name": "span.name",
    },
    "events": {
        "message": "event.description",
    },
}


@dataclass
class MappingConfig:
    index_map: List[Tuple[str, str]] = field(default_factory=lambda: list(DEFAULT_INDEX_MAP))
    field_map: Dict[str, str] = field(default_factory=lambda: dict(DEFAULT_FIELD_MAP))
    data_object_field_map: Dict[str, Dict[str, str]] = field(
        default_factory=lambda: {k: dict(v) for k, v in DEFAULT_DATA_OBJECT_FIELD_MAP.items()}
    )
    # Dynatrace normalizes log attribute keys to lowercase at ingest, so a
    # camelCase Elastic field (audit.logText) lands in Grail as audit.logtext.
    # Translated field references are lowercased to match; an explicit
    # field_map target always wins verbatim. Disable with
    # {"lowercase_fields": false} for data whose keys keep their case.
    lowercase_fields: bool = True

    # ---- resolution helpers -------------------------------------------------

    def resolve_data_object(self, index: str) -> Optional[str]:
        """Map an Elastic index/pattern to a Dynatrace data object.

        Returns None if no rule matches (caller should warn and fall back).
        """
        cleaned = index.strip().strip('"').strip("'")
        for pattern, data_object in self.index_map:
            if re.search(pattern, cleaned, re.IGNORECASE):
                return data_object
        return None

    def resolve_field(self, name: str, data_object: Optional[str]) -> str:
        """Translate an Elastic field name to its DQL equivalent.

        The Elasticsearch ``.keyword`` multi-field suffix has no Dynatrace
        equivalent (DQL fields are not multi-fields), so it is stripped before
        any map lookup. Centralising it here covers every caller — grouping
        (``terms``) and metric fields included, not just the filter paths.
        """
        if name.endswith(".keyword"):
            name = name[: -len(".keyword")]
        if data_object and data_object in self.data_object_field_map:
            do_map = self.data_object_field_map[data_object]
            if name in do_map:
                return do_map[name]
        if name in self.field_map:
            return self.field_map[name]
        if self.lowercase_fields and name.lower() != name:
            return name.lower()
        return name

    # ---- loading ------------------------------------------------------------

    @classmethod
    def load(cls, path: Optional[str]) -> "MappingConfig":
        cfg = cls()
        if not path:
            return cfg
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if "index_map" in data:
            # custom rules are tried first; the built-in defaults stay as a
            # fallback so one custom rule doesn't silently unmap everything else
            cfg.index_map = [(r["pattern"], r["data_object"])
                             for r in data["index_map"]] + cfg.index_map
        if "field_map" in data:
            cfg.field_map.update(data["field_map"])
        if "data_object_field_map" in data:
            for do, m in data["data_object_field_map"].items():
                cfg.data_object_field_map.setdefault(do, {}).update(m)
        if "lowercase_fields" in data:
            cfg.lowercase_fields = bool(data["lowercase_fields"])
        return cfg
