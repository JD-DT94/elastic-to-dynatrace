"""Audit which fields a converted dashboard's DQL depends on.

A migrated DQL query silently returns nothing when it reads a field that does
not exist on the target Grail data object — there is no error, the tile just
renders empty. The Elastic `.keyword` multi-field, ECS aliases, and bespoke
application attributes (e.g. `tracking.transactionName`) are the usual
offenders: faithfully translated, yet only present in Grail if the log/span
ingest actually carries them.

So after conversion we extract every field each tile reads and split them into:

  * **builtin**  — Dynatrace semantic-dictionary fields (prefixes like `dt.`,
    `k8s.`, `span.`, and bare fields like `loglevel`) that are present whenever
    the matching data is ingested; safe to assume.
  * **custom**   — everything else. These MUST be verified against the live
    environment; if absent they need an ingest-side extraction (OpenPipeline
    DPL `parse` / `fieldsAdd`) before the dashboard returns data.

This module only *identifies* the dependency — it deliberately does not invent
an OpenPipeline config, because a correct extraction needs the raw log/span
shape, which the Kibana export does not contain.
"""

from __future__ import annotations

import re
from typing import Dict, List, Set

# Field-name prefixes that belong to the Dynatrace semantic dictionary. A field
# under one of these is present whenever the corresponding data object is
# ingested, so it never needs an ingest-side extraction.
_BUILTIN_PREFIXES = (
    "dt.", "k8s.", "host.", "span.", "service.", "trace.", "http.", "db.",
    "code.", "exception.", "event.", "log.", "browser.", "geo.", "os.",
    "process.", "container.", "cloud.", "network.", "user.", "url.",
    "destination.", "source.", "client.", "server.", "faas.", "telemetry.",
    "thread.", "messaging.", "rpc.", "aws.", "azure.", "gcp.",
)

# Bare (un-prefixed) semantic-dictionary fields.
_BUILTIN_FIELDS = {"loglevel", "content", "timestamp"}

# DQL command words, parameter names, operators and literals — never fields.
_RESERVED = {
    "fetch", "filter", "filterout", "summarize", "maketimeseries", "timeseries",
    "sort", "limit", "fields", "fieldsadd", "fieldsremove", "fieldskeep",
    "fieldsrename", "fieldsflatten", "parse", "lookup", "join", "joinnested",
    "expand", "dedup", "search", "append", "data", "describe", "metrics",
    "by", "interval", "rollup", "scalar", "from", "to", "timeframe", "bins",
    "spread", "nonempty", "prefix", "sourcefield", "lookupfield", "on", "kind",
    "asc", "desc", "and", "or", "not", "in", "else", "true", "false", "null",
    "nulls", "first", "last",
}

# An identifier: a field path (optionally backtick-quoted), function name,
# alias, or keyword.
_IDENT = re.compile(r'"(?:[^"\\]|\\.)*"|`[^`]+`|[A-Za-z_][A-Za-z0-9_.]*')

_VARIABLE = re.compile(r"\$[A-Za-z_][A-Za-z0-9_]*(?::[a-z]+)?")

# A duration literal (1h, 10m, 500ms) — its unit must not read as a field.
_DURATION = re.compile(r"\b\d+(?:\.\d+)?(?:ms|s|m|h|d|w)\b")


def _fields_in_query(dql: str) -> Set[str]:
    """Extract the set of source-field references read by a single DQL query."""
    # Dashboard-variable references ($Var, $Var:noquote) are not fields, and
    # duration literals must not contribute their unit letter as a token.
    dql = _VARIABLE.sub('""', dql)
    dql = _DURATION.sub("0", dql)
    # Tokenize, dropping string literals (they start with a quote).
    raw = [m.group(0) for m in _IDENT.finditer(dql)]
    tokens = [t for t in raw if not t.startswith('"')]

    # Re-scan with the surrounding characters so we can tell a field from a
    # function call, an alias, or the `fetch` data object.
    aliases: Set[str] = set()
    funcs: Set[str] = set()
    data_objects: Set[str] = set()
    positions = [(m.start(), m.end(), m.group(0))
                 for m in _IDENT.finditer(dql) if not m.group(0).startswith('"')]
    for i, (start, end, tok) in enumerate(positions):
        tok = tok.strip("`")
        # Look far enough ahead to clear any whitespace before the operator, so
        # `field  == "x"` is read as a comparison, not an assignment.
        after = dql[end:end + 4].lstrip()
        # `name (` -> function call
        if after.startswith("("):
            funcs.add(tok)
        # `name =` (assignment) but not `name ==` (comparison) -> alias
        elif after.startswith("=") and not after.startswith("=="):
            aliases.add(tok)
        # token right after the `fetch` command word -> data object
        if i > 0 and positions[i - 1][2].lower() == "fetch":
            data_objects.add(tok)

    fields: Set[str] = set()
    for tok in tokens:
        tok = tok.strip("`")
        if tok.lower() in _RESERVED or tok in funcs or tok in aliases or tok in data_objects:
            continue
        fields.add(tok)
    return fields


def _classify(field: str) -> str:
    if field in _BUILTIN_FIELDS or field.startswith(_BUILTIN_PREFIXES):
        return "builtin"
    return "custom"


_FETCH = re.compile(r"\bfetch\s+([A-Za-z_][A-Za-z0-9_.]*)")


def _data_object_of(dql: str) -> str:
    m = _FETCH.search(dql)
    return m.group(1) if m else "logs"


def audit_dashboard_fields(dashboard: Dict) -> Dict[str, object]:
    """Field dependencies of a converted dashboard, across all `data` tiles.

    Returns ``{'builtin': [...], 'custom': [...], 'objects': {field: [obj,...]}}``
    — ``objects`` maps each custom field to the data object(s) it is read from,
    so an ingest fix targets the right pipeline.
    """
    builtin: Set[str] = set()
    custom: Set[str] = set()
    objects: Dict[str, Set[str]] = {}
    tiles = dashboard.get("content", {}).get("tiles", {})
    for tile in tiles.values():
        if tile.get("type") != "data":
            continue
        query = tile.get("query", "")
        data_object = _data_object_of(query)
        for f in _fields_in_query(query):
            if _classify(f) == "builtin":
                builtin.add(f)
            else:
                custom.add(f)
                objects.setdefault(f, set()).add(data_object)
    return {
        "builtin": sorted(builtin),
        "custom": sorted(custom),
        "objects": {f: sorted(o) for f, o in objects.items()},
    }


def render_field_manifest(name: str, audit: Dict[str, object]) -> str:
    """Render a Markdown ingest companion: the field dependencies plus, for each
    custom attribute, an OpenPipeline extraction scaffold (DPL `parse`/`fieldsAdd`).

    Follows the §C.6 model — flag the custom field, emit an extraction stub, mark
    the unknown source with `// TODO`. The DPL expressions are the faithful core;
    the source pattern is a TODO because the Kibana export does not carry the raw
    log/span shape needed to complete it.
    """
    builtin = audit.get("builtin", [])  # type: ignore[assignment]
    custom = audit.get("custom", [])    # type: ignore[assignment]
    objects: Dict[str, List[str]] = audit.get("objects", {})  # type: ignore[assignment]

    lines: List[str] = [f"# Field dependencies — {name}", ""]
    lines.append("Fields each `data` tile reads. A DQL tile renders **empty with no "
                 "error** if a field it queries is absent from the target Grail data "
                 "object, so verify the custom attributes below before shipping.")
    lines.append("")
    lines.append("## Built-in (semantic dictionary — present when the data is ingested)")
    lines.append("")
    lines.append(", ".join(f"`{f}`" for f in builtin) if builtin else "_none_")
    lines.append("")
    lines.append("## Custom attributes — verify these exist at ingest")
    lines.append("")
    if not custom:
        lines.append("_none — every field is a semantic-dictionary field._")
        return "\n".join(lines) + "\n"

    lines.append("| Attribute | Data object | Action |")
    lines.append("|-----------|-------------|--------|")
    for f in custom:
        objs = ", ".join(f"`{o}`" for o in objects.get(f, ["logs"]))
        lines.append(f"| `{f}` | {objs} | confirm ingested, else extract (below) |")
    lines.append("")
    lines.append("## OpenPipeline extraction scaffolds")
    lines.append("")
    lines.append("If a verification above fails, add a processor to the data object's "
                 "OpenPipeline. Pick **rename** (value present under another name) or "
                 "**parse** (value embedded in the record body), then remove the other.")
    lines.append("")
    for f in custom:
        objs = objects.get(f, ["logs"])
        for obj in objs:
            lines.append(f"### `{f}` on `{obj}`")
            lines.append("")
            lines.append("```dpl")
            lines.append(f"// Pipeline: {obj}  ->  Processor (DPL)")
            lines.append("// A) value already ingested under another name — rename:")
            lines.append(f"fieldsAdd {f} = <source.field>            // TODO confirm source field")
            lines.append("// B) value embedded in the record body — parse:")
            lines.append(f'parse content, "LD \'{f}\' ..."           // TODO complete DPL pattern')
            lines.append("```")
            lines.append("")
    return "\n".join(lines) + "\n"
