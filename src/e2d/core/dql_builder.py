"""Programmatic DQL builder. One place owns DQL text formatting (fetch vs
timeseries head, filter joining, pipeline assembly, field quoting)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional


def quote_field(name: str) -> str:
    """Backtick a field name only if it contains DQL-special characters."""
    if name and all(c.isalnum() or c in "._" for c in name):
        return name
    return "`" + name + "`"


def quote_string(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _needs_paren(pred: str) -> bool:
    # wrap a predicate when AND-joining if it contains a top-level or
    return " or " in pred and not (pred.startswith("(") and pred.endswith(")"))


@dataclass
class Query:
    """A DQL pipeline under construction.

    `head_override` lets callers start the pipeline with something other than
    `fetch <data_object>` (e.g. `timeseries avg(metric)` for metric queries).
    """
    data_object: str = "logs"
    head_override: Optional[str] = None
    timeframe: Optional[str] = None          # e.g. "from:now()-15m" or 'timeframe:"a/b"'
    filters: List[str] = field(default_factory=list)
    pipeline: List[str] = field(default_factory=list)

    def add_filter(self, predicate: Optional[str]) -> "Query":
        if predicate:
            self.filters.append(predicate)
        return self

    def add(self, command: Optional[str]) -> "Query":
        if command:
            self.pipeline.append(command)
        return self

    def head(self) -> str:
        if self.head_override:
            base = self.head_override
        else:
            base = f"fetch {self.data_object}"
        if self.timeframe:
            sep = ", " if not base.endswith(",") else " "
            base = f"{base}{sep}{self.timeframe}"
        return base

    def render(self) -> str:
        lines = [self.head()]
        if self.filters:
            joined = " and ".join(f"({p})" if _needs_paren(p) else p for p in self.filters)
            lines.append(f"filter {joined}")
        lines.extend(self.pipeline)
        out = lines[0]
        for ln in lines[1:]:
            out += "\n| " + ln
        return out
