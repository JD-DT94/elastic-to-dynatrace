"""Conversion reporting: structured warnings emitted during translation.

A warning never aborts a conversion. The goal of a migration tool is to convert
everything it can and clearly flag what a human must review, rather than fail on
the first unsupported construct.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Tuple


class Severity(str, Enum):
    INFO = "info"        # informational; output is correct but worth knowing
    WARN = "warn"        # best-effort translation; review recommended
    MANUAL = "manual"    # could not translate; human action required


@dataclass
class Warning:
    severity: Severity
    message: str
    # The original ES|QL / source fragment this warning concerns, if any.
    source: Optional[str] = None

    def format(self) -> str:
        tag = self.severity.value.upper()
        if self.source:
            return f"[{tag}] {self.message}  ->  `{self.source}`"
        return f"[{tag}] {self.message}"


@dataclass
class Report:
    warnings: List[Warning] = field(default_factory=list)

    def info(self, message: str, source: Optional[str] = None) -> None:
        self.warnings.append(Warning(Severity.INFO, message, source))

    def warn(self, message: str, source: Optional[str] = None) -> None:
        self.warnings.append(Warning(Severity.WARN, message, source))

    def manual(self, message: str, source: Optional[str] = None) -> None:
        self.warnings.append(Warning(Severity.MANUAL, message, source))

    @property
    def needs_review(self) -> bool:
        return any(w.severity in (Severity.WARN, Severity.MANUAL) for w in self.warnings)

    @property
    def has_blocking(self) -> bool:
        return any(w.severity is Severity.MANUAL for w in self.warnings)

    def extend(self, other: "Report") -> None:
        self.warnings.extend(other.warnings)

    def format(self) -> str:
        return "\n".join(w.format() for w in self.warnings)

    def deduped(self) -> List[Tuple[Warning, int]]:
        """Warnings collapsed by identical (severity, message, source), keeping
        first-seen order with an occurrence count. A dashboard with 40 panels
        repeating the same note reads as one line, not forty."""
        order: List[Tuple[Severity, str, Optional[str]]] = []
        counts: dict = {}
        first: dict = {}
        for w in self.warnings:
            key = (w.severity, w.message, w.source)
            if key not in counts:
                order.append(key)
                first[key] = w
            counts[key] = counts.get(key, 0) + 1
        return [(first[k], counts[k]) for k in order]

    def format_deduped(self) -> List[str]:
        """Human-readable deduplicated lines: `[WARN] message (×N)`."""
        out = []
        for w, n in self.deduped():
            line = w.format()
            out.append(f"{line}  (×{n})" if n > 1 else line)
        return out
