"""ES|QL -> DQL function, operator and cast mapping tables.

Three categories:

* SCALAR_FUNCTIONS  - row-level functions usable in WHERE / EVAL.
* AGG_FUNCTIONS     - aggregations usable in STATS.
* CAST_TYPES        - right-hand side of the `::` cast operator and TO_* funcs.

Where a mapping is lossy or semantics differ (1-indexed vs 0-indexed, regex vs
DPL pattern, etc.) the name maps to a `Mapping` carrying a `note` so the
translator can emit a review warning.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional


@dataclass
class Mapping:
    dql: str
    note: Optional[str] = None  # review note if translation is lossy/approximate


def _m(dql: str, note: Optional[str] = None) -> Mapping:
    return Mapping(dql, note)


# Functions that translate by name with identical argument order and semantics.
_IDENTITY = {
    "abs", "acos", "asin", "atan", "atan2", "ceil", "cos", "cosh", "exp",
    "floor", "log", "log10", "round", "signum", "sin", "sinh", "sqrt", "tan",
    "tanh", "trim", "concat", "coalesce", "now",
}

SCALAR_FUNCTIONS: Dict[str, Mapping] = {fn: _m(fn) for fn in _IDENTITY}
SCALAR_FUNCTIONS.update({
    # --- string ---------------------------------------------------------
    "length": _m("stringLength"),
    "to_lower": _m("lower"),
    "to_upper": _m("upper"),
    "starts_with": _m("startsWith"),
    "ends_with": _m("endsWith"),
    "split": _m("splitString"),
    "substring": _m(
        "substring",
        "ES|QL SUBSTRING is 1-indexed (start, length); DQL substring(expr, from:, to:) "
        "is 0-indexed with end index - review the bounds.",
    ),
    "replace": _m(
        "replacePattern",
        "ES|QL REPLACE uses a regex; DQL replacePattern uses a DPL pattern. "
        "Review the pattern, or use replaceString for literal replacement.",
    ),
    "ltrim": _m("trim", "ES|QL LTRIM trims only the left side; DQL trim() trims both."),
    "rtrim": _m("trim", "ES|QL RTRIM trims only the right side; DQL trim() trims both."),
    "locate": _m("indexOf", "Check index base: ES|QL LOCATE is 1-indexed, DQL indexOf is 0-indexed."),
    # --- math -----------------------------------------------------------
    "pow": _m("power"),
    "cbrt": _m("cbrt"),
    "greatest": _m("", "No direct DQL function - use array(...) with arrayMax() or nested if()."),
    "least": _m("", "No direct DQL function - use array(...) with arrayMin() or nested if()."),
    # --- type conversion ------------------------------------------------
    "to_string": _m("toString"),
    "to_long": _m("toLong"),
    "to_integer": _m("toLong"),
    "to_double": _m("toDouble"),
    "to_boolean": _m("toBoolean"),
    "to_ip": _m("toIp"),
    "to_datetime": _m("toTimestamp"),
    # --- multivalue -> DQL array functions ------------------------------
    "mv_avg": _m("arrayAvg"),
    "mv_count": _m("arraySize"),
    "mv_sum": _m("arraySum"),
    "mv_min": _m("arrayMin"),
    "mv_max": _m("arrayMax"),
    "mv_median": _m("arrayMedian"),
    "mv_dedupe": _m("arrayDistinct"),
    "mv_first": _m("arrayFirst"),
    "mv_last": _m("arrayLast"),
    "mv_sort": _m("arraySort"),
    "mv_concat": _m("arrayToString"),
    "mv_slice": _m("arraySlice"),
    # --- ip -------------------------------------------------------------
    "cidr_match": _m("ipIn", "Verify argument order: DQL ipIn(ip, range, ...)."),
    # --- date (lossy - DQL favours @ alignment / time functions) --------
    "date_format": _m("formatTimestamp", "Review the format string syntax."),
    "date_trunc": _m("", "No direct DQL function - use @ time alignment in the timeframe or bin()."),
    "date_extract": _m("", "Use DQL time functions (getHour, getDayOfMonth, ...) instead."),
    "date_diff": _m("", "Subtract timestamps directly in DQL (yields a duration)."),
})

# CASE is handled structurally by the translator, not as a name mapping.
SPECIAL_FUNCTIONS = {"case"}

AGG_FUNCTIONS: Dict[str, Mapping] = {
    "count": _m("count"),
    "count_distinct": _m("countDistinct"),
    "avg": _m("avg"),
    "sum": _m("sum"),
    "min": _m("min"),
    "max": _m("max"),
    "median": _m("median"),
    "percentile": _m("percentile"),
    "stddev": _m("stddev"),
    "values": _m("collectDistinct"),
    "top": _m("", "No direct DQL aggregation - use takeMax/takeMin or sort+limit."),
    "weighted_avg": _m("", "No direct DQL aggregation - compute sum(w*x)/sum(w) manually."),
    "median_absolute_deviation": _m("", "No direct DQL aggregation - compute manually."),
}

# `::` cast operator and TO_* targets -> DQL conversion function.
CAST_TYPES: Dict[str, str] = {
    "string": "toString",
    "long": "toLong",
    "integer": "toLong",
    "int": "toLong",
    "double": "toDouble",
    "float": "toDouble",
    "boolean": "toBoolean",
    "bool": "toBoolean",
    "ip": "toIp",
    "datetime": "toTimestamp",
}

# ES|QL logical/keyword operators -> DQL.
LOGICAL_OPERATORS = {
    "and": "and",
    "or": "or",
    "not": "not",
}
