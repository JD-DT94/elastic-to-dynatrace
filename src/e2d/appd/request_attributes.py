"""AppDynamics data collectors -> Dynatrace request attributes.

AppD has two kinds of collector and they migrate with very different confidence:

**HTTP data collectors** capture request parameters, headers, cookies and
session attributes. These map cleanly — Dynatrace has a source for each, so
they convert into complete, deployable request attributes.

**Method invocation data collectors (MIDC)** capture a method argument, return
value or the invoked object. Dynatrace can do this (`source = METHOD_PARAM`)
but matches methods differently: it needs the technology and a class/method rule
scoped to a process group, where AppD scoped by tier. The class and method names
carry across; the rule itself cannot be completed offline, so those attributes
are emitted **disabled** with the method detail preserved and a note saying what
to finish in the UI. A method rule guessed from an AppD export would attach to
nothing and capture silently empty values.

Cookies are the interesting case: Dynatrace has no cookie source, so a cookie
collector becomes a `REQUEST_HEADER` capture of `Cookie` with a value-extractor
regex for the named cookie. That is a real equivalent rather than a compromise,
but it is flagged because the regex deserves a human's eye.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from e2d.report import Report

# Config API v1 is the documented endpoint for request attributes.
API_PATH = "/api/config/v1/service/requestAttributes"

# Where a captured value is taken from and where it is stored. Server-side is
# the right default for anything an application emits.
CAPTURE_SERVER = "CAPTURE_AND_STORE_ON_SERVER"

# AppD collector segment -> Dynatrace source
_HTTP_SOURCES = {
    "parameter": "GET_PARAMETER",
    "parameters": "GET_PARAMETER",
    "requestparameter": "GET_PARAMETER",
    "getparameter": "GET_PARAMETER",
    "postparameter": "POST_PARAMETER",
    "header": "REQUEST_HEADER",
    "headers": "REQUEST_HEADER",
    "requestheader": "REQUEST_HEADER",
    "responseheader": "RESPONSE_HEADER",
    "sessionkey": "SESSION_ATTRIBUTE",
    "sessionkeys": "SESSION_ATTRIBUTE",
    "sessionattribute": "SESSION_ATTRIBUTE",
    "servervariable": "SERVER_VARIABLE",
    "uri": "URI",
    "url": "URI",
}

# AppD agent type -> Dynatrace technology (required for METHOD_PARAM)
_TECHNOLOGY = {
    "APP_AGENT": "JAVA", "JAVA": "JAVA", "JAVA_APP_AGENT": "JAVA",
    "DOTNET": "DOTNET", "DOT_NET_APP_AGENT": "DOTNET", ".NET": "DOTNET",
    "PHP": "PHP", "PHP_APP_AGENT": "PHP",
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


def _records(doc: Any) -> List[dict]:
    if isinstance(doc, list):
        return [r for r in doc if isinstance(r, dict)]
    if isinstance(doc, dict):
        for key in ("dataGathererConfigs", "methodInvocationDataCollectors",
                    "httpDataCollectors", "dataCollectors", "items"):
            v = _get(doc, key)
            if isinstance(v, list):
                return [r for r in v if isinstance(r, dict)]
        return [doc]
    return []


def _safe_name(name: str) -> str:
    cleaned = re.sub(r"\s+", " ", str(name or "").strip())
    return cleaned[:50] or "MigratedAttribute"


@dataclass
class RequestAttribute:
    name: str
    data_sources: List[dict] = field(default_factory=list)
    enabled: bool = True
    data_type: str = "STRING"
    aggregation: str = "ALL_DISTINCT_VALUES"
    normalization: str = "ORIGINAL"
    confidential: bool = False
    source_collector: str = ""
    needs_method_rule: bool = False

    def to_api(self) -> dict:
        """The Config API v1 body for this attribute."""
        return {
            "name": self.name,
            "enabled": self.enabled,
            "dataType": self.data_type,
            "normalization": self.normalization,
            "aggregation": self.aggregation,
            "confidential": self.confidential,
            "skipPersonalDataMasking": False,
            "dataSources": self.data_sources,
        }


@dataclass
class RequestAttributeResult:
    attributes: List[RequestAttribute] = field(default_factory=list)
    # Method collectors are described, never emitted — see _method_collector.
    method_collectors: List[dict] = field(default_factory=list)
    report: Report = field(default_factory=Report)


def _http_sources(rec: dict, report: Report, name: str) -> List[dict]:
    """Data sources from an AppD HTTP data collector."""
    sources: List[dict] = []

    for key, dt_source in (("parameters", "GET_PARAMETER"),
                           ("headers", "REQUEST_HEADER"),
                           ("sessionKeys", "SESSION_ATTRIBUTE")):
        values = _get(rec, key, default=None)
        if isinstance(values, str):
            values = [values]
        if not isinstance(values, list):
            continue
        for v in values:
            param = str(v).strip()
            if not param:
                continue
            sources.append({
                "enabled": True,
                "source": dt_source,
                "parameterName": param,
                "capturingAndStorageLocation": CAPTURE_SERVER,
            })

    # Cookies have no Dynatrace source; extract from the Cookie header instead.
    cookies = _get(rec, "cookies", "cookieNames", default=None)
    if isinstance(cookies, str):
        cookies = [cookies]
    if isinstance(cookies, list):
        for c in cookies:
            cookie = str(c).strip()
            if not cookie:
                continue
            sources.append({
                "enabled": True,
                "source": "REQUEST_HEADER",
                "parameterName": "Cookie",
                "capturingAndStorageLocation": CAPTURE_SERVER,
                "valueProcessing": {
                    "extractSubstring": None,
                    "splitAt": "",
                    "trim": True,
                    "valueExtractorRegex": re.escape(cookie) + r"=([^;]*)",
                    "valueCondition": None,
                },
            })
            report.warn(
                f"`{name}` captured cookie `{cookie}`. Dynatrace has no cookie source, so it "
                "reads the `Cookie` request header and extracts the value with a regex. "
                "Check the regex against a real header — cookie formatting varies.")
    return sources


def _method_collector(rec: dict, report: Report, name: str) -> Optional[dict]:
    """Describe a method invocation data collector without pretending to deploy it.

    Dynatrace's method rule requires a return type and a visibility on top of the
    class and method — neither of which an AppD export carries — and it matches
    against a process group where AppD matched a tier. A rule assembled from
    guesses passes `terraform validate`, applies without complaint, and then
    matches nothing: the captured attribute is simply always empty. So these are
    inventoried with everything the export *did* carry, and left for a human to
    finish in the UI where the class browser can confirm the signature.
    """
    class_name = str(_get(rec, "className", "classname", default="") or "").strip()
    method_name = str(_get(rec, "methodName", "methodname", default="") or "").strip()
    agent = str(_get(rec, "agentType", "technology", default="APP_AGENT") or "").upper()
    technology = _TECHNOLOGY.get(agent, "JAVA")

    if not (class_name or method_name):
        report.manual(
            f"`{name}` is a method collector with no class or method in the export, so there "
            "is nothing to carry across. Rebuild it as a request attribute by hand.")
        return None

    report.manual(
        f"`{name}` captures from `{class_name or '?'}.{method_name or '?'}` ({technology}). "
        "This is inventoried, not converted: a Dynatrace method rule also needs the return "
        "type and visibility, which the AppD export does not carry, and it matches on a "
        "process group where AppD matched a tier. A rule built from guesses applies cleanly "
        "and captures nothing. Create it under Settings > Server-side service monitoring > "
        "Request attributes, where the class browser confirms the real signature.")

    return {
        "name": name,
        "className": class_name,
        "methodName": method_name,
        "technology": technology,
        "capture": str(_get(rec, "dataGathererType", "capture", default="ARGUMENT") or ""),
        "argumentIndex": _get(rec, "parameterIndex", "argumentIndex", default=None),
    }


def looks_like_data_collectors(doc: Any) -> bool:
    if isinstance(doc, dict):
        for key in ("dataGathererConfigs", "methodInvocationDataCollectors",
                    "httpDataCollectors"):
            if _get(doc, key) is not None:
                return True
    for rec in _records(doc)[:50]:
        if _get(rec, "dataGathererType") is not None:
            return True
    return False


def translate_data_collectors(text_or_doc) -> RequestAttributeResult:
    doc = json.loads(text_or_doc) if isinstance(text_or_doc, (str, bytes)) else text_or_doc
    res = RequestAttributeResult()

    for rec in _records(doc):
        name = _safe_name(_get(rec, "name", "displayName", default="collector"))
        kind = str(_get(rec, "dataGathererType", "type", default="") or "").upper()

        is_http = "HTTP" in kind or any(
            _get(rec, k) is not None
            for k in ("parameters", "headers", "sessionKeys", "cookies"))

        if is_http:
            sources = _http_sources(rec, res.report, name)
            if not sources:
                continue
            res.attributes.append(RequestAttribute(
                name=name,
                data_sources=sources,
                source_collector=str(_get(rec, "name", default=name)),
            ))
        else:
            described = _method_collector(rec, res.report, name)
            if described:
                res.method_collectors.append(described)

    if not (res.attributes or res.method_collectors):
        res.report.manual("No data collectors recognised in this export.")
    if res.attributes:
        res.report.info(
            f"{len(res.attributes)} request attribute(s) built from HTTP collectors. Deploy "
            f"with `POST {{env}}{API_PATH}` (one body per attribute), or with the Terraform "
            "module, which creates them all in one apply.")
        res.report.info(
            "Request attributes capture from the moment they are created onward — they do "
            "not apply retrospectively, so create them before the traffic you want to "
            "analyse.")
    return res


def render_request_attributes(res: RequestAttributeResult, source: str = "") -> str:
    L: List[str] = ["# Request attributes (from AppDynamics data collectors)", ""]
    if source:
        L += [f"Source: `{source}`", ""]
    L += ["AppD data collectors capture method arguments, return values and HTTP request "
          "data. Dynatrace calls the same idea a **request attribute**.", ""]

    if res.attributes:
        L += [f"## Converted ({len(res.attributes)})", "",
              "Deployable now — from HTTP collectors, where the Dynatrace equivalent is exact.",
              "",
              "| Name | Captures from |", "|---|---|"]
        for a in res.attributes:
            kinds = ", ".join(sorted({s["source"] for s in a.data_sources}))
            L.append(f"| `{a.name}` | {kinds} |")
        L += ["",
              f"Deploy with `POST {{env}}{API_PATH}`, one body per attribute, or apply the "
              "Terraform module to create them together.", ""]

    if res.method_collectors:
        L += [f"## Build these by hand ({len(res.method_collectors)})", "",
              "Method invocation collectors. Dynatrace can capture the same values, but its "
              "method rule needs a **return type** and **visibility** that the AppD export "
              "does not carry, and it matches against a process group where AppD matched a "
              "tier. A rule assembled from guesses applies without error and then captures "
              "nothing at all, so these are listed rather than generated.",
              "",
              "| Attribute | Class | Method | Technology |", "|---|---|---|---|"]
        for m in res.method_collectors:
            L.append(f"| `{m['name']}` | `{m['className'] or '—'}` | "
                     f"`{m['methodName'] or '—'}` | {m['technology']} |")
        L += ["",
              "Create each under **Settings > Server-side service monitoring > Request "
              "attributes**, choosing *Java method* (or the matching technology) as the "
              "source. The class browser there confirms the real signature, which is the "
              "part that cannot be done offline.", ""]

    notes = res.report.format_deduped()
    if notes:
        L += ["## Notes", ""] + [f"- {n}" for n in notes] + [""]
    return "\n".join(L)
