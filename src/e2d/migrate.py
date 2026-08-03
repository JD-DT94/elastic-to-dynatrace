"""The `migrate` front door: point it at a folder of Elastic exports and it
auto-detects each artifact, converts everything it can, and writes one
plain-English report.

This is the hosting-agnostic core a friendly UI (local web app) wraps — it runs
entirely offline (stdlib only; the conversion engine makes no network calls) and
it surfaces any secrets found in the inputs rather than copying them into outputs.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from e2d.config import MappingConfig
from e2d.report import Report, Severity

# file-name suffixes we will look at
_KIBANA = (".ndjson",)
_ESQL = (".esql", ".es")
_LOGSTASH = (".conf",)
_TEXTQ = (".txt",)

# settings whose *values* are likely secrets — reported, never written to outputs.
_SECRET_KEY = re.compile(r"(pass(word)?|secret|token|api[_-]?key|credential|private[_-]?key)", re.I)


@dataclass
class Item:
    category: str          # dashboard | query | pipeline
    source: str            # input file (relative)
    status: str            # OK | REVIEW | MANUAL | ERROR
    outputs: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)


@dataclass
class MigrationSummary:
    items: List[Item] = field(default_factory=list)
    skipped: List[str] = field(default_factory=list)       # "file — why it was skipped"
    secrets: List[str] = field(default_factory=list)        # "file: key" where a secret was seen
    unmatched_indexes: List[str] = field(default_factory=list)  # index patterns with no index_map rule
    metrics_advisories: int = 0                             # tiles that could become ingest metrics
    dashboard_fields: Dict[str, List[str]] = field(default_factory=dict)  # source -> custom fields queried
    pipeline_fields: Dict[str, List[str]] = field(default_factory=dict)   # source -> fields produced at ingest
    ilm_policies: Dict[str, Optional[int]] = field(default_factory=dict)  # policy -> retention days (None: no delete)
    template_patterns: Dict[str, List[str]] = field(default_factory=dict)  # template -> index patterns

    def counts(self):
        c = {"OK": 0, "REVIEW": 0, "MANUAL": 0, "ERROR": 0}
        for it in self.items:
            c[it.status] = c.get(it.status, 0) + 1
        return c


# --------------------------------------------------------------------------- #
# classification
# --------------------------------------------------------------------------- #

def _looks_like_kibana_ndjson(text: str) -> bool:
    """Kibana saved-object export content: NDJSON lines of {type, attributes}."""
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            return False
        return isinstance(obj, dict) and "type" in obj and "attributes" in obj
    return False


def classify(path: Path, text: Optional[str] = None) -> str:
    suf = path.suffix.lower()
    if suf in _KIBANA:
        return "kibana"
    if suf in _ESQL:
        return "esql"
    if suf in _LOGSTASH:
        return "logstash"
    if suf == ".json":
        if text is None:
            try:
                text = path.read_text(encoding="utf-8")
            except OSError:
                return "unknown"
        try:
            doc = json.loads(text)
        except ValueError:
            # Kibana exports are NDJSON but often saved with a .json extension
            return "kibana" if _looks_like_kibana_ndjson(text) else "unknown"
        if isinstance(doc, list):
            if doc and all(isinstance(o, dict) and "type" in o and "attributes" in o for o in doc):
                return "kibana"
            return "unknown"
        if isinstance(doc, dict):
            if "type" in doc and "attributes" in doc:
                return "kibana"
            if "rule_type_id" in doc:
                return "alerting_rule"
            if "trigger" in doc and "input" in doc:
                return "watcher"
            if "pivot" in doc and "source" in doc:
                return "transform"
            if "processors" in doc:
                return "ingest"
            if "policy" in doc and isinstance(doc.get("policy"), dict) \
                    and "phases" in doc["policy"]:
                return "ilm_policy"
            if "index_patterns" in doc or "composed_of" in doc \
                    or ("template" in doc and isinstance(doc.get("template"), dict)):
                return "index_template"
            for k in ("match", "geo_match", "range"):
                body = doc.get(k)
                if isinstance(body, dict) and "enrich_fields" in body:
                    return "enrich_policy"
            if "indicator" in doc and ("objective" in doc or "budgetingMethod" in doc):
                return "slo"
            if any(k in doc for k in ("query", "aggs", "aggregations")):
                return "querydsl"
        return "unknown"
    if suf in _TEXTQ:
        return "querytext"
    if suf in (".yml", ".yaml"):
        if text is None:
            try:
                text = path.read_text(encoding="utf-8")
            except OSError:
                return "unknown"
        try:
            from e2d.yamlite import parse as _yparse
            from e2d.beats import detect_beat
            beat = detect_beat(_yparse(text))
            if beat:
                return beat
        except Exception:
            pass
        return "unknown"
    return "unknown"


def _status(report: Report) -> str:
    if report.has_blocking:
        return "MANUAL"
    if report.needs_review:
        return "REVIEW"
    return "OK"


def _scan_secrets(text: str, source: str, summary: MigrationSummary) -> None:
    for m in _SECRET_KEY.finditer(text):
        # only count when it looks like a key with a value: Logstash `key => "x"`
        # or JSON `"key": "x"` (the closing quote sits before the colon).
        tail = text[m.end():m.end() + 40]
        if re.match(r'\s*"?\s*(=>|:)\s*\S', tail):
            summary.secrets.append(f"{source}: {m.group(0).lower()}")


# --------------------------------------------------------------------------- #
# per-artifact conversion
# --------------------------------------------------------------------------- #

def _synthesize_dashboard(export, src: str):
    """Wrap a dashboard-less export (visualizations / lens / saved searches only)
    in a generated dashboard so every panel still converts to a tile."""
    from e2d.dashboards.kibana_loader import SavedObject

    panels, references = [], []
    i = 0
    for obj in export.objects:
        if obj.type not in ("visualization", "lens", "search"):
            continue
        i += 1
        idx = str(i)
        panels.append({"panelIndex": idx, "panelRefName": f"panel_{idx}",
                       "gridData": {"x": (i - 1) % 2 * 24, "y": (i - 1) // 2 * 12,
                                    "w": 24, "h": 12}})
        references.append({"name": f"{idx}:panel_{idx}", "type": obj.type, "id": obj.id})
    if not panels:
        return None
    title = f"Converted visualizations — {Path(src).stem}"
    return SavedObject(id=f"synth-{Path(src).stem}", type="dashboard",
                       attributes={"title": title, "panelsJSON": panels},
                       references=references)


def _do_kibana(text: str, src: str, out: Path, config: MappingConfig, summary: MigrationSummary) -> None:
    from e2d.dashboards.kibana_loader import KibanaExport
    from e2d.dashboards.converter import convert_dashboard, _safe_filename
    from e2d.dashboards.field_audit import audit_dashboard_fields, render_field_manifest
    from e2d.dashboards.metrics_advisor import advise_dashboard

    export = KibanaExport.load_text(text) if hasattr(KibanaExport, "load_text") else None
    if export is None:
        # KibanaExport.load takes a path; write text to a temp-less path under out
        tmp = out / "_input" / Path(src).name
        tmp.parent.mkdir(parents=True, exist_ok=True)
        tmp.write_text(text, encoding="utf-8")
        export = KibanaExport.load(str(tmp))

    # index patterns with no index_map rule -> collected for the suggested config
    for ip in export.of_type("index-pattern"):
        title = ip.attributes.get("title")
        if title and config.resolve_data_object(title) is None \
                and title not in summary.unmatched_indexes:
            summary.unmatched_indexes.append(title)

    dashboards = list(export.dashboards)
    synthesized = False
    if not dashboards:
        synth = _synthesize_dashboard(export, src)
        if synth is not None:
            dashboards = [synth]
            synthesized = True
    if not dashboards:
        kinds = sorted({o.type for o in export.objects}) or ["no objects"]
        summary.skipped.append(
            f"{src} — Kibana export contains no dashboards, visualizations or saved "
            f"searches (found: {', '.join(kinds)}); nothing convertible")
        return

    ddir = out / "dashboards"
    for d in dashboards:
        dashboard, report = convert_dashboard(d, export, config)
        if synthesized:
            report.info("This export contained no dashboard, only saved visualizations; "
                        "they were gathered onto one generated dashboard — re-arrange "
                        "the layout to taste.")
        ddir.mkdir(parents=True, exist_ok=True)
        base = _safe_filename(d.title)
        # Content document only — directly uploadable in the Dashboards app
        # (the `{name, type, content}` wrapper imports as a blank dashboard
        # there; deploy paths rebuild it from the filename).
        (ddir / f"{base}.json").write_text(json.dumps(dashboard["content"], indent=2),
                                           encoding="utf-8")
        outs = [f"dashboards/{base}.json"]
        audit = audit_dashboard_fields(dashboard)
        if audit["custom"]:
            merged = set(summary.dashboard_fields.get(src, [])) | set(audit["custom"])
            summary.dashboard_fields[src] = sorted(merged)
            (ddir / f"{base}.fields.md").write_text(
                render_field_manifest(dashboard["name"], audit), encoding="utf-8")
            outs.append(f"dashboards/{base}.fields.md")
        advisories = advise_dashboard(dashboard)
        summary.metrics_advisories += len(advisories)
        _pending_metric_advice(summary).extend(advisories)
        summary.items.append(Item("dashboard", src, _status(report), outs,
                                  report.format_deduped()))


def _pending_metric_advice(summary: MigrationSummary) -> List[dict]:
    """Advisories accumulate across every dashboard in the run; rendered once at
    the end into METRICS-GUIDE.md."""
    if not hasattr(summary, "_metric_advice"):
        summary._metric_advice = []  # type: ignore[attr-defined]
    return summary._metric_advice  # type: ignore[attr-defined]


def _do_query(text: str, src: str, out: Path, kind: str, config: MappingConfig,
              summary: MigrationSummary) -> None:
    qdir = out / "queries"
    qdir.mkdir(parents=True, exist_ok=True)
    base = Path(src).stem
    if kind == "esql":
        from e2d.esql.translator import translate_esql
        res = translate_esql(text, config)
        (qdir / f"{base}.dql").write_text(res.dql + "\n", encoding="utf-8")
        summary.items.append(Item("query", src, _status(res.report), [f"queries/{base}.dql"],
                                  res.report.format_deduped()))
    elif kind == "querydsl":
        from e2d.core.queries import convert_query_json
        res = convert_query_json(text, config, "logs")
        (qdir / f"{base}.dql").write_text(res.dql + "\n", encoding="utf-8")
        summary.items.append(Item("query", src, _status(res.report), [f"queries/{base}.dql"],
                                  res.report.format_deduped()))
    else:  # querytext (KQL/Lucene lines)
        from e2d.core.queries import convert_query_text
        results = convert_query_text(text, config, "logs", default_lang="kql")
        lines, notes, worst = [], [], "OK"
        for r in results:
            lines.append(f"# {r.source}\n{r.dql}")
            notes += r.report.format_deduped()
            worst = _worst(worst, _status(r.report))
        (qdir / f"{base}.dql").write_text("\n\n".join(lines) + "\n", encoding="utf-8")
        summary.items.append(Item("query", src, worst, [f"queries/{base}.dql"], notes))


def _do_pipeline(text: str, src: str, out: Path, kind: str, summary: MigrationSummary) -> None:
    from e2d.pipelines.translate import translate_pipeline, render_pipeline
    from e2d.pipelines.tf import write_openpipeline_tf
    if kind == "logstash":
        from e2d.pipelines.logstash import parse_logstash
        res = translate_pipeline(parse_logstash(text))
    else:
        from e2d.pipelines.ingest import translate_ingest
        res = translate_ingest(json.loads(text))

    from e2d.plan import fields_produced
    summary.pipeline_fields[src] = fields_produced([s.dql for s in res.stages if s.dql])

    base = Path(src).stem
    pdir = out / "pipelines"
    pdir.mkdir(parents=True, exist_ok=True)
    (pdir / f"{base}.dpl").write_text(render_pipeline(Path(src).name, res), encoding="utf-8")
    tf = write_openpipeline_tf(Path(src).name, res, str(out / "pipelines_tf" / base))
    summary.items.append(Item("pipeline", src, _status(res.report),
                              [f"pipelines/{base}.dpl", f"pipelines_tf/{base}/"],
                              res.report.format_deduped()))


def _do_alert(text: str, src: str, out: Path, config: MappingConfig, summary: MigrationSummary) -> None:
    from e2d.alerts import translate_alert, render_alert
    from e2d.alerts.tf import render_detectors_tf, has_terraform
    base = Path(src).stem
    res = translate_alert(text, config, name=base)
    adir = out / "alerts"
    adir.mkdir(parents=True, exist_ok=True)
    outs = [f"alerts/{base}.alert.md"]
    (adir / f"{base}.alert.md").write_text(render_alert(res.spec), encoding="utf-8")
    if res.spec.dql:
        (adir / f"{base}.dql").write_text(res.spec.dql + "\n", encoding="utf-8")
        outs.insert(0, f"alerts/{base}.dql")
    if has_terraform(res.spec):
        from e2d.alerts.tf import render_workflow_tf, needs_workflow
        from e2d.alerts.metrics import render_metric_creation
        tfdir = out / "alerts_tf" / base
        tfdir.mkdir(parents=True, exist_ok=True)
        (tfdir / "main.tf").write_text(render_detectors_tf(res.spec), encoding="utf-8")
        outs.append(f"alerts_tf/{base}/")
        metric_md = render_metric_creation(res.spec)
        if metric_md:
            (tfdir / "metric_creation.md").write_text(metric_md, encoding="utf-8")
        if needs_workflow(res.spec):
            (tfdir / "workflow.tf").write_text(render_workflow_tf(res.spec), encoding="utf-8")
    summary.items.append(Item("alert", src, _status(res.report), outs,
                              res.report.format_deduped()))


def _do_beat(text: str, src: str, out: Path, kind: str, summary: MigrationSummary) -> None:
    from e2d.yamlite import parse as yparse
    from e2d.beats import (translate_filebeat, translate_heartbeat,
                           render_shipper_guide, _section)
    doc = yparse(text)
    base = Path(src).stem
    if kind == "filebeat":
        res = translate_filebeat(doc, name=Path(src).name)
        sdir = out / "shippers"
        sdir.mkdir(parents=True, exist_ok=True)
        outs = []
        if res.otel_yaml:
            (sdir / f"{base}.otel.yaml").write_text(res.otel_yaml, encoding="utf-8")
            outs.append(f"shippers/{base}.otel.yaml")
        (sdir / f"{base}.md").write_text(
            render_shipper_guide(Path(src).name, "filebeat", res), encoding="utf-8")
        outs.append(f"shippers/{base}.md")
        summary.items.append(Item("shipper", src, _status(res.report), outs,
                                  res.report.format_deduped()))
    elif kind == "heartbeat":
        res = translate_heartbeat(doc)
        sdir = out / "synthetics"
        sdir.mkdir(parents=True, exist_ok=True)
        outs = []
        if res.monitors:
            (sdir / f"{base}.monitors.json").write_text(
                json.dumps(res.monitors, indent=2) + "\n", encoding="utf-8")
            outs.append(f"synthetics/{base}.monitors.json")
        (sdir / f"{base}.md").write_text(
            render_shipper_guide(Path(src).name, "heartbeat", res), encoding="utf-8")
        outs.append(f"synthetics/{base}.md")
        summary.items.append(Item("synthetic", src, _status(res.report), outs,
                                  res.report.format_deduped()))
    else:  # metricbeat
        modules = sorted({str(m.get("module", "?")) for m in _section(doc, "metricbeat", "modules")})
        sdir = out / "shippers"
        sdir.mkdir(parents=True, exist_ok=True)
        from e2d.beats import ShipperResult
        stub = ShipperResult()
        (sdir / f"{base}.md").write_text(
            render_shipper_guide(Path(src).name, "metricbeat", stub, modules=modules),
            encoding="utf-8")
        summary.items.append(Item("shipper", src, "REVIEW", [f"shippers/{base}.md"],
                                  ["Metricbeat has no mechanical conversion; wrote a "
                                   "guide mapping its modules to OneAgent and the "
                                   "Extensions Hub."]))


def _do_slo(text: str, src: str, out: Path, config: MappingConfig, summary: MigrationSummary) -> None:
    from e2d.slo import translate_slo, render_slo
    base = Path(src).stem
    res = translate_slo(text, config, name=base)
    sdir = out / "slos"
    sdir.mkdir(parents=True, exist_ok=True)
    outs = [f"slos/{base}.slo.md"]
    (sdir / f"{base}.slo.md").write_text(render_slo(res), encoding="utf-8")
    if res.dql:
        (sdir / f"{base}.dql").write_text(res.dql + "\n", encoding="utf-8")
        outs.insert(0, f"slos/{base}.dql")
    summary.items.append(Item("slo", src, _status(res.report), outs,
                              res.report.format_deduped()))


def _do_transform(text: str, src: str, out: Path, config: MappingConfig, summary: MigrationSummary) -> None:
    from e2d.transforms import translate_transform, render_transform
    base = Path(src).stem
    res = translate_transform(text, config, name=base)
    tdir = out / "transforms"
    tdir.mkdir(parents=True, exist_ok=True)
    (tdir / f"{base}.dql").write_text(res.dql + "\n", encoding="utf-8")
    (tdir / f"{base}.transform.md").write_text(render_transform(res), encoding="utf-8")
    summary.items.append(Item("transform", src, _status(res.report),
                              [f"transforms/{base}.dql", f"transforms/{base}.transform.md"],
                              res.report.format_deduped()))


def _worst(a: str, b: str) -> str:
    order = {"OK": 0, "REVIEW": 1, "MANUAL": 2, "ERROR": 3}
    return a if order[a] >= order[b] else b


# --------------------------------------------------------------------------- #
# Elastic cluster-config artifacts -> Dynatrace equivalents (advice, not code)
# --------------------------------------------------------------------------- #

def _do_config_advice(text: str, src: str, kind: str, out: Path,
                      summary: MigrationSummary) -> None:
    """ILM policies, index templates and enrich policies have no 1:1 Dynatrace
    object, but each has a clear Grail-side equivalent. Emit a short per-file
    advisory that names it and lists the concrete settings to carry over."""
    try:
        doc = json.loads(text)
    except ValueError:
        summary.skipped.append(f"{src} — unreadable JSON")
        return
    base = Path(src).stem
    cdir = out / "config_advice"
    L: List[str] = []

    if kind == "ilm_policy":
        L.append(f"# ILM policy `{base}` → Grail bucket retention")
        L.append("")
        L.append("Grail has no hot/warm/cold tiers — a log record lives in one **bucket** "
                 "with a single retention. Map the ILM lifetime to a bucket:")
        L.append("")
        phases = doc.get("policy", {}).get("phases", {})
        delete_age = phases.get("delete", {}).get("min_age", "—")
        from e2d.cutover import parse_min_age_days
        summary.ilm_policies[base] = parse_min_age_days(
            delete_age if delete_age != "—" else None)
        L.append(f"- Total lifetime in Elastic (delete phase `min_age`): **{delete_age}**")
        L.append("- Dynatrace: **Settings → Storage management → Bucket** — create/pick a "
                 "bucket with matching `retentionDays` and route these logs to it "
                 "(OpenPipeline → Storage stage).")
        L.append("- Rollover sizes/ages and shrink/forcemerge steps need no equivalent — "
                 "Grail manages storage automatically.")
    elif kind == "index_template":
        L.append(f"# Index template `{base}` → OpenPipeline routing")
        L.append("")
        pats = doc.get("index_patterns", [])
        if pats:
            summary.template_patterns[base] = list(pats)
            L.append(f"- Elastic index patterns: {', '.join('`%s`' % p for p in pats)}")
        L.append("- Dynatrace: index templates (mappings/settings) are unnecessary — Grail is "
                 "schema-on-read. What to carry over:")
        L.append("  - **Routing**: OpenPipeline → Logs → *Dynamic routing* on the source "
                 "attribute that distinguishes this data (e.g. `app_name`), into its own pipeline.")
        L.append("  - **Field types**: numeric fields used in dashboards should be converted "
                 "at ingest (processor: `fieldsAdd x = toLong(x)`) so aggregations work.")
        L.append("  - Add an `index_map` rule for these patterns in `mapping.config.json` so "
                 "converted queries target the right data object.")
    else:  # enrich_policy
        L.append(f"# Enrich policy `{base}` → Grail lookup")
        L.append("")
        body = next((doc[k] for k in ("match", "geo_match", "range") if k in doc), {})
        L.append(f"- Match field: `{body.get('match_field', '?')}`; enrich fields: "
                 + (", ".join(f"`{f}`" for f in body.get("enrich_fields", [])) or "?"))
        L.append("- Dynatrace equivalent — either:")
        L.append("  - **Query-time**: `| lookup [fetch <reference data>], sourceField:…, "
                 "lookupField:…` in DQL, or")
        L.append("  - **Ingest-time**: OpenPipeline processor referencing uploaded reference "
                 "data (Settings → OpenPipeline → Reference data).")

    cdir.mkdir(parents=True, exist_ok=True)
    (cdir / f"{base}.md").write_text("\n".join(L) + "\n", encoding="utf-8")
    summary.items.append(Item("config", src, "REVIEW", [f"config_advice/{base}.md"],
                              ["No 1:1 Dynatrace object exists for this artifact; wrote a "
                               "short guide with the equivalent settings to apply."]))


def _suggest_config(summary: MigrationSummary, out: Path) -> Optional[str]:
    """If dashboards referenced index patterns with no index_map rule, write a
    ready-to-edit mapping config so the next run resolves them explicitly."""
    if not summary.unmatched_indexes:
        return None
    rules = []
    seen = set()
    for pat in summary.unmatched_indexes:
        prefix = re.split(r"[*]", pat)[0].rstrip("-_.") or pat
        rule = "^" + re.escape(prefix)
        if rule not in seen:
            seen.add(rule)
            rules.append({"pattern": rule, "data_object": "logs"})
    cfg = {
        "_comment": "Generated from your export: every index pattern below had no "
                    "index_map rule and fell back to `logs`. Review each line — change "
                    "`data_object` where something should land elsewhere (e.g. spans) — "
                    "then re-run with --config (or drop this file in with your export).",
        "index_map": rules,
        "field_map": {},
    }
    path = out / "mapping.config.suggested.json"
    path.write_text(json.dumps(cfg, indent=2) + "\n", encoding="utf-8")
    return "mapping.config.suggested.json"


# --------------------------------------------------------------------------- #
# orchestration
# --------------------------------------------------------------------------- #

def run_migration(in_dir: str, out_dir: str, config: Optional[MappingConfig] = None) -> MigrationSummary:
    root = Path(in_dir)
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    summary = MigrationSummary()

    # A mapping config dropped in with the export is applied to the whole run.
    inline_cfg = next((p for p in sorted(root.rglob("mapping.config*.json"))), None)
    if inline_cfg is not None:
        try:
            config = MappingConfig.load(str(inline_cfg))
            summary.skipped.append(f"{inline_cfg.relative_to(root)} — mapping config; "
                                   "applied to this whole run")
        except (ValueError, OSError, KeyError) as e:
            summary.skipped.append(f"{inline_cfg.relative_to(root)} — mapping config could "
                                   f"not be read ({e}); run used defaults")
            inline_cfg = None
    config = config or MappingConfig()

    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        if inline_cfg is not None and path == inline_cfg:
            continue
        rel = str(path.relative_to(root))
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        kind = classify(path, text)
        if kind in ("logstash", "ingest", "querydsl", "watcher", "alerting_rule"):
            _scan_secrets(text, rel, summary)
        try:
            if kind == "kibana":
                _do_kibana(text, rel, out, config, summary)
            elif kind in ("esql", "querydsl", "querytext"):
                _do_query(text, rel, out, kind, config, summary)
            elif kind in ("logstash", "ingest"):
                _do_pipeline(text, rel, out, kind, summary)
            elif kind in ("watcher", "alerting_rule"):
                _do_alert(text, rel, out, config, summary)
            elif kind == "slo":
                _do_slo(text, rel, out, config, summary)
            elif kind in ("filebeat", "heartbeat", "metricbeat"):
                _do_beat(text, rel, out, kind, summary)
            elif kind == "transform":
                _do_transform(text, rel, out, config, summary)
            elif kind in ("ilm_policy", "index_template", "enrich_policy"):
                _do_config_advice(text, rel, kind, out, summary)
            else:
                summary.skipped.append(f"{rel} — {_skip_reason(path)}")
        except Exception as e:  # one bad file never aborts the whole migration
            summary.items.append(Item(kind, rel, "ERROR", [],
                                      [f"Conversion failed unexpectedly ({e}). Please report "
                                       "this file's shape — the rest of the migration continued."]))

    # log -> metric extraction guide, across every converted dashboard
    from e2d.dashboards.metrics_advisor import render_metrics_guide
    guide = render_metrics_guide(_pending_metric_advice(summary))
    if guide:
        (out / "METRICS-GUIDE.md").write_text(guide, encoding="utf-8")

    _suggest_config(summary, out)

    if summary.ilm_policies or summary.template_patterns:
        from e2d.cutover import render_cutover_plan
        (out / "CUTOVER-PLAN.md").write_text(
            render_cutover_plan(summary.ilm_policies, summary.template_patterns),
            encoding="utf-8")

    (out / "MIGRATION_REPORT.md").write_text(render_report(summary), encoding="utf-8")
    from e2d.score import report_payload
    (out / "migration_report.json").write_text(
        json.dumps(report_payload(summary), indent=2) + "\n", encoding="utf-8")
    return summary


_SKIP_REASONS = {
    ".yml": "YAML file that is not a recognisable Beats config; if it is reference data "
            "(e.g. a Logstash lookup table), upload it as OpenPipeline reference data",
    ".yaml": "YAML file that is not a recognisable Beats config; see the .yml note",
    ".md": "documentation, nothing to convert",
    ".txt": "not recognised as KQL/Lucene query lines",
    ".zip": "archives are read when uploaded directly; unzip and re-run if this was an export",
}


def _skip_reason(path: Path) -> str:
    return _SKIP_REASONS.get(path.suffix.lower(),
                             "not a recognised Elastic artifact (dashboard export, query, "
                             "pipeline, watcher/rule, transform, ILM/template/enrich policy)")


def render_report(summary: MigrationSummary) -> str:
    c = summary.counts()
    total = len(summary.items)
    ready = c["OK"]
    attention = c["REVIEW"] + c["MANUAL"] + c["ERROR"]
    L: List[str] = ["# Elastic → Dynatrace migration report", ""]
    L.append(f"We looked at your export and converted **{total}** item(s): "
             f"**{ready} ready to use**, **{attention} need a quick human check**.")
    L.append("")
    L.append("Everything ran **on this machine, offline**; none of your data left it.")
    L.append("")
    from e2d.score import build_scorecard, render_scorecard_md
    L.extend(render_scorecard_md(build_scorecard(summary)))
    L.append("| Status | Meaning |")
    L.append("|--------|---------|")
    L.append("| OK | Converted cleanly, ready to use. |")
    L.append("| REVIEW | Converted, but double-check it (reasons below). |")
    L.append("| MANUAL | Couldn't fully convert, needs a person. |")
    L.append("")

    from e2d.plan import build_plan, render_plan_md
    L.extend(render_plan_md(build_plan(summary)))

    if summary.ilm_policies or summary.template_patterns:
        L.append("## Cutover")
        L.append("")
        L.append("Dynatrace rejects log records older than 24 hours, so history "
                 "cannot be replayed after the fact. **`CUTOVER-PLAN.md`** next to "
                 "this report turns your ILM retention into a dual-ship schedule, "
                 "Grail bucket definitions, and a decommission timeline. Use "
                 "`e2d backfill` for the indexes whose history must live in "
                 "Dynatrace (records are re-stamped; the true event time is kept "
                 "in `original_timestamp`).")
        L.append("")

    for cat, title in (("dashboard", "Dashboards"), ("query", "Queries"), ("pipeline", "Pipelines"),
                       ("alert", "Alerts & watchers"), ("slo", "SLOs"),
                       ("shipper", "Shippers & agents"), ("synthetic", "Synthetic monitors"),
                       ("transform", "Transforms"),
                       ("config", "Cluster config (ILM / templates / enrich)")):
        rows = [it for it in summary.items if it.category == cat]
        if not rows:
            continue
        L.append(f"## {title} ({len(rows)})")
        L.append("")
        L.append("| Status | Item | Output |")
        L.append("|--------|------|--------|")
        for it in rows:
            L.append(f"| {it.status} | `{it.source}` | {', '.join(f'`{o}`' for o in it.outputs) or '—'} |")
        L.append("")

    flagged = [it for it in summary.items if it.status in ("REVIEW", "MANUAL", "ERROR")]
    if flagged:
        L.append("## What needs your attention")
        L.append("")
        L.append("Grouped by what to do: **rebuild by hand** → **double-check** → "
                 "automatic adjustments (usually fine, listed for completeness).")
        L.append("")
        for it in flagged:
            L.append(f"### `{it.source}`: {it.status}")
            L.append("")
            notes = list(dict.fromkeys(it.notes))
            manual = [n for n in notes if n.startswith("[MANUAL]")]
            warn = [n for n in notes if n.startswith("[WARN]") or n.startswith("conversion failed")]
            info = [n for n in notes if n.startswith("[INFO]")]
            other = [n for n in notes if n not in manual and n not in warn and n not in info]
            if manual:
                L.append("**Rebuild by hand:**")
                for n in manual:
                    L.append(f"- {n[len('[MANUAL] '):]}")
                L.append("")
            if warn or other:
                L.append("**Double-check:**")
                for n in warn + other:
                    L.append(f"- {n[len('[WARN] '):] if n.startswith('[WARN]') else n}")
                L.append("")
            if info:
                L.append(f"<details><summary>{len(info)} automatic adjustment(s) — "
                         "no action needed</summary>")
                L.append("")
                for n in info:
                    L.append(f"- {n[len('[INFO] '):]}")
                L.append("")
                L.append("</details>")
            L.append("")

    if summary.secrets:
        L.append("## Security")
        L.append("")
        L.append("Possible credentials were seen in the inputs below. They were **not** copied into "
                 "any output — replace them with your Dynatrace-side secrets when deploying:")
        L.append("")
        for s in dict.fromkeys(summary.secrets):
            L.append(f"- `{s}`")
        L.append("")

    if summary.metrics_advisories:
        L.append("## Consider metrics for the busiest tiles")
        L.append("")
        L.append(f"**{summary.metrics_advisories}** time-series tile(s) chart raw log queries. "
                 "They work as-is, but for tiles you keep long-term, extracting the number "
                 "into a **metric at ingest** is cheaper, faster, and retained longer. "
                 "**`METRICS-GUIDE.md`** in this folder walks through each one: the "
                 "OpenPipeline metric-extraction settings and the `timeseries` query to "
                 "switch the tile to afterwards.")
        L.append("")

    if summary.unmatched_indexes:
        L.append("## Index mapping")
        L.append("")
        L.append("These Elastic index patterns had no mapping rule, so their panels default "
                 "to the `logs` data object:")
        L.append("")
        for ix in summary.unmatched_indexes:
            L.append(f"- `{ix}`")
        L.append("")
        L.append("A ready-to-edit **`mapping.config.suggested.json`** was written next to this "
                 "report — review it (change any `data_object` that shouldn't be `logs`), then "
                 "re-run with the file included to make the mapping explicit and silence the "
                 "warnings.")
        L.append("")

    if summary.skipped:
        L.append("## Not converted (with reasons)")
        L.append("")
        for s in summary.skipped:
            L.append(f"- `{s}`")
        L.append("")

    return "\n".join(L) + "\n"
