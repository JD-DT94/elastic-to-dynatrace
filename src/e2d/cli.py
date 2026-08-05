"""Command-line interface for elastic-to-dynatrace (`e2d`).

Subcommands
-----------
  convert    Translate a single ES|QL file (or stdin) to DQL.
  batch      Bulk-translate every ES|QL file in a directory tree.
  dashboard  Convert a Kibana dashboard JSON to a Dynatrace dashboard  [phase 2].
  pipeline   Translate a Logstash .conf into OpenPipeline DQL/DPL stages.
  push       Upload generated artifacts to a Dynatrace environment      [phase 3].
  web        Launch the local web GUI (offline) wrapping `migrate`.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import List, Optional

from e2d.config import MappingConfig
from e2d.esql.translator import translate_esql
from e2d.report import Severity

ESQL_SUFFIXES = (".esql", ".es", ".txt")


def _load_config(path: Optional[str]) -> MappingConfig:
    return MappingConfig.load(path)


def _print_report(result, stream, show_info: bool) -> None:
    for w in result.report.warnings:
        if w.severity is Severity.INFO and not show_info:
            continue
        print("  " + w.format(), file=stream)


# --------------------------------------------------------------------------- #
# convert
# --------------------------------------------------------------------------- #

def cmd_convert(args: argparse.Namespace) -> int:
    config = _load_config(args.config)
    if args.input == "-":
        query = sys.stdin.read()
    else:
        query = Path(args.input).read_text(encoding="utf-8")

    result = translate_esql(query, config)

    out_text = result.dql + "\n"
    if args.output:
        Path(args.output).write_text(out_text, encoding="utf-8")
        print(f"Wrote DQL -> {args.output}", file=sys.stderr)
    else:
        sys.stdout.write(out_text)

    if result.report.warnings:
        print("\nConversion notes:", file=sys.stderr)
        _print_report(result, sys.stderr, show_info=args.verbose)

    return 1 if (args.strict and result.report.has_blocking) else 0


# --------------------------------------------------------------------------- #
# batch
# --------------------------------------------------------------------------- #

def cmd_batch(args: argparse.Namespace) -> int:
    config = _load_config(args.config)
    in_dir = Path(args.input)
    out_dir = Path(args.output)
    if not in_dir.is_dir():
        print(f"error: {in_dir} is not a directory", file=sys.stderr)
        return 2

    files = [p for p in sorted(in_dir.rglob("*")) if p.suffix.lower() in ESQL_SUFFIXES]
    if not files:
        print(f"No ES|QL files ({', '.join(ESQL_SUFFIXES)}) found under {in_dir}", file=sys.stderr)
        return 0

    summary_lines: List[str] = []
    n_clean = n_review = n_blocked = 0

    for src in files:
        rel = src.relative_to(in_dir)
        dst = (out_dir / rel).with_suffix(".dql")
        dst.parent.mkdir(parents=True, exist_ok=True)
        query = src.read_text(encoding="utf-8")
        result = translate_esql(query, config)
        dst.write_text(result.dql + "\n", encoding="utf-8")

        if result.report.has_blocking:
            status = "MANUAL"
            n_blocked += 1
        elif result.report.needs_review:
            status = "REVIEW"
            n_review += 1
        else:
            status = "OK"
            n_clean += 1

        summary_lines.append(f"[{status:6}] {rel}  ->  {dst.relative_to(out_dir)}")
        for w in result.report.warnings:
            if w.severity is Severity.INFO and not args.verbose:
                continue
            summary_lines.append(f"           {w.format()}")

    report_text = "\n".join(summary_lines)
    print(report_text)
    print(f"\nTotal: {len(files)}  |  OK: {n_clean}  REVIEW: {n_review}  MANUAL: {n_blocked}",
          file=sys.stderr)

    if args.report:
        Path(args.report).write_text(report_text + "\n", encoding="utf-8")
        print(f"Report -> {args.report}", file=sys.stderr)

    return 1 if (args.strict and n_blocked) else 0


# --------------------------------------------------------------------------- #
# dashboard / push  (phase 2 & 3 - wired but not yet implemented)
# --------------------------------------------------------------------------- #

def cmd_query(args: argparse.Namespace) -> int:
    from e2d.core.queries import (
        convert_query_json, convert_query_text, looks_like_json,
    )

    config = _load_config(args.config)
    data_object = args.data_object
    text = sys.stdin.read() if args.input == "-" else Path(args.input).read_text(encoding="utf-8")

    is_json = looks_like_json(text) if not args.lang or args.lang == "auto" else (args.lang == "dsl")
    if args.lang == "dsl" or (args.lang in (None, "auto") and is_json):
        result = convert_query_json(text, config, data_object)
        out = result.dql + "\n"
        if args.output:
            Path(args.output).write_text(out, encoding="utf-8")
            print(f"Wrote DQL -> {args.output}", file=sys.stderr)
        else:
            sys.stdout.write(out)
        if result.report.warnings:
            print("\nConversion notes:", file=sys.stderr)
            _print_report(result, sys.stderr, show_info=args.verbose)
        return 1 if (args.strict and result.report.has_blocking) else 0

    # text: one filter per line (KQL / Lucene)
    default_lang = args.lang if args.lang in ("kql", "lucene") else "kql"
    results = convert_query_text(text, config, data_object, default_lang=default_lang)
    blocking = False
    for r in results:
        print(f"# {r.source}")
        print(r.dql)
        for w in r.report.warnings:
            if w.severity is Severity.INFO and not args.verbose:
                continue
            print(f"  {w.format()}", file=sys.stderr)
        blocking = blocking or r.report.has_blocking
        print()
    return 1 if (args.strict and blocking) else 0


def cmd_dashboard(args: argparse.Namespace) -> int:
    from e2d.dashboards.converter import convert_dashboard_file
    from e2d.dashboards.kibana_loader import KibanaExport

    if args.list:
        export = KibanaExport.load(args.input)
        for d in export.dashboards:
            panels = d.attributes.get("panelsJSON", []) or []
            print(f"{len(panels):3d} panels  {d.title}")
        print(f"\n{len(export.dashboards)} dashboards", file=sys.stderr)
        return 0
    return convert_dashboard_file(args)


def cmd_pipeline(args: argparse.Namespace) -> int:
    import json
    from e2d.pipelines.ingest import looks_like_ingest_json, translate_ingest
    from e2d.pipelines.logstash import parse_logstash
    from e2d.pipelines.translate import translate_pipeline, render_pipeline

    name = "stdin" if args.input == "-" else Path(args.input).name
    text = sys.stdin.read() if args.input == "-" else Path(args.input).read_text(encoding="utf-8")

    # auto-detect: Elasticsearch ingest-pipeline JSON vs Logstash .conf
    forced = getattr(args, "lang", "auto")
    if forced == "ingest" or (forced == "auto" and looks_like_ingest_json(text)):
        res = translate_ingest(json.loads(text))
    else:
        res = translate_pipeline(parse_logstash(text))

    apply = getattr(args, "apply", False)
    if getattr(args, "terraform", False) or apply:
        import os
        from e2d.pipelines.tf import write_openpipeline_tf
        if not args.output:
            print("error: --terraform/--apply requires -o <output directory>", file=sys.stderr)
            return 2
        summary = write_openpipeline_tf(name, res, args.output)
        print(f"Wrote dynatrace_openpipeline_logs module ({summary['processors']} processors) "
              f"-> {summary['dir']}", file=sys.stderr)
        if apply or getattr(args, "plan", False):
            from e2d.pipelines.deploy import run_deploy
            return run_deploy(args.output, apply=apply, env=dict(os.environ))
    else:
        out_text = render_pipeline(name, res)
        if args.output:
            Path(args.output).write_text(out_text, encoding="utf-8")
            print(f"Wrote OpenPipeline stages -> {args.output}", file=sys.stderr)
        else:
            sys.stdout.write(out_text)

    status = "MANUAL" if res.report.has_blocking else ("REVIEW" if res.report.needs_review else "OK")
    print(f"\n[{status}] {name}", file=sys.stderr)
    return 1 if (args.strict and res.report.has_blocking) else 0


def cmd_migrate(args: argparse.Namespace) -> int:
    from e2d.migrate import run_migration
    config = _load_config(args.config)
    if not Path(args.input).is_dir():
        print(f"error: {args.input} is not a directory", file=sys.stderr)
        return 2
    summary = run_migration(args.input, args.output, config, emit=args.emit)
    c = summary.counts()
    print(f"\nMigrated {len(summary.items)} item(s): "
          f"{c['OK']} OK, {c['REVIEW']} REVIEW, {c['MANUAL']} MANUAL, {c['ERROR']} ERROR  "
          f"| {len(summary.skipped)} skipped", file=sys.stderr)
    print(f"Report -> {Path(args.output) / 'MIGRATION_REPORT.md'}", file=sys.stderr)
    if summary.secrets:
        print(f"⚠ {len(set(summary.secrets))} possible secret(s) seen in inputs (not copied to outputs) "
              "— see the report's Security section.", file=sys.stderr)
    return 1 if (args.strict and (c["MANUAL"] or c["ERROR"])) else 0


def cmd_push(args: argparse.Namespace) -> int:
    from e2d.api.client import push_cli
    return push_cli(args)


def cmd_alert(args: argparse.Namespace) -> int:
    from e2d.alerts import translate_alert, render_alert
    from e2d.alerts.tf import render_detectors_tf, has_terraform
    config = _load_config(args.config)
    text = sys.stdin.read() if args.input == "-" else Path(args.input).read_text(encoding="utf-8")
    name = None if args.input == "-" else Path(args.input).stem
    res = translate_alert(text, config, name=name)
    if args.terraform:
        from e2d.alerts.tf import render_workflow_tf, needs_workflow
        from e2d.alerts.metrics import render_metric_creation
        out_dir = Path(args.output or ".")
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "main.tf").write_text(render_detectors_tf(res.spec), encoding="utf-8")
        wrote = [f"main.tf ({len(res.spec.detectors)} detector(s))"]
        metric_md = render_metric_creation(res.spec)
        if metric_md:
            (out_dir / "metric_creation.md").write_text(metric_md, encoding="utf-8")
            wrote.append("metric_creation.md")
        if needs_workflow(res.spec):
            (out_dir / "workflow.tf").write_text(render_workflow_tf(res.spec), encoding="utf-8")
            wrote.append("workflow.tf")
        print(f"Wrote {', '.join(wrote)} -> {out_dir}", file=sys.stderr)
        if not has_terraform(res.spec):
            print("warning: no threshold could be derived — review the alert by hand.", file=sys.stderr)
    else:
        plan = render_alert(res.spec)
        if args.output:
            Path(args.output).write_text(plan, encoding="utf-8")
            print(f"Alert plan -> {args.output}", file=sys.stderr)
        else:
            print(plan)
    _print_report(res, sys.stderr, args.verbose)
    return 1 if (args.strict and res.report.has_blocking) else 0


def cmd_verify(args: argparse.Namespace) -> int:
    from e2d.api.client import verify_cli
    return verify_cli(args)


def cmd_backfill(args: argparse.Namespace) -> int:
    from e2d.backfill import backfill_cli
    return backfill_cli(args)


def cmd_parity(args: argparse.Namespace) -> int:
    from e2d.parity import parity_cli
    return parity_cli(args)


def cmd_assess(args: argparse.Namespace) -> int:
    """Assessment-only: convert into a scratch directory, print the scorecard,
    keep nothing. Exit 0 = clean, 2 = manual work present, 1 = converter errors."""
    import json
    import tempfile
    from e2d.migrate import run_migration
    from e2d.score import report_payload, scorecard_line
    config = _load_config(args.config)
    if not Path(args.input).is_dir():
        print(f"error: {args.input} is not a directory", file=sys.stderr)
        return 2
    with tempfile.TemporaryDirectory() as td:
        summary = run_migration(args.input, td, config)
        payload = report_payload(summary)
    sc = payload["scorecard"]
    print(scorecard_line(sc))
    if sc["by_category"]:
        w = max(len(c) for c in sc["by_category"])
        print(f"\n{'CATEGORY':{w}}  TOTAL  EXACT  APPROX  MANUAL")
        for cat in sorted(sc["by_category"]):
            r = sc["by_category"][cat]
            print(f"{cat:{w}}  {r['total']:5}  {r['exact']:5}  "
                  f"{r['approximate']:6}  {r['manual']:6}")
    for s in payload["skipped"]:
        print(f"skipped: {s}", file=sys.stderr)
    if args.json:
        Path(args.json).write_text(json.dumps(payload, indent=2) + "\n",
                                   encoding="utf-8")
        print(f"\nJSON report -> {args.json}", file=sys.stderr)
    if sc["counts"]["failed"]:
        return 1
    return 2 if sc["counts"]["manual"] else 0


def cmd_web(args: argparse.Namespace) -> int:
    from e2d.web import serve
    config = _load_config(args.config)
    serve(host=args.host, port=args.port, open_browser=not args.no_browser, config=config)
    return 0


# --------------------------------------------------------------------------- #
# arg parsing
# --------------------------------------------------------------------------- #

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="e2d",
        description="Convert Elastic and AppDynamics artifacts to Dynatrace.")
    sub = p.add_subparsers(dest="command", required=True)

    c = sub.add_parser("convert", help="Translate one ES|QL file (or - for stdin) to DQL.")
    c.add_argument("input", help="ES|QL file path, or - for stdin")
    c.add_argument("-o", "--output", help="Write DQL here (default: stdout)")
    c.add_argument("--config", help="Mapping config JSON")
    c.add_argument("-v", "--verbose", action="store_true", help="Show INFO notes too")
    c.add_argument("--strict", action="store_true", help="Exit non-zero if any MANUAL items remain")
    c.set_defaults(func=cmd_convert)

    b = sub.add_parser("batch", help="Bulk-translate a directory of ES|QL files.")
    b.add_argument("input", help="Input directory")
    b.add_argument("-o", "--output", required=True, help="Output directory")
    b.add_argument("--config", help="Mapping config JSON")
    b.add_argument("--report", help="Write the run summary to this file")
    b.add_argument("-v", "--verbose", action="store_true", help="Show INFO notes too")
    b.add_argument("--strict", action="store_true", help="Exit non-zero if any file has MANUAL items")
    b.set_defaults(func=cmd_batch)

    q = sub.add_parser("query", help="Translate Elastic Query DSL / KQL / Lucene to DQL.")
    q.add_argument("input", help="Query file (.json DSL, or .txt of KQL/Lucene lines), or - for stdin")
    q.add_argument("-o", "--output", help="Write DQL here (default: stdout); DSL input only")
    q.add_argument("--lang", choices=["auto", "dsl", "kql", "lucene"], default="auto",
                   help="Force the input dialect (default: auto-detect)")
    q.add_argument("--data-object", default="logs",
                   help="Dynatrace data object to fetch (default: logs)")
    q.add_argument("--config", help="Mapping config JSON")
    q.add_argument("-v", "--verbose", action="store_true", help="Show INFO notes too")
    q.add_argument("--strict", action="store_true", help="Exit non-zero on MANUAL items")
    q.set_defaults(func=cmd_query)

    d = sub.add_parser("dashboard", help="Convert Kibana dashboards (NDJSON export) to Dynatrace.")
    d.add_argument("input", help="Kibana dashboard / saved-object export (NDJSON or JSON)")
    d.add_argument("-o", "--output", help="Output file (single match) or directory (multiple)")
    d.add_argument("--config", help="Mapping config JSON")
    d.add_argument("--title", help="Only convert dashboards whose title contains this substring")
    d.add_argument("--list", action="store_true", help="List dashboards in the export and exit")
    d.add_argument("-v", "--verbose", action="store_true", help="Show INFO notes too")
    d.add_argument("--terraform", action="store_true", help="Emit a Terraform dynatrace_document instead of raw JSON")
    d.set_defaults(func=cmd_dashboard)

    pl = sub.add_parser("pipeline",
                        help="Translate a Logstash .conf or Elasticsearch ingest JSON into OpenPipeline DQL/DPL.")
    pl.add_argument("input", help="Logstash .conf or ingest-pipeline JSON file, or - for stdin")
    pl.add_argument("-o", "--output", help="Write the OpenPipeline stages here (default: stdout)")
    pl.add_argument("--lang", choices=["auto", "logstash", "ingest"], default="auto",
                    help="Force the input dialect (default: auto-detect)")
    pl.add_argument("--terraform", action="store_true",
                    help="Emit a deployable dynatrace_openpipeline_logs Terraform module (needs -o <dir>)")
    pl.add_argument("--plan", action="store_true",
                    help="After writing the module, run `terraform init && terraform plan` (dry run)")
    pl.add_argument("--apply", action="store_true",
                    help="After writing the module, run `terraform init && terraform apply` (deploys!)")
    pl.add_argument("--config", help="Mapping config JSON")
    pl.add_argument("-v", "--verbose", action="store_true", help="Show INFO notes too")
    pl.add_argument("--strict", action="store_true", help="Exit non-zero if any MANUAL items remain")
    pl.set_defaults(func=cmd_pipeline)

    m = sub.add_parser("migrate",
                       help="One-shot: point at a folder of Elastic or AppDynamics exports, "
                            "convert everything, write a report.")
    m.add_argument("input", help="Folder of exports — Elastic (.ndjson/.esql/.conf/.json/.txt) "
                                 "and/or AppDynamics (health rules, dashboards, "
                                 "application/tier/node inventory, policies/actions as .json)")
    m.add_argument("-o", "--output", required=True, help="Output directory for converted artifacts + report")
    m.add_argument("--config", help="Mapping config JSON")
    m.add_argument("--emit", choices=["json", "tf", "both"], default="both",
                   help="Deployable format for alerts/pipelines: 'json' = Settings-API upload "
                        "files (no Terraform needed), 'tf' = Terraform modules, 'both' (default)")
    m.add_argument("--strict", action="store_true", help="Exit non-zero if any item is MANUAL/ERROR")
    m.add_argument("-v", "--verbose", action="store_true", help="(reserved) show INFO notes")
    m.set_defaults(func=cmd_migrate)

    u = sub.add_parser("push", help="Upload converted dashboard JSON to Dynatrace (Document API).")
    u.add_argument("input", help="Dashboard JSON file or directory of them")
    u.add_argument("--env-url", help="Dynatrace env URL (or set DYNATRACE_ENV_URL)")
    u.add_argument("--token-env", default="DT_API_TOKEN",
                   help="Env var holding the platform token (default: DT_API_TOKEN)")
    u.add_argument("--apply", action="store_true",
                   help="Actually create documents (default is a dry run)")
    u.set_defaults(func=cmd_push)

    a = sub.add_parser("alert",
                       help="Translate an Elastic Watcher or Kibana alerting rule to DQL + an alert plan.")
    a.add_argument("input", help="Watcher/rule JSON file, or - for stdin")
    a.add_argument("-o", "--output", help="Output dir (--terraform) or plan file (default: stdout)")
    a.add_argument("--terraform", action="store_true",
                   help="Emit a deployable dynatrace_davis_anomaly_detectors module instead of a plan")
    a.add_argument("--config", help="Mapping config JSON")
    a.add_argument("-v", "--verbose", action="store_true", help="Show INFO notes too")
    a.add_argument("--strict", action="store_true", help="Exit non-zero if anything is MANUAL")
    a.set_defaults(func=cmd_alert)

    v = sub.add_parser("verify",
                       help="Validate converted DQL against a Dynatrace tenant (authoritative).")
    v.add_argument("input", help="Converted output dir (or a .dql / dashboard .json file)")
    v.add_argument("--env-url", help="Dynatrace env URL (or set DYNATRACE_ENV_URL)")
    v.add_argument("--token-env", default="DT_API_TOKEN",
                   help="Env var holding the platform token (default: DT_API_TOKEN)")
    v.add_argument("--data", action="store_true",
                   help="Also execute each valid query and flag ones returning no data "
                        "(a tile with a missing custom attribute renders blank, not broken)")
    v.set_defaults(func=cmd_verify)

    ax = sub.add_parser(
        "assess",
        help="Assessment-only: convert to a scratch dir, print the scorecard and "
             "per-category table, keep nothing. Exit 0 = clean, 2 = manual work "
             "present, 1 = converter errors; suits CI gates.")
    ax.add_argument("input", help="Folder containing Elastic and/or AppDynamics exports")
    ax.add_argument("--json", help="Write the machine-readable report to this file")
    ax.add_argument("--config", help="Mapping config JSON")
    ax.set_defaults(func=cmd_assess)

    pr = sub.add_parser(
        "parity",
        help="Compare counts between the original Elastic queries and the converted "
             "DQL over the same window (dual-ship validation).")
    pr.add_argument("input", help="Folder holding the original Elastic query files")
    pr.add_argument("--es-url", required=True, help="Elasticsearch URL")
    pr.add_argument("--index", required=True, help="Index or pattern both stacks receive")
    pr.add_argument("--es-token-env", default="ES_API_KEY",
                    help="Env var holding the Elasticsearch API key (default: ES_API_KEY)")
    pr.add_argument("--es-auth", choices=["ApiKey", "Bearer"], default="ApiKey")
    pr.add_argument("--env-url", help="Dynatrace env URL (or set DYNATRACE_ENV_URL)")
    pr.add_argument("--token-env", default="DT_API_TOKEN",
                    help="Env var holding the Dynatrace token (default: DT_API_TOKEN)")
    pr.add_argument("--window", default="2h",
                    help="Relative window both sides are counted over (default: 2h)")
    pr.add_argument("--tolerance", type=float, default=0.02,
                    help="Relative drift that still counts as a match (default: 0.02)")
    pr.add_argument("--config", help="Mapping config JSON")
    pr.add_argument("--insecure", action="store_true", help="Skip TLS verification for Elasticsearch")
    pr.set_defaults(func=cmd_parity)

    bf = sub.add_parser(
        "backfill",
        help="Copy historical logs from Elasticsearch into Dynatrace despite the "
             "24h ingest wall: records are re-stamped into the accepted window and "
             "the true event time is kept in an original_timestamp attribute.")
    bf.add_argument("--es-url", required=True, help="Elasticsearch URL (https://es:9200)")
    bf.add_argument("--index", help="Index/pattern to read, or a comma-separated list "
                                    "(e.g. logs-app-*,logs-nginx-*)")
    bf.add_argument("--discover", action="store_true",
                    help="List matching indices with doc counts and time ranges, then exit")
    bf.add_argument("--from", dest="time_from", default="",
                    help="Start of the original time window (ISO 8601)")
    bf.add_argument("--to", dest="time_to", default="",
                    help="End of the original time window (ISO 8601)")
    bf.add_argument("--query", help="Optional Lucene query_string to narrow the pull")
    bf.add_argument("--timestamp-field", default="@timestamp",
                    help="Source timestamp field (default: @timestamp)")
    bf.add_argument("--es-token-env", default="ES_API_KEY",
                    help="Env var holding the Elasticsearch API key (default: ES_API_KEY)")
    bf.add_argument("--es-auth", choices=["ApiKey", "Bearer"], default="ApiKey",
                    help="Elasticsearch Authorization scheme (default: ApiKey)")
    bf.add_argument("--env-url", help="Dynatrace env URL (or set DYNATRACE_ENV_URL)")
    bf.add_argument("--token-env", default="DT_API_TOKEN",
                    help="Env var holding the Dynatrace token (default: DT_API_TOKEN)")
    bf.add_argument("--stamp", choices=["spread", "now"], default="spread",
                    help="spread: map the original range onto the last ~23h, keeping shape "
                         "(default); now: stamp everything with ingest time")
    bf.add_argument("--page-size", type=int, default=1000, help="ES page size (default: 1000)")
    bf.add_argument("--limit", type=int, default=0, help="Stop after N records (0 = all)")
    bf.add_argument("--state", help="Checkpoint file (default: one per index in the "
                                    "working directory); interrupted --apply runs resume "
                                    "from it instead of duplicating")
    bf.add_argument("--no-state", action="store_true", help="Disable checkpointing")
    bf.add_argument("--dlq", help="Dead-letter file for permanently rejected batches "
                                  "(default: next to the state file)")
    bf.add_argument("--redrive", help="Re-send records from a dead-letter file, then exit")
    bf.add_argument("--classic", action="store_true",
                    help="Use the classic /api/v2/logs/ingest endpoint with an Api-Token "
                         "(scope logs.ingest) instead of the platform endpoint")
    bf.add_argument("--insecure", action="store_true", help="Skip TLS verification for Elasticsearch")
    bf.add_argument("--apply", action="store_true", help="Actually ingest (default: dry run)")
    bf.set_defaults(func=cmd_backfill)

    w = sub.add_parser("web",
                       help="Launch the local web GUI (offline; data stays on this machine).")
    w.add_argument("--host", default="127.0.0.1",
                   help="Bind address (default: 127.0.0.1 — localhost only)")
    w.add_argument("--port", type=int, default=8765, help="Port (default: 8765)")
    w.add_argument("--no-browser", action="store_true", help="Don't auto-open a browser")
    w.add_argument("--config", help="Mapping config JSON")
    w.set_defaults(func=cmd_web)

    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
