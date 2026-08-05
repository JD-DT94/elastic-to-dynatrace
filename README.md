# migration assist (`e2d`)

Convert **Elastic / Kibana** and **AppDynamics** artifacts into Dynatrace
equivalents: dashboards, alerts, ingest pipelines, transforms, queries — and,
for AppDynamics, a OneAgent onboarding plan sized by host.

## Use it in the browser (nothing to install)

**https://jd-dt94.github.io/elastic-to-dynatrace/**

Drag an export onto the page, click **Convert**, download the results.
Everything runs inside your browser tab (Python compiled to WebAssembly) —
your files are never uploaded anywhere.

[![Open in GitHub Codespaces](https://github.com/codespaces/badge.svg)](https://codespaces.new/JD-DT94/elastic-to-dynatrace?quickstart=1)

## What converts

| Input | Output |
|-------|--------|
| Kibana dashboard exports (`.ndjson`) — Lens (incl. formulas), TSVB, legacy visualizations, saved searches, controls, Vega with embedded ES queries | Dynatrace dashboard JSON (DQL tiles, variables, series colors) |
| Watchers and Kibana alerting rules | Davis anomaly detectors + Workflows (Terraform) |
| Logstash `.conf` and Elasticsearch ingest pipelines | OpenPipeline DQL/DPL stages |
| ES\|QL, Query DSL, KQL, Lucene | DQL |
| Continuous transforms | Rollup DQL |
| Kibana SLOs (custom-KQL indicators) | DQL SLI queries + objective guide |
| Filebeat configs (`filebeat.yml`) | OpenTelemetry Collector configs shipping to Dynatrace |
| Heartbeat monitors (`heartbeat.yml`) | Dynatrace Synthetic HTTP monitor definitions |
| ILM policies, index templates, enrich policies | Migration guides (bucket retention, routing, lookups) + `CUTOVER-PLAN.md` |

### AppDynamics

| Input | Output |
|-------|--------|
| Application / tier / node inventory (`/controller/rest/applications/{app}/nodes`) | `ONBOARDING-PLAN.md` — OneAgent rollout waves sized by **host**, host-group and tagging design, `waves.json` + `host_groups.json` |
| Health rules (`/controller/alerting/rest/v1/.../health-rules`) | Davis anomaly detectors (Settings JSON or Terraform), with AppD units rescaled |
| Custom dashboards (`CustomDashboardImportExportServlet`) | Dynatrace dashboard JSON with DQL tiles |
| Policies and actions (`/controller/policies`, `/controller/actions`) | Notification plan (problem notifications / Workflow tasks) |

Three AppD-specific behaviours worth knowing, because they are where a naive
converter goes silently wrong:

- **Units are rescaled.** AppD reports response time in milliseconds; the Grail
  metric `dt.service.request.response_time` is in microseconds. A 2000 ms
  threshold becomes 2000000, and the conversion is stated in the report.
- **Baseline health rules are not converted.** A rule comparing against an AppD
  baseline has no static threshold to carry across. Inventing one produces a
  detector that deploys cleanly and watches the wrong thing, so these are
  reported as already covered by built-in Davis anomaly detection.
- **Nothing is entity-scoped automatically.** AppD scopes by application/tier/BT
  name and there is no reliable offline mapping to Dynatrace entities. Converted
  detectors and tiles carry their original AppD scope as a note for a human to
  apply, rather than a guessed filter that would match nothing.

Every run also produces a plain-English `MIGRATION_REPORT.md` with a
deployment-order plan, per-dashboard field manifests (`*.fields.md`
— what must exist at ingest or a tile renders empty), a `METRICS-GUIDE.md`
with log→metric extraction best practice, a `CUTOVER-PLAN.md` dual-ship
schedule when ILM policies are present, and a suggested mapping config when
index patterns need rules.

## CLI

```bash
pip install -e .            # Python >= 3.9, stdlib only
e2d assess <export-dir>                     # scorecard only, converts nothing
                                            # exit 0 clean / 2 manual work / 1 errors
e2d migrate <export-dir> -o out/            # convert everything, one report
e2d dashboard export.ndjson -o out/         # dashboards only
e2d verify out/ --env-url https://<env>.apps.dynatrace.com          # DQL check
e2d verify out/ --data ...                  # + flag tiles that return no data
e2d push out/dashboards --env-url ... --apply                       # deploy
e2d parity out/ --es-url https://es:9200 --index logs-*             # dual-ship count check
e2d backfill --es-url ... --index logs-* --from 2026-01-01T00:00:00Z \
             --to 2026-02-01T00:00:00Z --apply    # history past the 24h ingest wall
e2d web                                     # local GUI
```

Dynatrace rejects log records older than 24 hours, so history cannot be
replayed as-is. `e2d backfill` re-stamps records into the accepted window and
keeps the true event time in an `original_timestamp` attribute; query it with
`fetch logs | filter backfilled == "true" and original_timestamp >= "..."`.
Use `e2d backfill --es-url ... --discover` to list indices with doc counts and
time ranges, pass a comma-separated `--index` list to move several in one run,
or do the whole thing point-and-click in the local GUI (`e2d web`): the
"Backfill historical logs" panel discovers indices, dry-runs with a sample
record, ships with live progress, and verifies the landed counts in Grail.

Backfill is resilient by default: every send retries with exponential backoff
(429/5xx honor Retry-After; the defaults mirror the OpenTelemetry Collector's),
progress is checkpointed per index so an interrupted run resumes instead of
duplicating, permanently rejected batches land in a dead-letter file you can
re-send with `--redrive`, and each record carries a deterministic `dedup.key`
so any duplicates stay detectable in DQL. Every run also writes
`migration_report.json` (scorecard, per-item outcomes, plan) for CI and
tooling.

Translated field references are lowercased automatically (Dynatrace
normalizes log attribute keys to lowercase at ingest, so `audit.logText`
lands as `audit.logtext`); disable with `"lowercase_fields": false` or
override per field with an explicit rename.

Use a `mapping.config.json` to route index patterns to data objects and
rename fields — see `samples/mapping.config.json`. Drop it in with your
export and it is applied automatically.

## Samples

`samples/` contains synthetic simple and complex examples of every artifact
type — see `samples/README.md`. Try:

```bash
e2d migrate samples -o out/
```

## Development

```bash
pip install -e .[dev]
pytest tests
```

Tests run in CI before every deploy of the hosted page. Never commit real
Elastic exports — `.gitignore` keeps `examples/` and private data out.
