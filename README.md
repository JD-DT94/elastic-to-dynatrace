# elastic-to-dynatrace (`e2d`)

Convert Elastic / Kibana artifacts into Dynatrace equivalents: dashboards,
alerts, ingest pipelines, transforms, and queries.

## Use it in the browser (nothing to install)

**https://jd-dt94.github.io/elastic-to-dynatrace/**

Drag a Kibana export onto the page, click **Convert**, download the results.
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

Every run also produces a plain-English `MIGRATION_REPORT.md` with a
deployment-order plan, per-dashboard field manifests (`*.fields.md`
— what must exist at ingest or a tile renders empty), a `METRICS-GUIDE.md`
with log→metric extraction best practice, a `CUTOVER-PLAN.md` dual-ship
schedule when ILM policies are present, and a suggested mapping config when
index patterns need rules.

## CLI

```bash
pip install -e .            # Python >= 3.9, stdlib only
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
