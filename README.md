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
| ILM policies, index templates, enrich policies | Migration guides (bucket retention, routing, lookups) |

Every run also produces a plain-English `MIGRATION_REPORT.md` (notes grouped
by rebuild / double-check / FYI), per-dashboard field manifests (`*.fields.md`
— what must exist at ingest or a tile renders empty), a `METRICS-GUIDE.md`
with log→metric extraction best practice, and a suggested mapping config when
index patterns need rules.

## CLI

```bash
pip install -e .            # Python >= 3.9, stdlib only
e2d migrate <export-dir> -o out/            # convert everything, one report
e2d dashboard export.ndjson -o out/         # dashboards only
e2d verify out/ --env-url https://<env>.apps.dynatrace.com          # DQL check
e2d verify out/ --data ...                  # + flag tiles that return no data
e2d push out/dashboards --env-url ... --apply                       # deploy
e2d web                                     # local GUI
```

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
