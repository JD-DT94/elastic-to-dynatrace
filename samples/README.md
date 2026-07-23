# Samples

Synthetic (company-data-free) inputs for trying the converter — a fictional
web-shop stack. Drag any of these (or the whole folder zipped) onto the
hosted page, or run the CLI:

```bash
e2d migrate samples -o out/          # everything at once, one report
e2d dashboard samples/dashboards/complex_dashboard.ndjson -o out/
```

| Path | What it shows |
|------|---------------|
| `dashboards/simple_dashboard.ndjson` | 3 panels: markdown, legacy terms bar, TSVB line |
| `dashboards/complex_dashboard.ndjson` | 18-panel torture test: TSVB (colors, gauge, derivative), Lens formulas (`count(kql=…)/count()`, moving_average), filters-split × avg, last_value, controls (legacy + controlGroupInput), drilldowns, saved time range, custom/combined filters, convertible + non-convertible Vega, map |
| `alerts/simple_watcher.json` | count-threshold watcher → Davis anomaly detector |
| `alerts/complex_watcher.json` | agg watcher with Painless condition + authed webhook → workflow |
| `alerts/kibana_threshold_rule.json` | `.index-threshold` rule with KQL filter + group-by |
| `pipelines/simple_syslog.conf` | Logstash grok + date → OpenPipeline DPL |
| `pipelines/complex_access_log.conf` | COMBINEDAPACHELOG, kv, geoip, translate, conditionals, drop |
| `pipelines/ingest_pipeline.json` | Elasticsearch ingest pipeline (grok/date/convert/rename/set) |
| `queries/simple_query.json` | bool + range Query DSL → DQL |
| `queries/complex_aggs.json` | date_histogram → terms → percentiles + bucket_script ratio |
| `queries/top_errors.esql` | ES\|QL → DQL |
| `queries/kql_lucene_samples.txt` | KQL/Lucene one-liners (incl. quoted field names) |
| `transforms/service_slo_transform.json` | continuous transform → rollup DQL + SLO note |
| `config/ilm_policy.json` | ILM → Grail bucket-retention guide |
| `config/index_template.json` | index template → OpenPipeline routing guide |
| `config/enrich_policy.json` | enrich policy → Grail lookup guide |
| `mapping.config.json` | index/field mapping config (auto-applied when included) |
| `sample_export.ndjson` | minimal original sample kept for the README quickstart |

The conversion output includes `MIGRATION_REPORT.md` (action-grouped notes),
`METRICS-GUIDE.md` (log→metric best practice per busy tile), field manifests
(`*.fields.md`), and — when indexes lack mapping rules — a generated
`mapping.config.suggested.json`.

Real Elastic exports (`examples/`, exports from your Kibana) are intentionally
.gitignored — keep company data out of this repository.
