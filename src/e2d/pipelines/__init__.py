"""Track D: Elastic ingest pipelines (Logstash `.conf`) -> Dynatrace OpenPipeline.

A Logstash filter chain (grok/dissect/kv/date/geoip/mutate/drop/translate/...)
becomes an ordered list of OpenPipeline processing stages expressed in DQL/DPL
(`parse`, `filter`, `fieldsAdd`, `fieldsRemove`, `lookup`). Grok and dissect
patterns translate to DPL matchers; conditionals become routing/filter stages;
constructs with no faithful target (Painless `ruby`, Kafka SOC mirror) are
flagged MANUAL rather than silently dropped.
"""
