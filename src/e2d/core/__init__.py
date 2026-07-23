"""Shared conversion core: a small DQL builder plus dialect-neutral IR for
boolean filters and aggregation trees. Front-ends (ES|QL, KQL, Lucene, Query DSL,
Lens, watcher searches) translate into this IR; one emitter owns DQL syntax."""
