"""Elasticsearch continuous transforms (pivot) -> a Dynatrace rollup.

A transform's `pivot` is the same shape as an aggregation: group-by buckets +
metric aggregations. So this reuses the query engine to build the rollup DQL,
then recommends where it lives in Dynatrace — a scheduled Workflow writing a
metric (via OpenPipeline), or an SLO when the transform computes a success ratio.
"""

from e2d.transforms.translate import translate_transform, render_transform, is_transform, TransformResult

__all__ = ["translate_transform", "render_transform", "is_transform", "TransformResult"]
