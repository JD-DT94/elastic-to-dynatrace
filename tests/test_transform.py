"""Continuous transform (pivot) -> rollup DQL."""

from pathlib import Path

import pytest

from e2d.transforms import translate_transform, render_transform, is_transform
from e2d.migrate import classify
from e2d.dql.validate import lint_dql

FIX = Path(__file__).resolve().parents[1] / "examples" / "fixtures" / "elastic-fixtures" / "08-transforms"

# Fixture exports are company data and not committed; skip where absent (CI).
pytestmark = pytest.mark.skipif(not FIX.exists(), reason="company-data fixtures not present")


def test_classify_transform():
    f = FIX / "service_slo_transform.json"
    assert classify(f, f.read_text(encoding="utf-8")) == "transform"


def test_pivot_becomes_maketimeseries_rollup():
    res = translate_transform((FIX / "service_slo_transform.json").read_text(encoding="utf-8"),
                              name="slo")
    assert res.data_object == "spans"          # APM index resolved
    assert res.dql.startswith("fetch spans")
    assert "makeTimeseries" in res.dql
    assert "by: {service.name, service.environment}" in res.dql
    assert "requests = count()" in res.dql and "percentile(transaction.duration.ms, 95)" in res.dql
    assert res.has_ratio                       # availability bucket_script -> SLO candidate
    assert lint_dql(res.dql) == []             # valid DQL


def test_render_mentions_slo_for_ratio():
    res = translate_transform((FIX / "service_slo_transform.json").read_text(encoding="utf-8"))
    md = render_transform(res)
    assert "SLO" in md and "```dql" in md


def test_is_transform_guard():
    assert is_transform({"pivot": {}, "source": {}})
    assert not is_transform({"processors": []})
