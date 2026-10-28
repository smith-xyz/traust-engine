"""traust_engine.locations — config resolution."""

from __future__ import annotations

from traust_contracts import Locations

from traust_engine import locations as config


def test_analysis_results_location_reads_config():
    assert (
        config.analysis_results_location(Locations(analysis_results="s3://bucket/results"))
        == "s3://bucket/results"
    )
    assert (
        config.analysis_results_location(Locations(analysis_results="/local/results"))
        == "/local/results"
    )


def test_unconfigured_returns_none():
    assert config.analysis_results_location(None) is None
