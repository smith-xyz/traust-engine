"""HarnessEngine client: built from a loaded context, injects locations into ops."""

from __future__ import annotations

import shutil
from pathlib import Path

import yaml

from traust_engine import HarnessEngine

_FIXTURE = Path(__file__).parent / "fixtures" / "config"


def _home_with_progress_tracker(tmp_path: Path, pt: Path) -> Path:
    home = tmp_path / f"cfg-{pt.name}"
    shutil.copytree(_FIXTURE, home)
    (home / "locations.yaml").write_text(
        yaml.safe_dump({"progress_tracker": str(pt)}), encoding="utf-8"
    )
    return home


def test_two_engines_are_isolated_by_their_context(tmp_path):
    h1 = HarnessEngine.load(config_home=_home_with_progress_tracker(tmp_path, tmp_path / "a"))
    h2 = HarnessEngine.load(config_home=_home_with_progress_tracker(tmp_path, tmp_path / "b"))
    assert h1.sweep._progress_tracker() == tmp_path / "a"
    assert h2.sweep._progress_tracker() == tmp_path / "b"


def test_namespace_ops_are_cached_per_engine(tmp_path):
    h = HarnessEngine.load(config_home=_home_with_progress_tracker(tmp_path, tmp_path / "pt"))
    assert h.adapters is h.adapters
    assert h.sweep is h.sweep
    assert h.portfolio is h.portfolio


def test_sweep_paths_follow_configured_locations(tmp_path):
    home = tmp_path / "cfg-sweep"
    shutil.copytree(_FIXTURE, home)
    ar = tmp_path / "analysis-results"
    ar.mkdir()
    pt = tmp_path / "progress-tracker"
    ws = tmp_path / "workspace"
    ws.mkdir()
    (home / "locations.yaml").write_text(
        yaml.safe_dump(
            {
                "analysis_results": str(ar),
                "progress_tracker": str(pt),
                "workspace": str(ws),
            }
        ),
        encoding="utf-8",
    )
    h = HarnessEngine.load(config_home=home)
    assert h.sweep._analysis_results() == ar
    assert h.sweep._scan_testing() == ar / "scan-testing"
    assert h.sweep._benchmark_dir() == ar / "scan-testing" / "validation-benchmark"
    assert h.sweep._progress_tracker() == pt
    assert h.sweep._workspace() == ws


def test_adapters_ops_expose_context_config(tmp_path):
    home = _home_with_progress_tracker(tmp_path, tmp_path / "pt")
    h = HarnessEngine.load(config_home=home)
    allowlist = h.adapters.allowlist_for_opengrep()
    assert allowlist is not None
    assert "argus-observe-rules" in (allowlist.packs or {})
    assert h.adapters.rule_pack_allowlist_path() == home / "rule-pack-allowlist.yaml"
    assert h.adapters.rule_pack_dir().is_dir()

    from traust_engine.adapters.opengrep import load_supplemental_packs

    packs = load_supplemental_packs(allowlist=allowlist)
    assert any(p["name"] == "argus-observe-rules" for p in packs)


def test_portfolio_ops_use_configured_paths(tmp_path):
    ar = tmp_path / "analysis-results"
    (ar / "graph").mkdir(parents=True)
    spine_path = ar / "graph" / "repo-graph.json"
    spine_path.write_text('{"nodes":[],"edges":[]}', encoding="utf-8")
    explicit_db = tmp_path / "custom" / "portfolio.db"
    explicit_db.parent.mkdir()

    home = _home_with_progress_tracker(tmp_path, tmp_path / "pt")
    (home / "locations.yaml").write_text(
        yaml.safe_dump({"progress_tracker": str(tmp_path / "pt"), "analysis_results": str(ar)}),
        encoding="utf-8",
    )
    h = HarnessEngine.load(config_home=home)

    assert h.portfolio.repo_graph() == spine_path
    assert h.portfolio.portfolio_graph_db() == ar / "graph" / "portfolio-graph.db"
    assert h.portfolio.portfolio_graph_location() == str(ar / "graph" / "portfolio-graph.db")

    (home / "locations.yaml").write_text(
        yaml.safe_dump(
            {
                "progress_tracker": str(tmp_path / "pt"),
                "analysis_results": str(ar),
                "portfolio_graph": str(explicit_db),
            }
        ),
        encoding="utf-8",
    )
    h2 = HarnessEngine.load(config_home=home)
    assert h2.portfolio.portfolio_graph_db() == explicit_db
    assert h2.portfolio.portfolio_graph_location() == str(explicit_db)
