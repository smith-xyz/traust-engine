"""register_providers: every engine provider on a core Context by name, its config read on first use."""

from __future__ import annotations

import shutil
from pathlib import Path
from uuid import uuid4

import pytest
from traust_contracts import DeploymentConfigMissing, load_context
from traust_core.v1.context import Config, Context
from traust_core.v1.errors import ConfigError
from traust_core.v1.models.detection_quality import RulePack

from traust_engine.adapters.providers import register_providers
from traust_engine.adapters.tools import TOOL_NAMES, register_tools
from traust_engine.engine import HarnessEngine

FIXTURE_CONFIG = Path(__file__).parent / "fixtures" / "config"


@pytest.fixture
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    config = tmp_path / "config"
    shutil.copytree(FIXTURE_CONFIG, config)
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    return config


def _ctx(tmp_path: Path, home: Path, loads: list[Path] | None = None, **kw: str) -> Context:
    def engine() -> HarnessEngine:
        if loads is not None:
            loads.append(home)
        return HarnessEngine(load_context(config_home=home))

    ctx = Context(Config(home=tmp_path / "store"))
    register_providers(ctx, engine, **kw)
    return ctx


def test_tool_names_are_what_register_tools_registers(tmp_path: Path) -> None:
    ctx = Context(Config(home=tmp_path))
    register_tools(ctx, loc=None, profile_map={}, pins={}, rule_pack=tmp_path)
    assert ctx.tools.names() == sorted(TOOL_NAMES)


def test_every_provider_is_registered_and_used_through_the_services(
    tmp_path: Path, home: Path
) -> None:
    ctx = _ctx(tmp_path, home)
    assert ctx.tools.names() == sorted(TOOL_NAMES)
    assert ctx.adr_source is not None and ctx.doc_source is not None
    assert ctx.fleet_fix_applier is not None and ctx.fleet_fix_goldens is not None
    packs = ctx.services().detection_quality.rule_packs()
    assert packs and all(isinstance(p, RulePack) and p.rules for p in packs)
    assert ctx.tool_floors  # the pins arrived with the config


def test_canary_sources_are_the_named_recall_benchmark_dir(tmp_path: Path, home: Path) -> None:
    detail = _ctx(tmp_path, home, canaries="seeded").canaries.check().detail
    assert str(home / "recall-benchmark" / "seeded") in detail


def test_the_engine_is_loaded_once_on_first_use(tmp_path: Path, home: Path) -> None:
    loads: list[Path] = []
    ctx = _ctx(tmp_path, home, loads)
    ctx.services()
    assert loads == []
    ctx.tools.get("grype")
    ctx.tools.get("opengrep")
    ctx.rule_packs.packs()
    assert loads == [home]


def test_a_home_without_the_engine_config_serves_everything_but_its_providers(
    tmp_path: Path,
) -> None:
    bare = tmp_path / "bare"
    bare.mkdir()
    ctx = _ctx(tmp_path, bare)
    services = ctx.services()
    assert services.findings.open_count(uuid4(), []) == 0
    with pytest.raises(DeploymentConfigMissing, match=r"feeds\.yaml"):
        ctx.tools.get("grype")
    with pytest.raises(DeploymentConfigMissing, match=r"feeds\.yaml"):
        services.detection_quality.rule_packs()


def test_an_unresolvable_rule_pack_is_a_config_error(tmp_path: Path, home: Path) -> None:
    (home / "locations.yaml").write_text("opengrep_rules: s3://bucket/rules\n")
    with pytest.raises(ConfigError, match="no local path form"):
        _ctx(tmp_path, home).tools.get("opengrep")
