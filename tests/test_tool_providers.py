"""The engine adapters as core tool providers, through `Context.services()`."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from traust_contracts.models import AdapterResult
from traust_core.v1.context import Config, Context
from traust_core.v1.errors import ConfigError, ServiceError, ValidationError
from traust_core.v1.models.assessment import ToolName
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.services.provider_catalog import Capability, CapabilityKind

from traust_engine.adapters import gitleaks, govulncheck, grype, opengrep, osv, tools, yara
from traust_engine.adapters._contract_bridge import build_scan_result
from traust_engine.adapters.tools import (
    AdapterTool,
    EngineToolInspector,
    NoDatabase,
    register_tools,
)
from traust_engine.toolchain import DBInfo

NOW = datetime(2026, 10, 24, 12, tzinfo=UTC)
CHECKOUT_TOOLS = ["gitleaks", "gitleaks-history", "govulncheck", "grype", "opengrep", "osv", "yara"]
PINS = {
    "gitleaks": {"expected": "8.30.1", "version_cmd": ["gitleaks", "version"]},
    "grype": {"expected": "0.115.0"},
    "govulncheck": {"expected": "1.6.0", "version_regex": r"govulncheck@v(\d+)\.(\d+)\.(\d+)"},
    "syft": {"expected": "1.48.0"},
}


def _result(tool: str, target: Path, version: str = "1.0.0") -> AdapterResult:
    finding = {"id": f"{tool}/x", "title": "x", "severity": "high", "locations": []}
    return build_scan_result(str(target), tool, [finding], scanner_version=version)


def _ctx(tmp_path: Path, **kw: Any) -> Context:
    ctx = Context(Config(home=tmp_path), clock=FixedClock(NOW))
    register_tools(
        ctx,
        loc=None,
        profile_map=kw.pop("profile_map", {"go-scan": {"marker": True}}),
        pins=PINS,
        rule_pack=tmp_path / "pack",
        **kw,
    )
    return ctx


def test_every_checkout_scanner_and_checkov_are_registered_with_the_inspector_and_floors(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    assert ctx.tools.names() == sorted([*CHECKOUT_TOOLS, "checkov"])
    assert isinstance(ctx.tool_inspector, EngineToolInspector)
    assert ctx.tool_floors == {
        "gitleaks": "8.30.1",
        "gitleaks-history": "8.30.1",
        "govulncheck": "1.6.0",
        "grype": "0.115.0",
    }


def test_a_second_registration_is_refused(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    with pytest.raises(ConfigError, match="already registered"):
        register_tools(ctx, loc=None, profile_map={}, pins={}, rule_pack=tmp_path)


@pytest.mark.parametrize(
    ("tool", "module", "expect"),
    [
        ("gitleaks", gitleaks, {"mode": "dir", "loc": None}),
        ("gitleaks-history", gitleaks, {"mode": "history", "loc": None}),
        ("govulncheck", govulncheck, {"profile_map": {"go-scan": {"marker": True}}}),
        ("grype", grype, {}),
        ("yara", yara, {"rules": ["https://example.invalid/rules@" + "a" * 40]}),
    ],
)
def test_run_tools_calls_the_adapters_own_scan_with_its_guards(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, tool: str, module: Any, expect: dict
) -> None:
    seen: list[tuple[Path, dict]] = []

    def scan(target: Path, **kw: Any) -> AdapterResult:
        seen.append((target, kw))
        return _result(tool, target, "8.30.1")

    monkeypatch.setattr(module, "scan", scan)
    monkeypatch.setattr(AdapterTool, "check", lambda self: tools.Readiness(ready=True))
    ctx = _ctx(tmp_path, yara_rules=["https://example.invalid/rules@" + "a" * 40])
    run = ctx.services().assessment.run_tools(tmp_path, [ToolName(tool)])
    assert run.data(tool, AdapterResult).findings[0].id == f"{tool}/x"
    assert run.results[tool].acquisition.version == "8.30.1"
    assert run.results[tool].acquisition.acquired_at == NOW
    assert seen == [(tmp_path, expect)]


def test_opengrep_gets_the_pinned_pack_and_the_allowlist(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[dict] = []
    allow = object()
    monkeypatch.setattr(opengrep, "scan", lambda t, **kw: seen.append(kw) or _result("opengrep", t))
    ctx = _ctx(tmp_path, allowlist=allow)
    ctx.tools.get("opengrep").acquire(tools.ToolRequest(workspace=tmp_path))
    assert seen == [{"rule_pack": tmp_path / "pack", "allowlist": allow, "loc": None}]


def test_osv_uses_a_fresh_client_from_the_factory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = object()
    seen: list[object] = []
    monkeypatch.setattr(osv, "scan", lambda t, **kw: seen.append(kw["client"]) or _result("osv", t))
    ctx = _ctx(tmp_path, osv_client=lambda: client)
    result = ctx.tools.get("osv").acquire(tools.ToolRequest(workspace=tmp_path))
    assert seen == [client]
    assert result.acquisition.provider == "osv"


@pytest.mark.parametrize(
    ("raised", "kind"),
    [
        (ValueError("no go.mod"), ValidationError),
        (RuntimeError("tool failed"), ServiceError),
        (FileNotFoundError("absent"), ServiceError),
        (TimeoutError("timed out"), ServiceError),
    ],
)
def test_an_adapter_failure_is_a_typed_error_naming_the_tool(
    tmp_path: Path, raised: Exception, kind: type[Exception]
) -> None:
    def scan(_: Path) -> AdapterResult:
        raise raised

    tool = AdapterTool("t", (), scan, FixedClock(NOW))
    with pytest.raises(kind, match=f"t over {tmp_path}: {raised}"):
        tool.acquire(tools.ToolRequest(workspace=tmp_path))


def test_a_missing_workspace_never_reaches_the_adapter(tmp_path: Path) -> None:
    tool = AdapterTool("t", (), lambda _: pytest.fail("scanned"), FixedClock(NOW))
    with pytest.raises(ValidationError, match="not a directory"):
        tool.acquire(tools.ToolRequest(workspace=tmp_path / "absent"))


def test_readiness_names_missing_binaries_then_an_unresolved_precondition(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        tools,
        "on_path",
        lambda *b, missing="": tools.Readiness(ready=False, detail=f"{b[0]}{missing}"),
    )
    absent = AdapterTool("t", ("nope",), lambda _: None, FixedClock(NOW))  # type: ignore[arg-type,return-value]
    assert absent.check().detail == "nope not on PATH"
    monkeypatch.setattr(tools, "on_path", lambda *b, missing="": tools.Readiness(ready=True))

    def unresolved() -> object:
        raise ValueError("pack missing")

    gated = AdapterTool(
        "t",
        ("x",),
        lambda _: None,
        FixedClock(NOW),
        lambda: tools._resolves("t", unresolved),  # type: ignore[arg-type,return-value]
    )
    assert gated.check() == tools.Readiness(ready=False, detail="t: pack missing")


def test_unready_tools_stop_run_tools_before_any_scan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(grype, "scan", lambda *_a, **_k: pytest.fail("scanned"))
    monkeypatch.setattr(
        AdapterTool, "check", lambda self: tools.Readiness(ready=False, detail="grype not on PATH")
    )
    ctx = _ctx(tmp_path)
    with pytest.raises(ConfigError, match="grype: grype not on PATH"):
        ctx.services().assessment.run_tools(tmp_path, [ToolName("grype")])


def test_the_catalog_stamps_versions_and_grypes_database(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    asked: list[tuple[str, Any, Any]] = []

    def version(binary: str, version_cmd: Any = None, version_regex: Any = None) -> str | None:
        asked.append((binary, version_cmd, version_regex))
        return {"grype": "0.115.0", "gitleaks": "8.30.1"}.get(binary)

    monkeypatch.setattr(tools.toolchain, "tool_version", version)
    monkeypatch.setattr(
        tools.toolchain,
        "db_status",
        lambda b: DBInfo(
            exists=True, built="2026-10-23T01:31:46Z", schema_version="v6.0.2", path="/db"
        ),
    )
    catalog = _ctx(tmp_path).services().catalog
    stamp = {s.tool: s for s in catalog.stamp().tools}
    assert stamp["grype"].render() == "grype 0.115.0 (db built 2026-10-23, schema v6.0.2)"
    assert stamp["gitleaks"].render() == "gitleaks 8.30.1"
    assert stamp["osv"].version is None
    assert ("gitleaks", ["gitleaks", "version"], None) in asked
    assert ("osv", None, None) not in asked and ("", None, None) not in asked
    [db] = catalog.databases()
    assert db.tool == "grype" and db.max_age == timedelta(days=5)
    assert db.built_at == datetime(2026, 10, 23, 1, 31, 46, tzinfo=UTC)
    assert not db.stale(NOW)


def test_readiness_holds_a_tool_below_its_floor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(AdapterTool, "check", lambda self: tools.Readiness(ready=True))
    monkeypatch.setattr(tools.toolchain, "tool_version", lambda b, **_: "8.0.0")
    catalog = _ctx(tmp_path).services().catalog
    [binding] = catalog.readiness(Capability(kind=CapabilityKind.TOOL, name="gitleaks"))
    assert not binding.readiness.ready
    assert binding.readiness.detail == "version 8.0.0 is below the floor 8.30.1"


def test_fetch_databases_updates_only_grype(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    populated: list[str] = []
    monkeypatch.setattr(tools.toolchain, "populate", lambda b: populated.append(b) or (True, "ok"))
    monkeypatch.setattr(tools.toolchain, "db_status", lambda b: DBInfo(exists=True))
    [db] = _ctx(tmp_path).services().catalog.fetch_databases()
    assert populated == ["grype"] and db.tool == "grype"


def test_a_failed_or_impossible_database_update_is_a_typed_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inspector = EngineToolInspector({"grype": "grype", "gitleaks": "gitleaks"}, {})
    monkeypatch.setattr(tools.toolchain, "populate", lambda b: (False, "grype: db update failed"))
    with pytest.raises(ServiceError, match="db update failed"):
        inspector.update_database("grype")
    with pytest.raises(NoDatabase, match="gitleaks keeps no vulnerability database"):
        inspector.update_database("gitleaks")


@pytest.mark.parametrize(
    ("raw", "expect"),
    [
        ("2026-10-23T01:31:46Z", datetime(2026, 10, 23, 1, 31, 46, tzinfo=UTC)),
        ("2026-10-23 01:31:46 +0000 UTC", datetime(2026, 10, 23, tzinfo=UTC)),
        ("garbage", None),
        (None, None),
    ],
)
def test_grypes_built_value_reads_as_an_aware_datetime(raw: str | None, expect: Any) -> None:
    assert tools._built_at(raw) == expect


def test_the_providers_start_no_process_of_their_own() -> None:
    source = Path(tools.__file__).read_text(encoding="utf-8")
    for forbidden in ("subprocess", "urlopen", "ProcessRunner(", "socket"):
        assert forbidden not in source
