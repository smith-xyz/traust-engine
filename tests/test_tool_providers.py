"""The engine adapters as core tool providers, through `Context.services()`."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from traust_contracts.models import AdapterResult
from traust_core.v1.context import Config, Context
from traust_core.v1.errors import ConfigError, ServiceError, ValidationError
from traust_core.v1.models.assessment import ToolName
from traust_core.v1.models.common import SymbolQuery
from traust_core.v1.providers.base import argv_digest
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.providers.tools import ToolProvider
from traust_core.v1.services.provider_catalog import Capability, CapabilityKind

from traust_engine.adapters import (
    gitleaks,
    govulncheck,
    grype,
    joern,
    opengrep,
    osv,
    osv_sbom,
    tools,
    yara,
)
from traust_engine.adapters._contract_bridge import build_scan_result
from traust_engine.adapters.tools import AdapterTool, NoDatabase, register_tools
from traust_engine.toolchain import DBInfo

NOW = datetime(2026, 10, 24, 12, tzinfo=UTC)
CHECKOUT_TOOLS = ["gitleaks", "gitleaks-history", "govulncheck", "grype", "opengrep", "osv", "yara"]
OTHER_TARGET_TOOLS = ["joern", "osv_sbom"]
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


def test_every_scanner_and_checkov_are_registered_reporting_themselves_with_the_floors(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    assert ctx.tools.names() == sorted([*CHECKOUT_TOOLS, *OTHER_TARGET_TOOLS, "checkov"])
    assert all(isinstance(ctx.tools.get(n), ToolProvider) for n in ctx.tools.names())
    assert ctx.tool_inspector is None
    assert ctx.tool_floors == {
        "gitleaks": "8.30.1",
        "gitleaks-history": "8.30.1",
        "govulncheck": "1.6.0",
        "grype": "0.115.0",
    }


def test_a_second_registration_is_refused(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    with pytest.raises(ConfigError, match="registered twice"):
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
    def tool(name: str) -> AdapterTool:
        return AdapterTool(name, (name,), lambda _: None, FixedClock(NOW))

    monkeypatch.setattr(tools.toolchain, "populate", lambda b: (False, "grype: db update failed"))
    with pytest.raises(ServiceError, match="db update failed"):
        tool("grype").update_database()
    with pytest.raises(NoDatabase, match="gitleaks keeps no vulnerability database"):
        tool("gitleaks").update_database()


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


def test_joern_runs_over_the_symbols_target_checkout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[tuple[Path, Any]] = []
    monkeypatch.setattr(
        joern, "scan", lambda r, symbols: seen.append((r, symbols)) or _result("joern", r)
    )
    query = SymbolQuery(workspace=tmp_path, names=("com.foo.Bar#parse",))
    result = _ctx(tmp_path).tools.get("joern").acquire(tools.ToolRequest(symbols=query))
    assert seen == [(tmp_path, ["com.foo.Bar#parse"])]
    assert result.acquisition.source == str(tmp_path.resolve())


def test_osv_sbom_runs_over_the_sbom_and_a_failed_lookup_is_a_service_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sbom = tmp_path / "image.syft.json"
    sbom.write_text("{}", encoding="utf-8")
    client = object()
    doc = {"provenance": {"status": "complete"}, "candidates": []}
    seen: list[tuple[Path, object]] = []
    monkeypatch.setattr(osv_sbom, "scan_sbom", lambda p, c: seen.append((p, c)) or doc)
    tool = _ctx(tmp_path, osv_client=lambda: client).tools.get("osv_sbom")
    result = tool.acquire(tools.ToolRequest(sbom=sbom))
    assert result.data == doc and seen == [(sbom, client)]
    assert result.acquisition.version is None
    failed = {"status": "failed", "base_url": "https://osv.invalid", "failure": {"detail": "503"}}
    monkeypatch.setattr(osv_sbom, "scan_sbom", lambda p, c: {"provenance": failed})
    with pytest.raises(ServiceError, match=r"OSV API unavailable at https://osv.invalid: 503"):
        tool.acquire(tools.ToolRequest(sbom=sbom))


def test_a_malformed_sbom_is_a_validation_error(tmp_path: Path) -> None:
    sbom = tmp_path / "image.cdx.json"
    sbom.write_text('{"bomFormat": "CycloneDX"}', encoding="utf-8")
    tool = _ctx(tmp_path).tools.get("osv_sbom")
    with pytest.raises(ValidationError, match="not a syft JSON SBOM"):
        tool.acquire(tools.ToolRequest(sbom=sbom))


@pytest.mark.parametrize(
    ("tool", "request_for", "message"),
    [
        ("grype", lambda p: {"sbom": p / "x.json"}, "grype runs over a checkout, not a sbom"),
        ("osv_sbom", lambda p: {"workspace": p}, "osv_sbom runs over a sbom, not a checkout"),
        ("joern", lambda p: {"workspace": p}, "joern runs over a symbols, not a checkout"),
        ("osv_sbom", lambda p: {"sbom": p / "absent.json"}, "SBOM is not a file"),
        (
            "joern",
            lambda p: {"symbols": SymbolQuery(workspace=p / "absent", names=("f",))},
            "workspace is not a directory",
        ),
    ],
)
def test_a_request_for_another_or_a_missing_target_never_reaches_the_adapter(
    tmp_path: Path, tool: str, request_for: Any, message: str
) -> None:
    provider = _ctx(tmp_path).tools.get(tool)
    with pytest.raises(ValidationError, match=message):
        provider.acquire(tools.ToolRequest(**request_for(tmp_path)))


def test_grype_records_the_argv_it_ran_and_its_database_build_time(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ran: list[list[str]] = []

    def run(cmd: list[str], **_: Any) -> Any:
        ran.append(cmd)
        return type("Done", (), {"returncode": 0, "stdout": '{"matches": []}', "stderr": ""})()

    monkeypatch.setattr(grype, "subprocess", SimpleNamespace(run=run))
    monkeypatch.setattr(grype, "_tool_version", lambda b: "0.115.0")
    monkeypatch.setattr(
        tools.toolchain, "db_status", lambda b: DBInfo(exists=True, built="2026-10-23T01:31:46Z")
    )
    result = _ctx(tmp_path).tools.get("grype").acquire(tools.ToolRequest(workspace=tmp_path))
    assert result.acquisition.argv_sha256 == argv_digest(ran[0])
    assert ran[0] == ["grype", str(tmp_path), "-o", "json"]
    assert result.acquisition.db_built_at == datetime(2026, 10, 23, 1, 31, 46, tzinfo=UTC)


def test_govulncheck_records_its_argv_and_tools_without_a_known_argv_or_db_record_none(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    for module, name in ((govulncheck, "govulncheck"), (gitleaks, "gitleaks")):
        monkeypatch.setattr(module, "scan", lambda t, _n=name, **_: _result(_n, t))
    ctx = _ctx(tmp_path)
    request = tools.ToolRequest(workspace=tmp_path)
    vuln = ctx.tools.get("govulncheck").acquire(request).acquisition
    assert vuln.argv_sha256 == argv_digest(["govulncheck", "-json", "./..."])
    assert vuln.db_built_at is None
    leaks = ctx.tools.get("gitleaks").acquire(request).acquisition
    assert leaks.argv_sha256 is None and leaks.db_built_at is None


def test_joern_reports_its_version_through_its_pin(monkeypatch: pytest.MonkeyPatch) -> None:
    asked: list[tuple[str, Any]] = []
    monkeypatch.setattr(
        tools.toolchain,
        "tool_version",
        lambda b, version_cmd=None, version_regex=None: (
            asked.append((b, version_regex)) or "4.0.600"
        ),
    )
    regex = r"Version:\s*(\d+)\.(\d+)\.(\d+)"
    tool = AdapterTool(
        "joern",
        ("joern", "joern-parse"),
        lambda _: None,
        FixedClock(NOW),
        pin={"version_regex": regex},
    )
    assert tool.version() == "4.0.600" and asked == [("joern", regex)]
    assert tool.database() is None
