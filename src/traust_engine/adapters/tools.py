"""traust-engine's scanner adapters as traust-core tool providers, and its toolchain as core's
`ToolInspector`.

Each provider runs its adapter's own `scan()` over one checkout (the adapter keeps its argv,
safe_exec profile, freeze env, rule-pack pinning and secret redaction); this module only adapts
the call to core's `ToolProvider` and the toolchain probes to `ToolInspector`. Nothing here
starts a process or opens a connection the adapter didn't already.

Not registered (see `UNREGISTERED`): adapters whose input is not a checkout, and the crypto
probes core already implements natively.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from traust_contracts import Locations, RulePackAllowlist
from traust_contracts.models import AdapterResult
from traust_core.v1.context import Context
from traust_core.v1.errors import ConfigError, ServiceError, TraustError, ValidationError
from traust_core.v1.providers.base import Acquisition, Readiness, Result, on_path
from traust_core.v1.providers.clock import Clock
from traust_core.v1.providers.tools import DatabaseStatus, ToolRequest

from traust_engine import toolchain
from traust_engine.adapters import cloud_config, gitleaks, govulncheck, grype, opengrep, osv, yara
from traust_engine.osv import OsvClient

# grype refuses a database older than this itself (traust check_drift GRYPE_DB_MAX_AGE_DAYS).
GRYPE_DB_MAX_AGE = timedelta(days=5)

# Adapters with no provider here, and why; `traust admin toolchain` can name them.
UNREGISTERED: Mapping[str, str] = {
    "joern": "NEED(core: ToolRequest symbols): a reachability query needs the vulnerable "
    "symbols, which a checkout-only ToolRequest cannot carry",
    "osv_sbom": "NEED(core: ToolRequest sbom): it scans a syft SBOM, not a checkout",
    "crypto_probe": "core's CryptoProbe (FactEnumerator) is the source-tree crypto census",
    "crypto_audit": "core's CryptoProbe, ImageCryptoProbe and ClusterCryptoProbe cover its "
    "source, image and cluster modes",
}


class NoDatabase(ConfigError):
    """`update_database` for a tool that keeps no vulnerability database."""


@dataclass(frozen=True, slots=True)
class AdapterTool:
    """One engine adapter over a checkout, as its `AdapterResult`; read-only toward it."""

    name: str
    binaries: tuple[str, ...]
    scan: Callable[[Path], AdapterResult]
    clock: Clock
    precondition: Callable[[], Readiness] | None = None

    def check(self) -> Readiness:
        if self.binaries and not (found := on_path(*self.binaries, missing=" not on PATH")).ready:
            return found
        return self.precondition() if self.precondition else Readiness(ready=True)

    def acquire(self, request: ToolRequest) -> Result[AdapterResult]:
        workspace = request.workspace
        if not workspace.is_dir():
            raise ValidationError(f"{self.name}: workspace is not a directory: {workspace}")
        try:
            result = self.scan(workspace)
        except TraustError:
            raise
        except ValueError as e:
            raise ValidationError(f"{self.name} over {workspace}: {e}") from e
        except (OSError, RuntimeError) as e:  # missing binary, timeout, tool failure
            raise ServiceError(f"{self.name} over {workspace}: {e}") from e
        return Result(
            result,
            Acquisition(
                provider=self.name,
                acquired_at=self.clock.now(),
                version=result.metadata.scanner_version or None,
                source=str(workspace.resolve()),
            ),
        )


class EngineToolInspector:
    """Core's `ToolInspector` over the engine toolchain probes: each tool's version (its
    external-tools.yaml pin's version command) and grype's database."""

    def __init__(self, binaries: Mapping[str, str], pins: Mapping[str, Mapping[str, Any]]) -> None:
        self._binaries = dict(binaries)
        self._pins = {k: dict(v) for k, v in pins.items()}

    def version(self, tool: str) -> str | None:
        binary = self._binaries.get(tool, tool)
        if not binary:
            return None  # an API, not a binary (osv)
        spec = self._pins.get(binary, {})
        return toolchain.tool_version(
            binary, version_cmd=spec.get("version_cmd"), version_regex=spec.get("version_regex")
        )

    def database(self, tool: str) -> DatabaseStatus | None:
        binary = self._binaries.get(tool, tool)
        if binary not in toolchain.POPULATABLE_TOOLS:
            return None
        info = toolchain.db_status(binary)
        if info is None:
            return None
        return DatabaseStatus(
            tool=tool,
            exists=info.exists,
            built_at=_built_at(info.built),
            schema_version=info.schema_version,
            max_age=GRYPE_DB_MAX_AGE if binary == "grype" else None,
            path=info.path,
        )

    def update_database(self, tool: str) -> DatabaseStatus:
        binary = self._binaries.get(tool, tool)
        if binary not in toolchain.POPULATABLE_TOOLS:
            raise NoDatabase(f"{tool} keeps no vulnerability database to update")
        ok, message = toolchain.populate(binary)
        if not ok:
            raise ServiceError(message)
        status = self.database(tool)
        if status is None:
            raise ServiceError(f"{tool}: database updated but its status is unreadable")
        return status


def register_tools(
    ctx: Context,
    *,
    loc: Locations | None,
    profile_map: Mapping[str, Any],
    pins: Mapping[str, Mapping[str, Any]],
    rule_pack: Path,
    allowlist: RulePackAllowlist | None = None,
    yara_rules: Sequence[str] = (),
    osv_client: Callable[[], OsvClient] = OsvClient,
) -> None:
    """Register every checkout scanner in `ctx.tools` (Checkov included, through
    `register_checkov`), the toolchain as `ctx.tool_inspector`, and the pins' `expected`
    versions as `ctx.tool_floors`.

    `profile_map` is the deployment's safe_exec profiles (`AdaptersOps.safe_exec_profile_map()`),
    `pins` external-tools.yaml (`ToolchainOps.pins()`), `rule_pack` / `allowlist` the opengrep
    pack and supplemental-pack allowlist, `yara_rules` pinned `url@sha` sources (empty: the
    adapter's pinned default).
    """
    if ctx.tool_inspector is not None:
        raise ConfigError("a tool inspector is already registered")
    clock = ctx.clock
    profiles = dict(profile_map)
    rules = list(yara_rules)
    tools = [
        AdapterTool(
            "gitleaks",
            ("gitleaks",),
            lambda w: gitleaks.scan(w, mode="dir", loc=loc),
            clock,
            lambda: _resolves("gitleaks", lambda: gitleaks.resolve_gitleaks_config(None, loc)),
        ),
        AdapterTool(
            "gitleaks-history",
            ("gitleaks", "git"),
            lambda w: gitleaks.scan(w, mode="history", loc=loc),
            clock,
            lambda: _resolves("gitleaks", lambda: gitleaks.resolve_gitleaks_config(None, loc)),
        ),
        AdapterTool(
            "govulncheck",
            ("govulncheck", "go"),
            lambda w: govulncheck.scan(w, profile_map=profiles),
            clock,
        ),
        AdapterTool("grype", ("grype",), lambda w: grype.scan(w), clock),  # DB frozen by default
        AdapterTool(
            "opengrep",
            ("opengrep",),
            lambda w: opengrep.scan(w, rule_pack=rule_pack, allowlist=allowlist, loc=loc),
            clock,
            lambda: _resolves("opengrep", lambda: opengrep.resolve_rule_pack_dir(rule_pack, loc)),
        ),
        AdapterTool("osv", (), lambda w: osv.scan(w, client=osv_client()), clock),
        AdapterTool("yara", ("yara", "git"), lambda w: yara.scan(w, rules=rules), clock),
    ]
    for tool in tools:
        ctx.tools.register(tool.name, lambda t=tool: t)
    cloud_config.register_checkov(ctx)
    binaries = {t.name: t.binaries[0] if t.binaries else "" for t in tools}
    ctx.tool_inspector = EngineToolInspector(binaries, pins)
    ctx.tool_floors.update(
        {
            name: str(spec["expected"])
            for name, binary in {**binaries, cloud_config.CHECKOV: cloud_config.CHECKOV}.items()
            if binary and (spec := pins.get(binary)) and spec.get("expected")
        }
    )


def _resolves(tool: str, resolve: Callable[[], object]) -> Readiness:
    try:
        resolve()
    except ValueError as e:
        return Readiness(ready=False, detail=f"{tool}: {e}")
    return Readiness(ready=True)


def _built_at(raw: str | None) -> datetime | None:
    """`grype db status`'s `Built:` value (`2026-08-24T01:31:46Z`, or with a trailing zone
    name), as an aware datetime; None when it reads as neither."""
    if not raw:
        return None
    text = raw.strip().replace("Z", "+00:00")
    try:
        found = datetime.fromisoformat(text.split(" ")[0] if "T" in text else text)
    except ValueError:
        m = re.match(r"(\d{4}-\d{2}-\d{2})", text)
        if not m:
            return None
        found = datetime.fromisoformat(m.group(1))
    return found if found.tzinfo else found.replace(tzinfo=UTC)
