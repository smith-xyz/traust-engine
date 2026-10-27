"""traust-engine's scanner adapters as traust-core tool providers.

Each provider runs its adapter's own `scan()` over one target (the adapter keeps its argv,
safe_exec profile, freeze env, rule-pack pinning and secret redaction) and reports the
binary's version and database through the engine toolchain probes; this module only adapts
the call to core's `ToolProvider`. Nothing here starts a process or opens a connection the
adapter or toolchain didn't already.

Not registered (see `UNREGISTERED`): the crypto probes core already implements natively.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Generic, TypeVar

from traust_core.v1.context import Context
from traust_core.v1.errors import ServiceError, TraustError, ValidationError
from traust_core.v1.models.common import ToolTarget
from traust_core.v1.providers.base import Acquisition, Readiness, Result, argv_digest, on_path
from traust_core.v1.providers.clock import Clock
from traust_core.v1.providers.tools import DatabaseStatus, NoDatabase, ToolRequest

from traust_engine import toolchain
from traust_engine.adapters import (
    cloud_config,
    gitleaks,
    govulncheck,
    grype,
    joern,
    opengrep,
    osv,
    osv_sbom,
    yara,
)
from traust_engine.adapters._contract_bridge import AdapterResult  # contract types via adapters
from traust_engine.osv import OsvClient

# grype refuses a database older than this itself (traust check_drift GRYPE_DB_MAX_AGE_DAYS).
GRYPE_DB_MAX_AGE = timedelta(days=5)

# Adapters with no provider here, and why; `traust admin toolchain` can name them.
UNREGISTERED: Mapping[str, str] = {
    "crypto_probe": "core's CryptoProbe (FactEnumerator) is the source-tree crypto census",
    "crypto_audit": "core's CryptoProbe, ImageCryptoProbe and ClusterCryptoProbe cover its "
    "source, image and cluster modes",
}

# What `register_tools` registers, so a lazy registration knows the names before the config.
TOOL_NAMES = (
    "checkov",
    "gitleaks",
    "gitleaks-history",
    "govulncheck",
    "grype",
    "joern",
    "opengrep",
    "osv",
    "osv_sbom",
    "yara",
)

Res = TypeVar("Res")


@dataclass(frozen=True, slots=True)
class AdapterTool(Generic[Res]):
    """One engine adapter over one kind of target, with its binary's version and database."""

    name: str
    binaries: tuple[str, ...]
    scan: Callable[[Any], Res]
    clock: Clock
    precondition: Callable[[], Readiness] | None = None
    target: ToolTarget = ToolTarget.CHECKOUT
    pin: Mapping[str, Any] = field(default_factory=dict)  # the binary's external-tools.yaml row
    # The argv `scan` runs, for adapters that build it from the target alone.
    argv: Callable[[Any], Sequence[str]] | None = None

    def check(self) -> Readiness:
        if self.binaries and not (found := on_path(*self.binaries, missing=" not on PATH")).ready:
            return found
        return self.precondition() if self.precondition else Readiness(ready=True)

    def acquire(self, request: ToolRequest) -> Result[Res]:
        given, where = self._target(request)
        try:
            result = self.scan(given)
        except TraustError:
            raise
        except ValueError as e:
            raise ValidationError(f"{self.name} over {where}: {e}") from e
        except (OSError, RuntimeError) as e:  # missing binary, timeout, tool failure
            raise ServiceError(f"{self.name} over {where}: {e}") from e
        db = self.database()
        return Result(
            result,
            Acquisition(
                provider=self.name,
                acquired_at=self.clock.now(),
                version=_scanner_version(result),
                source=str(where.resolve()),
                argv_sha256=argv_digest(self.argv(given)) if self.argv else None,
                db_built_at=db.built_at if db else None,
            ),
        )

    def version(self) -> str | None:
        if not self._binary:
            return None  # an API, not a binary (osv)
        return toolchain.tool_version(
            self._binary,
            version_cmd=self.pin.get("version_cmd"),
            version_regex=self.pin.get("version_regex"),
        )

    def database(self) -> DatabaseStatus | None:
        binary = self._binary
        if (
            binary not in toolchain.POPULATABLE_TOOLS
            or (info := toolchain.db_status(binary)) is None
        ):
            return None
        return DatabaseStatus(
            tool=self.name,
            exists=info.exists,
            built_at=_built_at(info.built),
            schema_version=info.schema_version,
            max_age=GRYPE_DB_MAX_AGE if binary == "grype" else None,
            path=info.path,
        )

    def update_database(self) -> DatabaseStatus:
        binary = self._binary
        if binary not in toolchain.POPULATABLE_TOOLS:
            raise NoDatabase(f"{self.name} keeps no vulnerability database to update")
        ok, message = toolchain.populate(binary)
        if not ok:
            raise ServiceError(message)
        status = self.database()
        if status is None:
            raise ServiceError(f"{self.name}: database updated but its status is unreadable")
        return status

    @property
    def _binary(self) -> str:
        return self.binaries[0] if self.binaries else ""

    def _target(self, request: ToolRequest) -> tuple[Any, Path]:
        """The scan's input, and the path its errors and provenance name."""
        if request.target is not self.target:
            raise ValidationError(
                f"{self.name} runs over a {self.target.value}, not a {request.target.value}"
            )
        if (sbom := request.sbom) is not None:
            if not sbom.is_file():
                raise ValidationError(f"{self.name}: SBOM is not a file: {sbom}")
            return sbom, sbom
        query = request.symbols
        workspace = query.workspace if query else request.checkout()
        if not workspace.is_dir():
            raise ValidationError(f"{self.name}: workspace is not a directory: {workspace}")
        return query or workspace, workspace


def register_tools(
    ctx: Context,
    *,
    loc: opengrep.Locations | None,
    profile_map: Mapping[str, Any],
    pins: Mapping[str, Mapping[str, Any]],
    rule_pack: Path,
    allowlist: opengrep.RulePackAllowlist | None = None,
    yara_rules: Sequence[str] = (),
    osv_client: Callable[[], OsvClient] = OsvClient,
) -> None:
    """Register every engine scanner in `ctx.tools` (Checkov included, through
    `register_checkov`) and the pins' `expected` versions as `ctx.tool_floors`.

    `profile_map` is the deployment's safe_exec profiles (`AdaptersOps.safe_exec_profile_map()`),
    `pins` external-tools.yaml (`ToolchainOps.pins()`), `rule_pack` / `allowlist` the opengrep
    pack and supplemental-pack allowlist, `yara_rules` pinned `url@sha` sources (empty: the
    adapter's pinned default).
    """
    clock = ctx.clock
    profiles = dict(profile_map)
    rules = list(yara_rules)

    def tool(
        name: str, binaries: tuple[str, ...], scan: Callable[[Any], Any], **kw: Any
    ) -> AdapterTool[Any]:
        return AdapterTool(
            name, binaries, scan, clock, pin=pins.get(next(iter(binaries), ""), {}), **kw
        )

    def gitleaks_ready() -> Readiness:
        return _resolves("gitleaks", lambda: gitleaks.resolve_gitleaks_config(None, loc))

    tools = [
        tool(
            "gitleaks",
            ("gitleaks",),
            lambda w: gitleaks.scan(w, mode="dir", loc=loc),
            precondition=gitleaks_ready,
        ),
        tool(
            "gitleaks-history",
            ("gitleaks", "git"),
            lambda w: gitleaks.scan(w, mode="history", loc=loc),
            precondition=gitleaks_ready,
        ),
        tool(
            "govulncheck",
            ("govulncheck", "go"),
            lambda w: govulncheck.scan(w, profile_map=profiles),
            argv=lambda _: govulncheck.command(),
        ),
        tool(  # DB frozen by default
            "grype", ("grype",), lambda w: grype.scan(w), argv=lambda w: grype.command(str(w))
        ),
        tool(
            "joern",
            ("joern", "joern-parse"),
            lambda q: joern.scan(q.workspace, symbols=list(q.names)),
            target=ToolTarget.SYMBOLS,
        ),
        tool(
            "opengrep",
            ("opengrep",),
            lambda w: opengrep.scan(w, rule_pack=rule_pack, allowlist=allowlist, loc=loc),
            precondition=lambda: _resolves(
                "opengrep", lambda: opengrep.resolve_rule_pack_dir(rule_pack, loc)
            ),
        ),
        tool("osv", (), lambda w: osv.scan(w, client=osv_client())),
        tool(
            "osv_sbom",
            (),
            lambda p: osv_sbom.scan(p, client=osv_client()),
            target=ToolTarget.SBOM,
        ),
        tool("yara", ("yara", "git"), lambda w: yara.scan(w, rules=rules)),
    ]
    for t in tools:
        ctx.tools.register(t.name, lambda t=t: t)
    cloud_config.register_checkov(ctx)
    binaries = {t.name: t._binary for t in tools}
    ctx.tool_floors.update(
        {
            name: str(spec["expected"])
            for name, binary in {**binaries, cloud_config.CHECKOV: cloud_config.CHECKOV}.items()
            if binary and (spec := pins.get(binary)) and spec.get("expected")
        }
    )


def _scanner_version(result: object) -> str | None:
    return (result.metadata.scanner_version or None) if isinstance(result, AdapterResult) else None


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
