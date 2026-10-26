"""Every traust-engine provider on a traust-core `Context`, registered once by name. The app's
engine (tool pins, safe-exec profiles, rule pack, allowlist) is loaded on first use, so a command
that never uses one runs without its config; one that does gets the load's error naming the file.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from functools import cache
from pathlib import Path
from typing import Any

from traust_core.v1.context import Context
from traust_core.v1.errors import ConfigError
from traust_core.v1.models.cloud_config import CHECKOV

from traust_engine.adapters.cloud_config import register_checkov
from traust_engine.adapters.compliance_sources import register_compliance_sources
from traust_engine.adapters.detection_quality import register_detection_quality
from traust_engine.adapters.fleet_fix import register_fleet_fix
from traust_engine.adapters.opengrep import load_supplemental_packs
from traust_engine.adapters.tools import TOOL_NAMES, register_tools
from traust_engine.engine import HarnessEngine


class _OnFirstUse:
    """A provider built on its first attribute read."""

    def __init__(self, build: Callable[[], Any]) -> None:
        self._build = cache(build)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._build(), name)


def register_providers(
    ctx: Context, engine: Callable[[], HarnessEngine], *, canaries: str = "canaries"
) -> None:
    """ADR and docs sources, fleet-fix applier and golden runner, rule-pack source and canary
    materialiser (`recall-benchmark/<canaries>`), and every scanner tool with its floors."""

    @cache
    def configured() -> Context:
        # PENDING(engine Policy): the tools' config still comes from the HarnessContext.
        loaded = engine()
        try:
            pack = loaded.adapters.rule_pack_dir()
        except ValueError as e:
            raise ConfigError(str(e)) from e
        cache_dir = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache")) / "recall-bench"
        staged = Context(ctx.config, clock=ctx.clock)
        register_detection_quality(
            staged,
            pack=pack,
            supplements=load_supplemental_packs(),
            canary_sources=loaded.ctx.config_home / "recall-benchmark" / canaries,
            canary_repos=cache_dir / canaries,
        )
        register_tools(
            staged,
            loc=loaded.ctx.locations,
            profile_map=loaded.adapters.safe_exec_profile_map(),
            pins=loaded.toolchain.pins(),
            rule_pack=pack,
            allowlist=loaded.adapters.allowlist_for_opengrep(),
        )
        ctx.tool_floors.update(staged.tool_floors)
        return staged

    # NEED(config: product -> docs slug/version): no DocsTarget map yet, so every product's
    # docs lookup is refused by name until one has a home.
    register_compliance_sources(ctx, {})
    register_fleet_fix(ctx)
    register_checkov(ctx)  # needs none of the engine's config
    ctx.rule_packs = _OnFirstUse(lambda: configured().rule_packs)
    ctx.canaries = _OnFirstUse(lambda: configured().canaries)
    for name in set(TOOL_NAMES) - {CHECKOV}:
        ctx.tools.register(name, lambda name=name: configured().tools.get(name))
