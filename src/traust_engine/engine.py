"""HarnessEngine — the client for the processing core.

Construct once from the loaded config context (or an explicit one), then call
namespaced operations. The engine only ever *receives* its context; it never
reaches for config itself. It runs standalone — contracts + a config home is all
it needs, with no dependency on the app:

    from traust_engine import HarnessEngine

    h = HarnessEngine(ctx)                       # explicit context (tests, app)
    h.sweep.collect(...)

Namespaces mirror the engine's submodules: `.adapters` (the rule-lane stage's opengrep
config), `.sweep`.

PENDING(decision: sweep stages) — kept for traust;
deleted when traust retires or ports it.
"""

from __future__ import annotations

from functools import cached_property
from pathlib import Path

from traust_contracts import HarnessContext, load_context

from traust_engine.adapters.ops import AdaptersOps
from traust_engine.sweep.ops import SweepOps


class HarnessEngine:
    def __init__(self, ctx: HarnessContext) -> None:
        self._ctx = ctx

    @classmethod
    def load(cls, *, config_home: Path | None = None) -> HarnessEngine:
        """Build from config — the one canonical load point (contracts)."""
        return cls(load_context(config_home=config_home))

    @property
    def ctx(self) -> HarnessContext:
        return self._ctx

    @cached_property
    def adapters(self) -> AdaptersOps:
        return AdaptersOps(self._ctx)

    @cached_property
    def sweep(self) -> SweepOps:
        return SweepOps(self._ctx)
