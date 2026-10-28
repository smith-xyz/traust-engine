"""HarnessEngine — the facade traust's `load_engine` still builds. Its namespaces moved to
traust-core with the sweep stages and the portfolio graph; it goes with the last caller."""

from __future__ import annotations

from pathlib import Path

from traust_contracts import HarnessContext, load_context


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
