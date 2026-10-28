"""Harness Engine — the continuous-ops service on traust-core.

Submodules:
    ops         — continuous ops: pack spec, controller (tick), admission, reaper

Kept for traust until its PENDING decision (sweep stages) retires or ports them:
    engine      — the ``HarnessEngine`` facade (adapters, sweep)
    sweep       — class-generalization scan engine
    adapters    — opengrep (sweep stages)
    corpus      — population resolver the sweep stages read
"""

from traust_engine.assets import harness_version as _harness_version
from traust_engine.engine import HarnessEngine
from traust_engine.ops import EngineLoop, Pack

#: Engine version from installed package metadata (pyproject) — never a hardcoded
#: string that drifts from the wheel. Falls back to "0.0.0" in an uninstalled
#: source tree (see assets.harness_version).
__version__ = _harness_version()

__all__ = ["EngineLoop", "HarnessEngine", "Pack"]
