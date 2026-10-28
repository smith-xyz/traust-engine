"""The engine's own version, from package metadata (never a hardcoded string)."""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _pkg_version


def harness_version() -> str:
    """Engine version, from package metadata."""
    try:
        return _pkg_version("traust-engine")
    except PackageNotFoundError:
        return "0.0.0"
