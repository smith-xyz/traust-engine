"""Ecosystem-aware version normalization: a comparable numeric release tuple."""

from __future__ import annotations

import re


def parse_semver(v: str) -> tuple[int, ...] | None:
    m = re.match(r"^v?(\d+)\.(\d+)\.(\d+)", v or "")
    return (int(m.group(1)), int(m.group(2)), int(m.group(3))) if m else None


def _leading_numeric(s: str, max_parts: int | None = None) -> tuple[int, ...] | None:
    """Leading dotted-numeric release tuple of `s` (e.g. '1.0.0.Final' ->
    (1,0,0); 'preview' -> None). `max_parts` caps the component count."""
    m = re.match(r"(\d+(?:\.\d+)*)", s)
    if not m:
        return None
    parts = tuple(int(x) for x in m.group(1).split("."))
    return parts[:max_parts] if max_parts is not None else parts


def parse_version(version: str, ecosystem: str = "go") -> tuple[int, ...] | None:
    """Ecosystem-aware normalization to a comparable numeric release tuple.

    UNPARSEABLE -> None. Callers treat None as "cannot decide": the repo
    stays `inconclusive` and is still deep-scanned — a garbage version never
    becomes a false `version_not_in_range`/`safe`. This is a best-effort
    normalizer, NOT a range solver: npm `^`/`~`, Maven ranges, and NuGet
    floating versions are left to the per-clone analyzer, which is
    authoritative for ranges.
    """
    v = (version or "").strip()
    if not v:
        return None
    if ecosystem == "go":
        # Byte-identical to the legacy Go/semver path.
        return parse_semver(v)
    if ecosystem in ("npm", "cargo"):
        # Strip a leading 'v', take the first 3 dotted numeric components.
        if v[:1] in ("v", "V"):
            v = v[1:]
        return _leading_numeric(v, 3)
    if ecosystem == "pypi":
        # PEP 440-lite: drop the `N!` epoch, then the numeric release tuple.
        if "!" in v:
            v = v.split("!", 1)[1]
        if v[:1] in ("v", "V"):
            v = v[1:]
        return _leading_numeric(v)
    # maven (drop qualifier .Final/-RELEASE), ruby/nuget (dotted numeric),
    # and any unknown ecosystem all reduce to the leading numeric release.
    return _leading_numeric(v)
