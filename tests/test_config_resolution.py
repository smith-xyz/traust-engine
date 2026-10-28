"""The engine ships no configuration: config resolution is traust-core's `Context`."""

from __future__ import annotations

from pathlib import Path


def test_engine_ships_no_config():
    """The engine owns the resolver's consumers, never the config files.

    Two data trees ship by design and are not configuration: the rule pack
    (secure-code-audit) and the public compliance reference data (NIST
    800-53 spine and profiles, framework catalogs, the control-to-check
    mapping; owner decision 2026-10-17). Neither varies per estate.
    """
    import traust_engine

    data = Path(traust_engine.__file__).parent / "data"
    shipped = {"secure-code-audit", "compliance"}
    stray = [
        p
        for p in data.rglob("*")
        if p.suffix in (".yaml", ".yml", ".json") and not shipped & set(p.parts)
    ]
    assert stray == [], stray
