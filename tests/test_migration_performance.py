from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from pydantic import ValidationError
from test_migration_rehearsal import MemoryDatabase, layer, put, setup

from traust_engine.corpus import migration_rehearsal as migration
from traust_engine.corpus.migration_discovery import MigrationOptions
from traust_engine.corpus.migration_workers import validation_results


def test_parallel_validation_preserves_order_and_errors(tmp_path: Path) -> None:
    tasks = []
    for index in range(6):
        path = tmp_path / f"{index}-findings-layer.json"
        path.write_text(json.dumps(layer() if index % 2 == 0 else {}))
        tasks.append((str(path), "layer", hashlib.sha256(path.read_bytes()).hexdigest()))
    serial = list(validation_results(iter(tasks), 1))
    parallel = list(validation_results(iter(tasks), 2))
    assert serial == parallel
    assert [task for task, _ in parallel] == tasks


def test_parallel_validation_stops_on_source_change(tmp_path: Path) -> None:
    path = tmp_path / "layer.json"
    path.write_text(json.dumps(layer()))
    with pytest.raises(RuntimeError, match="Source changed"):
        list(validation_results(iter([(str(path), "layer", "0" * 64)]), 2))


@pytest.mark.parametrize("workers", [0, 9, True, "2"])
def test_workers_are_bounded_and_explicit(workers) -> None:
    with pytest.raises(ValidationError):
        MigrationOptions(validation_workers=workers)


def test_registrations_cached_by_full_product_repo_ref(tmp_path: Path) -> None:
    root, config, output = setup(tmp_path, "migration: {validation_workers: 2}\n")
    for name in ("one", "two"):
        put(root, f"findings/product/repo/{name}-findings-layer.json", layer())
    registrations = []

    class CountingDatabase(MemoryDatabase):
        def register_repository(self, slug: str, url: str, ref: str) -> str:
            registrations.append((slug, url, ref))
            return super().register_repository(slug, url, ref)

    result = migration.rehearse(root, config, "", output, database_factory=CountingDatabase)
    assert result["diagnostics_complete"]
    assert result["outcomes"] == {"ingested": 2}
    assert registrations == [("product", "https://example.test/r", "")]
    assert result["validation_processed"] == 2


def test_explicit_schema_pass_not_repeated_for_ingestion(tmp_path: Path, monkeypatch) -> None:
    from traust_engine.corpus import migration_workers

    root, config, output = setup(tmp_path)
    put(root, "findings/product/repo/good-findings-layer.json", layer())
    calls = []
    original = migration_workers.validate_artifact

    def counted(*args, **kwargs):
        calls.append(args[0])
        return original(*args, **kwargs)

    monkeypatch.setattr(migration_workers, "validate_artifact", counted)
    result = migration.rehearse(root, config, "", output, database_factory=MemoryDatabase)
    assert result["status"] == "passed"
    assert len(calls) == 1


def test_rejected_all_sources_does_not_use_uninitialized_progress(tmp_path: Path) -> None:
    root, config, output = setup(tmp_path)
    put(root, "invalid-findings-layer.json", {"bad": float("inf")})
    result = migration.rehearse(root, config, "", output, database_factory=MemoryDatabase)
    assert result["diagnostics_complete"]
    assert result.get("validation_processed", 0) == 0
