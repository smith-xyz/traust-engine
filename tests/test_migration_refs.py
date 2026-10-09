from pathlib import Path

import pytest
from test_migration_rehearsal import MemoryDatabase, put, setup
from test_migration_validation import report

from traust_engine.corpus import migration_rehearsal as migration
from traust_engine.corpus.migration_discovery import DiscoveryError
from traust_engine.corpus.migration_refs import recorded_commit, repository_ref

SHA = "de2fb00501f99b53123dd9ba9c02bfd09d2a6793"


@pytest.mark.parametrize(
    "value",
    [
        SHA + " (master HEAD, 2026-05-08); requested commit unavailable",
        "main",
        "de2fb005",
        " " + SHA,
        SHA + "\n",
        "",
        123,
    ],
)
def test_diagnostic_or_nonimmutable_commit_rejected(value) -> None:
    with pytest.raises(DiscoveryError):
        recorded_commit(value)


def test_bare_commit_and_absent_commit_preserved() -> None:
    assert recorded_commit(SHA) == SHA
    assert recorded_commit("a" * 64) == "a" * 64
    assert recorded_commit(None) is None


@pytest.mark.parametrize("value", ["", "main", "release-4.23", SHA, "refs/heads/main"])
def test_valid_requested_ref(value) -> None:
    assert repository_ref(value) == value


@pytest.mark.parametrize(
    "value", ["-option", "main note", "main..other", "main.lock", "refs//heads/main", "main@{1}"]
)
def test_unsafe_requested_ref_rejected(value) -> None:
    with pytest.raises(DiscoveryError):
        repository_ref(value)


def test_prose_commit_blocked_before_native_registration_and_ingestion(
    tmp_path: Path, monkeypatch
) -> None:
    from traust_engine.corpus import migration_workers

    monkeypatch.setattr(migration_workers, "validate_artifact", lambda *args, **kwargs: None)
    root, config, output = setup(tmp_path)
    document = report()
    document["metadata"]["repository"] = "https://example.test/r"
    document["metadata"]["commit"] = SHA + " (master HEAD); requested ref does not exist"
    path = put(root, "findings/product/repo/repo-security-audit.json", document)
    before = path.read_bytes()
    calls = []

    class NoUnsafeRegistration(MemoryDatabase):
        def register_repository(self, *args):
            calls.append(args)
            return super().register_repository(*args)

    result = migration.rehearse(root, config, "", output, database_factory=NoUnsafeRegistration)
    assert result["diagnostics_complete"]
    assert result["outcomes"] == {"blocked": 1}
    assert calls == []
    assert path.read_bytes() == before
    assert result["issue_counts"] == {"ambiguous_repository": 1}
