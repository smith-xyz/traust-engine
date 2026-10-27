"""grype and govulncheck reading their vulnerability database from a feeds-cache mount
(`<feeds_cache>/tool-dbs/<tool>`) instead of their native caches: explicit invocation, and a
missing or unusable database raising before the scanner process starts — never a silent
zero-finding scan. Design: scanner-currency-plan.md "Target state"."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import pytest

from traust_engine.adapters import govulncheck, grype
from traust_engine.toolchain._errors import ScannerDatabaseUnavailable


def _grype_db(tmp_path: Path, name: str = "grype-db") -> Path:
    db = tmp_path / name
    (db / "6").mkdir(parents=True)
    (db / "6" / "vulnerability.db").write_bytes(b"")
    return db


def _govulncheck_db(tmp_path: Path, name: str = "govulncheck-db") -> Path:
    db = tmp_path / name
    (db / "index").mkdir(parents=True)
    (db / "ID").mkdir()
    return db


class TestGrypePreflight:
    def test_empty_db_dir_raises_before_running_grype(self, tmp_path):
        empty = tmp_path / "empty"
        empty.mkdir()
        with (
            mock.patch("traust_engine.adapters.grype.subprocess.run") as run,
            pytest.raises(ScannerDatabaseUnavailable, match=str(empty)),
        ):
            grype.scan(tmp_path, db_dir=empty)
        run.assert_not_called()

    def test_missing_db_dir_raises_before_running_grype(self, tmp_path):
        with (
            mock.patch("traust_engine.adapters.grype.subprocess.run") as run,
            pytest.raises(ScannerDatabaseUnavailable),
        ):
            grype.scan(tmp_path, db_dir=tmp_path / "does-not-exist")
        run.assert_not_called()

    def test_populated_db_dir_runs_with_grype_db_cache_dir_set(self, tmp_path):
        db = _grype_db(tmp_path)
        done = SimpleNamespace(returncode=0, stdout=json.dumps({"matches": []}), stderr="")
        with mock.patch("traust_engine.adapters.grype.subprocess.run", return_value=done) as run:
            grype.scan(tmp_path, db_dir=db)
        scan_call = next(c for c in run.call_args_list if "-o" in c.args[0])
        assert scan_call.kwargs["env"]["GRYPE_DB_CACHE_DIR"] == str(db)
        assert scan_call.kwargs["env"]["GRYPE_DB_AUTO_UPDATE"] == "false"

    def test_no_db_dir_keeps_pre_split_behaviour_no_preflight_gate(self, tmp_path):
        """Without db_dir (no feeds cache configured), grype runs exactly as it did before the
        image split: the environment it inherits decides what database it finds, and the
        preflight gate — which only exists for an explicitly pinned feeds-cache mount — never
        raises here, including when nothing is on disk at all."""
        done = SimpleNamespace(returncode=0, stdout=json.dumps({"matches": []}), stderr="")
        with mock.patch("traust_engine.adapters.grype.subprocess.run", return_value=done) as run:
            grype.scan(tmp_path)
        scan_call = next(c for c in run.call_args_list if "-o" in c.args[0])
        assert "GRYPE_DB_CACHE_DIR" not in scan_call.kwargs["env"]


class TestGovulncheckCommand:
    def test_no_db_dir_builds_the_unpinned_command(self):
        assert govulncheck.command("govulncheck") == ["govulncheck", "-json", "./..."]

    def test_db_dir_adds_an_explicit_db_flag(self, tmp_path):
        db = tmp_path / "db"
        assert govulncheck.command("govulncheck", db_dir=db) == [
            "govulncheck",
            "-json",
            "-db",
            f"file://{db}",
            "./...",
        ]


class TestGovulncheckPreflight:
    def _repo(self, tmp_path: Path) -> Path:
        repo = tmp_path / "mod"
        repo.mkdir()
        (repo / "go.mod").write_text("module example.com/x\n\ngo 1.21\n", encoding="utf-8")
        return repo

    def test_empty_db_dir_raises_before_running_govulncheck(self, tmp_path):
        repo = self._repo(tmp_path)
        empty = tmp_path / "empty"
        empty.mkdir()
        with (
            mock.patch("traust_engine._util.safe_exec.run") as run,
            pytest.raises(ScannerDatabaseUnavailable, match=str(empty)),
        ):
            govulncheck.scan(repo, db_dir=empty)
        run.assert_not_called()

    def test_missing_db_dir_raises_before_running_govulncheck(self, tmp_path):
        repo = self._repo(tmp_path)
        with (
            mock.patch("traust_engine._util.safe_exec.run") as run,
            pytest.raises(ScannerDatabaseUnavailable),
        ):
            govulncheck.scan(repo, db_dir=tmp_path / "does-not-exist")
        run.assert_not_called()

    def test_populated_db_dir_runs_with_the_explicit_db_flag_and_govulndb_env(self, tmp_path):
        repo = self._repo(tmp_path)
        db = _govulncheck_db(tmp_path)
        config = json.dumps({"config": {"scanner_name": "govulncheck", "scanner_version": "v1"}})
        with mock.patch("traust_engine._util.safe_exec.run", return_value=(0, config, "")) as run:
            govulncheck.scan(repo, db_dir=db)
        argv = run.call_args.args[0]
        assert argv == ["govulncheck", "-json", "-db", f"file://{db}", "./..."]
        assert run.call_args.kwargs["extra_env"]["GOVULNDB"] == f"file://{db}"

    def test_no_db_dir_keeps_pre_split_behaviour_no_preflight_gate(self, tmp_path):
        repo = self._repo(tmp_path)
        config = json.dumps({"config": {"scanner_name": "govulncheck", "scanner_version": "v1"}})
        with mock.patch("traust_engine._util.safe_exec.run", return_value=(0, config, "")) as run:
            govulncheck.scan(repo)
        argv = run.call_args.args[0]
        assert argv == ["govulncheck", "-json", "./..."]
        assert run.call_args.kwargs["extra_env"] is None
