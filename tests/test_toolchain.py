"""Tests for traust_engine.toolchain — freeze, check, parsers, preflight, stamp."""

from traust_engine.toolchain._freeze import freeze_env, freeze_flags
from traust_engine.toolchain._parsers import (
    db_status,
    govulncheck_db_present,
    grype_db_present,
)
from traust_engine.toolchain._preflight import preflight_failures
from traust_engine.toolchain._stamp import stamp_string
from traust_engine.toolchain._types import DBInfo, ToolCheck


class TestFreeze:
    def test_grype_freeze_env(self):
        env = freeze_env("grype")
        assert env["GRYPE_DB_AUTO_UPDATE"] == "false"
        assert env["GRYPE_CHECK_FOR_APP_UPDATE"] == "false"

    def test_syft_freeze_env(self):
        env = freeze_env("syft")
        assert env["SYFT_CHECK_FOR_APP_UPDATE"] == "false"

    def test_govulncheck_freeze_env_no_db_dir(self):
        env = freeze_env("govulncheck")
        assert "GOVULNDB" not in env

    def test_govulncheck_freeze_env_with_db_dir(self):
        env = freeze_env("govulncheck", db_dir="/tmp/vulndb")
        assert env["GOVULNDB"] == "file:///tmp/vulndb"

    def test_osv_scanner_freeze_flags(self):
        flags = freeze_flags("osv-scanner")
        assert flags == ["--offline"]

    def test_unknown_tool_returns_empty(self):
        assert freeze_env("unknown-tool") == {}
        assert freeze_flags("unknown-tool") == []

    def test_grype_freeze_env_no_db_dir_omits_cache_dir(self):
        env = freeze_env("grype")
        assert "GRYPE_DB_CACHE_DIR" not in env

    def test_grype_freeze_env_with_db_dir_points_at_the_feeds_cache_mount(self):
        env = freeze_env("grype", db_dir="/mnt/feeds/tool-dbs/grype")
        assert env["GRYPE_DB_CACHE_DIR"] == "/mnt/feeds/tool-dbs/grype"
        assert env["GRYPE_DB_AUTO_UPDATE"] == "false"


class TestDbPresence:
    """grype_db_present / govulncheck_db_present: the single source of truth the status check
    and the scan-time preflight both read, so they can never disagree."""

    def test_grype_db_present_requires_the_vulnerability_db_file(self, tmp_path):
        assert grype_db_present(tmp_path) is False
        (tmp_path / "6").mkdir()
        assert grype_db_present(tmp_path) is False
        (tmp_path / "6" / "vulnerability.db").write_bytes(b"")
        assert grype_db_present(tmp_path) is True

    def test_grype_db_present_missing_directory(self, tmp_path):
        assert grype_db_present(tmp_path / "absent") is False

    def test_govulncheck_db_present_requires_both_index_and_id_dirs(self, tmp_path):
        assert govulncheck_db_present(tmp_path) is False
        (tmp_path / "index").mkdir()
        assert govulncheck_db_present(tmp_path) is False  # ID/ still missing
        (tmp_path / "ID").mkdir()
        assert govulncheck_db_present(tmp_path) is True

    def test_govulncheck_db_present_missing_directory(self, tmp_path):
        assert govulncheck_db_present(tmp_path / "absent") is False


class TestDbStatusFeedsCacheOverride:
    """db_status(tool, db_dir=...): a feeds-cache mount overrides the tool's native cache, and
    an empty or corrupt mount is reported as absent — never silently treated as present."""

    def test_grype_status_reads_the_given_db_dir_not_the_native_cache(self, tmp_path, monkeypatch):
        # No `grype` binary in this test environment: the subprocess call fails, and the status
        # falls back to the filesystem check of db_dir alone — still correct without the binary.
        monkeypatch.setattr(
            "traust_engine.toolchain._parsers.subprocess.run",
            lambda *a, **k: (_ for _ in ()).throw(FileNotFoundError("no grype")),
        )
        empty = tmp_path / "empty"
        empty.mkdir()
        info = db_status("grype", db_dir=empty)
        assert info.exists is False
        assert info.path == str(empty)

        populated = tmp_path / "populated"
        (populated / "6").mkdir(parents=True)
        (populated / "6" / "vulnerability.db").write_bytes(b"")
        info = db_status("grype", db_dir=populated)
        assert info.exists is True

    def test_govulncheck_status_reads_the_given_db_dir(self, tmp_path):
        empty = tmp_path / "empty"
        empty.mkdir()
        assert db_status("govulncheck", db_dir=empty).exists is False

        full = tmp_path / "full"
        (full / "index").mkdir(parents=True)
        (full / "ID").mkdir()
        assert db_status("govulncheck", db_dir=full).exists is True

    def test_govulncheck_status_without_db_dir_keeps_the_pre_split_default(self):
        """No feeds cache configured (laptop/workstation): unchanged from before the image
        split — govulncheck is left to its own live vuln.go.dev query, never gated."""
        assert db_status("govulncheck").exists is True

    def test_corrupt_govulncheck_db_missing_id_subdir_is_absent_not_present(self, tmp_path):
        (tmp_path / "index").mkdir()
        assert db_status("govulncheck", db_dir=tmp_path).exists is False


class TestPreflightFailures:
    def test_missing_tool(self):
        results = [ToolCheck(name="grype", installed=False)]
        msgs = preflight_failures(results)
        assert len(msgs) == 1
        assert "not found on PATH" in msgs[0]

    def test_wrong_version(self):
        results = [ToolCheck(name="grype", installed=True, version="0.100.0", version_ok=False)]
        msgs = preflight_failures(results)
        assert len(msgs) == 1
        assert "does not meet pin" in msgs[0]

    def test_missing_db(self):
        results = [
            ToolCheck(
                name="grype",
                installed=True,
                version="0.115.0",
                version_ok=True,
                db=DBInfo(exists=False, path="/tmp/grype/db"),
            )
        ]
        msgs = preflight_failures(results)
        assert len(msgs) == 1
        assert "DB not found" in msgs[0]

    def test_all_ok(self):
        results = [
            ToolCheck(
                name="grype",
                installed=True,
                version="0.115.0",
                version_ok=True,
                db=DBInfo(exists=True, built="2026-08-24"),
            )
        ]
        msgs = preflight_failures(results)
        assert msgs == []

    def test_tool_without_db_ok(self):
        results = [
            ToolCheck(name="opengrep", installed=True, version="1.25.0", version_ok=True, db=None)
        ]
        msgs = preflight_failures(results)
        assert msgs == []


class TestStamp:
    def test_full_stamp(self):
        s = stamp_string("grype", "0.115.0", db_built="2026-08-24", db_schema="5")
        assert s == "grype 0.115.0 (db built 2026-08-24, schema 5)"

    def test_no_db(self):
        assert stamp_string("opengrep", "1.25.0") == "opengrep 1.25.0"

    def test_db_built_only(self):
        s = stamp_string("osv-scanner", "2.4.0", db_built="2026-08-20")
        assert s == "osv-scanner 2.4.0 (db built 2026-08-20)"

    def test_no_version(self):
        assert stamp_string("grype") == "grype"
