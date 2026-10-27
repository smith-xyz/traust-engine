"""Per-tool DB status parsers.

Each parser probes the tool's native cache location and returns a DBInfo
describing the current state of its vulnerability database.
"""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

from traust_engine.toolchain._types import DBInfo

# Native DB cache locations (platform-dependent defaults)
_GRYPE_DB_DIR = Path(
    os.environ.get(
        "GRYPE_DB_CACHE_DIR",
        Path.home() / ".cache" / "grype" / "db",
    )
)


def grype_db_present(db_dir: Path) -> bool:
    """Whether *db_dir* holds a grype vulnerability database, by the layout grype itself reads
    (``<schema>/vulnerability.db``). Shared by the status check and the scan-time preflight so
    the two can never disagree about what counts as "present"."""
    return db_dir.is_dir() and any(db_dir.glob("*/vulnerability.db"))


def _parse_grype_db_status(db_dir: Path | None = None) -> DBInfo:
    """Parse ``grype db status`` output for build date and schema.

    *db_dir* pins the check to a feeds-cache mount (passed as ``GRYPE_DB_CACHE_DIR`` to the
    status probe); without it, grype's own native cache location applies.
    """
    env = {**os.environ, "GRYPE_DB_CACHE_DIR": str(db_dir)} if db_dir else None
    try:
        proc = subprocess.run(
            ["grype", "db", "status"],
            capture_output=True,
            text=True,
            timeout=15,
            env=env,
        )
        text = proc.stdout + proc.stderr
    except (subprocess.SubprocessError, OSError):
        text = ""

    built = None
    schema = None
    location = None
    for line in text.splitlines():
        if m := re.match(r"^\s*Built:\s*(.+)", line):
            built = m.group(1).strip()
        elif m := re.match(r"^\s*Schema:\s*(\S+)", line):
            schema = m.group(1).strip()
        elif m := re.match(r"^\s*Location:\s*(.+)", line):
            location = m.group(1).strip()

    checked_dir = db_dir or (Path(location) if location else _GRYPE_DB_DIR)
    exists = grype_db_present(checked_dir)

    return DBInfo(
        exists=exists or built is not None,
        built=built,
        schema_version=schema,
        path=str(checked_dir),
    )


def govulncheck_db_present(db_dir: Path) -> bool:
    """Whether *db_dir* holds an extracted Go vulnerability database (``vulndb.zip``'s layout:
    ``index/`` and ``ID/``). Shared by the status check and the scan-time preflight."""
    return db_dir.is_dir() and (db_dir / "index").is_dir() and (db_dir / "ID").is_dir()


def _parse_govulncheck_db_status(db_dir: Path | None = None) -> DBInfo:
    """govulncheck keeps no native local cache by default (it queries vuln.go.dev live unless
    pointed at an extracted database with ``-db file://``). Without *db_dir* there is nothing to
    check, so a workstation scan is left to govulncheck's own live-query behaviour; with it, the
    feeds-cache mount is checked for the layout ``-db file://`` reads."""
    if db_dir is None:
        return DBInfo(exists=True)
    return DBInfo(exists=govulncheck_db_present(db_dir), path=str(db_dir))


_PARSERS: dict[str, callable] = {
    "grype": _parse_grype_db_status,
    "govulncheck": _parse_govulncheck_db_status,
}

# Tools that have no vuln DB the harness tracks. osv-scanner's offline
# database exists only on air-gapped deployments, provided and kept current
# by the adopter (owner decision 2026-10-20).
_NO_DB_TOOLS = {
    "opengrep",
    "gitleaks",
    "syft",
    "skopeo",
    "cosign",
    "yara",
    "joern",
    "pip-audit",
    "osv-scanner",
}


def db_status(tool_name: str, db_dir: Path | None = None) -> DBInfo | None:
    """Return DB status for *tool_name*, or None if the tool has no DB. *db_dir* checks a
    feeds-cache mount instead of the tool's native cache location (grype, govulncheck only)."""
    if tool_name in _NO_DB_TOOLS:
        return None
    parser = _PARSERS.get(tool_name)
    if parser is None:
        return None
    return parser(db_dir)
