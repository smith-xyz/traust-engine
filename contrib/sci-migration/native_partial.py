import collections
import hashlib
import json
import shutil
from pathlib import Path

RECORD_ERRORS = {
    "unknown_contract",
    "contract_validation",
    "ambiguous_repository",
    "unresolved_binding",
    "ambiguous_binding",
    "unresolved_repository",
    "unrecognized_artifact",
    "invalid_json",
    "number_representation",
    "directory_symlink",
    "unsafe_source_path",
    "unreadable_source",
    "ingest_rejected",
    "mapping_failure",
}


def safe_path(root, relative):
    part = Path(relative)
    if part.is_absolute() or ".." in part.parts:
        raise ValueError("unsafe input path")
    path = root / part
    if not path.resolve().is_relative_to(root.resolve()):
        raise ValueError("path escapes source")
    return path


def revised_source(source, revision_file, destination, approval_sha256):
    raw = revision_file.read_bytes()
    if hashlib.sha256(raw).hexdigest() != approval_sha256:
        raise ValueError("revised input approval mismatch")
    revision = json.loads(raw)
    replacements = revision.get("replacements")
    if not isinstance(replacements, list) or not replacements:
        raise ValueError("revised input requires explicit replacements")
    checks = []
    paths = set()
    for row in replacements:
        relative = row["path"]
        if relative in paths:
            raise ValueError("duplicate revised path")
        paths.add(relative)
        original = safe_path(source, relative)
        replacement = safe_path(revision_file.parent, row["replacement_file"])
        if not original.is_file() or not replacement.is_file():
            raise ValueError("revised input source absent")
        if (
            hashlib.sha256(original.read_bytes()).hexdigest() != row["original_sha256"]
            or hashlib.sha256(replacement.read_bytes()).hexdigest() != row["replacement_sha256"]
        ):
            raise ValueError("revised input before/after hash mismatch")
        json.loads(replacement.read_bytes())
        checks.append((relative, replacement))
    if destination.exists():
        raise ValueError("new immutable effective-source directory required")
    shutil.copytree(source, destination, symlinks=True)
    for relative, replacement in checks:
        target = safe_path(destination, relative)
        if target.is_symlink():
            target.unlink()
        shutil.copyfile(replacement, target)
    return destination


def partial_native_result(output):
    result = json.loads((output / "migration-result.json").read_text())
    issues = [
        json.loads(line) for line in (output / "issues.jsonl").read_text().splitlines() if line
    ]
    decisions = [
        json.loads(line) for line in (output / "decisions.jsonl").read_text().splitlines() if line
    ]
    if not result.get("diagnostics_complete") or result.get("status") == "blocked":
        raise ValueError("native systemic failure; partial apply refused")
    unexpected = [
        issue
        for issue in issues
        if issue.get("blocking", True) and issue.get("error_class") not in RECORD_ERRORS
    ]
    if unexpected:
        raise ValueError("unclassified/systemic native errors; partial apply refused")
    checks = result.get("reconciliation", {})
    if not checks.get("loaded_artifacts_verified") or checks.get("source_unchanged") is not True:
        raise ValueError("native loaded projection/source checks did not complete")
    expected, actual = checks.get("expected_rows"), checks.get("actual_rows")
    if (
        not isinstance(expected, dict)
        or not isinstance(actual, dict)
        or any(
            expected.get(key, 0) != actual.get(key, 0) for key in expected.keys() | actual.keys()
        )
    ):
        raise ValueError("native loaded row counts differ")
    return decisions, issues


def save_quarantine(output, decisions, issues):
    rejected = {
        row["source_file"]: row
        for row in decisions
        if row.get("decision") in ("blocked", "rejected", "unrecognized")
    }
    reasons = collections.defaultdict(list)
    for issue in issues:
        if issue.get("source_file"):
            reasons[issue["source_file"]].append(issue)
    file = output / "quarantine.jsonl"
    with file.open("x") as stream:
        file.chmod(0o600)
        for path, row in sorted(rejected.items()):
            stream.write(
                json.dumps(
                    {
                        "path": path,
                        "source_digest": row.get("source_digest"),
                        "decision": row.get("decision"),
                        "issues": reasons[path],
                    },
                    sort_keys=True,
                )
                + "\n"
            )
    return len(rejected)


def project_successful_groups(accepted, quarantine):
    from native_sci_shim import projection_rows

    groups = collections.defaultdict(list)
    for item in accepted:
        if item[0]["artifact"] in ("report", "triage"):
            groups[(item[1].binding.product_repo_id, item[1].binding.run_id)].append(item)
    selected = []
    failures = []
    for key, group in groups.items():
        reports = [item for item in group if item[0]["artifact"] == "report"]
        triages = [item for item in group if item[0]["artifact"] == "triage"]
        try:
            report_rows = projection_rows(reports)
            if not report_rows:
                raise ValueError("no selected report")
            selected.extend(report_rows)
        except ValueError as error:
            failures.extend(
                {
                    "path": item[0]["source_file"],
                    "phase": "SCI_projection",
                    "reason": str(error),
                    "product_repo_id": key[0],
                }
                for item in group
            )
            continue
        for triage in triages:
            try:
                rows = projection_rows([*reports, triage])
                existing_ids = {row["result_id"] for row in selected}
                selected.extend(row for row in rows if row["result_id"] not in existing_ids)
            except ValueError as error:
                failures.append(
                    {
                        "path": triage[0]["source_file"],
                        "phase": "SCI_projection",
                        "reason": str(error),
                        "product_repo_id": key[0],
                    }
                )
    with quarantine.open("x") as stream:
        quarantine.chmod(0o600)
        for row in failures:
            stream.write(json.dumps(row, sort_keys=True) + "\n")
    return selected, failures
