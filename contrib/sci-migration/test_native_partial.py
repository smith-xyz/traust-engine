import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from native_partial import (
    partial_native_result,
    project_successful_groups,
    revised_source,
    save_quarantine,
)
from test_native_job import record


class PartialTests(unittest.TestCase):
    def test_revised_source_preserves_original_and_checks_hashes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            (source / "bad.json").write_bytes(b'{"old":true}')
            replacement = root / "fixed.json"
            replacement.write_bytes(b'{"fixed":true}')
            revision = root / "revision.json"
            revision.write_text(
                json.dumps(
                    {
                        "replacements": [
                            {
                                "path": "bad.json",
                                "replacement_file": "fixed.json",
                                "original_sha256": hashlib.sha256(
                                    (source / "bad.json").read_bytes()
                                ).hexdigest(),
                                "replacement_sha256": hashlib.sha256(
                                    replacement.read_bytes()
                                ).hexdigest(),
                            }
                        ]
                    }
                )
            )
            output = revised_source(
                source,
                revision,
                root / "effective",
                hashlib.sha256(revision.read_bytes()).hexdigest(),
            )
            self.assertEqual((output / "bad.json").read_bytes(), replacement.read_bytes())
            self.assertEqual((source / "bad.json").read_bytes(), b'{"old":true}')
            with self.assertRaises(ValueError):
                revised_source(source, revision, root / "other", "wrong")

    def test_partial_native_requires_completed_reconciliation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result = {
                "status": "failed",
                "diagnostics_complete": True,
                "reconciliation": {
                    "loaded_artifacts_verified": True,
                    "source_unchanged": True,
                    "expected_rows": {"artifact_binding": 1},
                    "actual_rows": {"artifact_binding": 1},
                },
            }
            (root / "migration-result.json").write_text(json.dumps(result))
            (root / "issues.jsonl").write_text(
                json.dumps({"error_class": "contract_validation", "source_file": "bad.json"}) + "\n"
            )
            (root / "decisions.jsonl").write_text(
                json.dumps(
                    {"source_file": "bad.json", "decision": "rejected", "source_digest": "a" * 64}
                )
                + "\n"
            )
            decisions, issues = partial_native_result(root)
            self.assertEqual(save_quarantine(root, decisions, issues), 1)
            self.assertEqual(
                json.loads((root / "quarantine.jsonl").read_text())["path"], "bad.json"
            )
            (root / "issues.jsonl").write_text(
                json.dumps({"error_class": "systemic_failure"}) + "\n"
            )
            with self.assertRaises(ValueError):
                partial_native_result(root)

    def test_bad_triage_does_not_hide_valid_snapshot(self):
        with tempfile.TemporaryDirectory() as temporary:
            report = {"metadata": {"date": "2026-05-01"}, "findings": [{"id": "NEW"}]}
            triage = {
                "triage_completed": "2026-05-02",
                "findings": [{"id": "T1", "orig_id": "OLD"}],
            }
            accepted = [
                record("cumulative", "report", report),
                record(None, "triage", triage, "triage"),
            ]
            records, failures = project_successful_groups(
                accepted, Path(temporary) / "projection-quarantine.jsonl"
            )
            self.assertEqual(len(records), 1)
            self.assertEqual(records[0]["kind"], "report")
            self.assertEqual(len(failures), 1)


if __name__ == "__main__":
    unittest.main()
