import unittest
from datetime import UTC, datetime
from types import SimpleNamespace

from native_sci_shim import completed, identity, projection_rows, validate_references


def record(role, digest, document, family="report"):
    binding = SimpleNamespace(product_repo_id="anchor", run_id="run", role=role)
    native = SimpleNamespace(binding=binding, binding_id=digest, artifact_digest=digest)
    return (
        {"artifact": family, "source_file": digest + ".json"},
        native,
        document,
        "s3://bucket/" + digest,
    )


class NativeJobTests(unittest.TestCase):
    def test_current_snapshot_selected_without_merging_findings(self):
        audit = {"metadata": {"date": "2026-05-01"}, "findings": [{"id": "OLD"}]}
        current = {"metadata": {"date": "2026-06-01"}, "findings": [{"id": "NEW"}]}
        rows = projection_rows(
            [record(None, "baseline", audit), record("cumulative", "current", current)]
        )
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["document"], current)

    def test_current_filename_resolves_missing_role(self):
        baseline = {"metadata": {"date": "2026-05-01"}, "findings": [{"id": "F1"}]}
        current = {"metadata": {"date": "2026-06-01"}, "findings": [{"id": "F1"}]}
        first = record(None, "baseline", baseline)
        first[0]["source_file"] = "findings/product/repo/repo-security-audit.json"
        second = record(None, "current", current)
        second[0]["source_file"] = "findings/product/repo/repo-findings-current.json"
        self.assertEqual(projection_rows([first, second])[0]["path"], second[0]["source_file"])

    def test_legacy_source_reference_keeps_exact_old_baseline(self):
        baseline = {"metadata": {"date": "2026-05-01"}, "findings": [{"id": "F1"}]}
        current = {"metadata": {"date": "2026-06-01"}, "findings": [{"id": "F1"}]}
        triage = {
            "triage_completed": "2026-05-02",
            "findings": [{"id": "T1", "source": "repo-security-audit.json#F1"}],
        }
        first = record(None, "baseline", baseline)
        first[0]["source_file"] = "findings/product/repo/repo-security-audit.json"
        second = record(None, "current", current)
        second[0]["source_file"] = "findings/product/repo/repo-findings-current.json"
        child = record(None, "triage", triage, "triage")
        child[0]["source_file"] = "findings/product/repo/repo-triage.json"
        rows = projection_rows([first, second, child])
        self.assertEqual(len(rows), 3)
        self.assertEqual(rows[-1]["scan_id"], identity("native-scan", "baseline"))
        self.assertEqual(rows[0]["path"], second[0]["source_file"])
        self.assertNotIn("orig_id", triage["findings"][0])
        with self.assertRaises(ValueError):
            validate_references(
                baseline,
                {"findings": [{"source": "different.json#F1"}]},
                first[0]["source_file"],
                child[0]["source_file"],
            )

    def test_competing_current_roots_not_guessed(self):
        d = {"metadata": {"date": "2026-05-01"}, "findings": []}
        with self.assertRaises(ValueError):
            projection_rows([record("cumulative", "first", d), record("cumulative", "second", d)])

    def test_triage_cannot_attach_to_different_current_ids(self):
        parent = {"findings": [{"id": "NEW"}]}
        child = {"findings": [{"id": "T1", "orig_id": "OLD"}]}
        with self.assertRaises(ValueError):
            validate_references(parent, child)
        validate_references(parent, {"findings": [{"id": "T1", "orig_id": "NEW"}]})

    def test_explicit_id_does_not_bypass_source_path_evidence(self):
        parent = {"findings": [{"id": "F1"}]}
        child = {"findings": [{"id": "T1", "orig_id": "F1", "source": "other.json#F1"}]}
        with self.assertRaises(ValueError):
            validate_references(parent, child)
        with self.assertRaises(ValueError):
            validate_references(
                parent, child, "findings/repo/audit.json", "findings/repo/triage.json"
            )

    def test_date_only_convention_and_occurrence_stability(self):
        self.assertEqual(
            completed({"metadata": {"date": "2026-05-01"}}, "report"),
            datetime(2026, 5, 1, tzinfo=UTC),
        )
        self.assertEqual(identity("scan", "binding"), identity("scan", "binding"))
        self.assertNotEqual(identity("scan", "binding"), identity("scan", "different"))


if __name__ == "__main__":
    unittest.main()
