"""Baseline bookkeeping in cross_validate_vuln_findings: an audit file or a core audit id."""

import pytest

from traust_engine.reporting import validate as V

KNOWN_ERROR = "known_findings recorded but metadata.baseline is null"
COUNT_ERROR = "metadata.baseline_findings > 0 but metadata.baseline is null"


def report(baseline, additional):
    return {
        "findings": [],
        "known_findings": [{"title": "SQL injection", "matches_baseline_id": "X-abc1234-001"}],
        "summary": {
            "total": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "informational": 0,
            "known": 1,
            "low_confidence": 0,
        },
        "metadata": {
            "repo_slug": "X",
            "scanned_ref": "abc1234",
            "baseline": baseline,
            "baseline_findings": 3,
            **({"additional": additional} if additional is not None else {}),
        },
    }


@pytest.mark.parametrize(
    ("baseline", "additional", "expected"),
    [
        ("findings/x/x-security-audit.json", None, set()),
        (None, {"baseline_assessment_id": "0b5c2f9e-3f0d-4c65-9a51-2f1b7c0d9e11"}, set()),
        (None, None, {KNOWN_ERROR, COUNT_ERROR}),
        (None, {"baseline_assessment_id": None}, {KNOWN_ERROR, COUNT_ERROR}),
    ],
    ids=["audit-file", "core-audit-id", "neither", "null-core-id"],
)
def test_a_baseline_is_an_audit_file_or_a_core_audit_id(baseline, additional, expected):
    result = V.ValidationResult("x-vuln-findings.json")
    V.cross_validate_vuln_findings(report(baseline, additional), result)
    baseline_errors = [e for e in result.errors if "baseline is null" in e]
    assert {
        m for m in (KNOWN_ERROR, COUNT_ERROR) if any(m in e for e in baseline_errors)
    } == expected
    assert len(baseline_errors) == len(expected)
