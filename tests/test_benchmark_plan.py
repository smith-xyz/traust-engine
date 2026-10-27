"""Benchmark worklists carry claims, not validity answers."""

import json
from types import SimpleNamespace

from traust_engine.sweep.benchmark import cmd_plan


def test_plan_leaves_claim_validity_unanswered(tmp_path):
    bench = tmp_path / "benchmark"
    bench.mkdir()
    (bench / "expected.json").write_text(
        json.dumps(
            {
                "namespace": "validation-benchmark",
                "fixtures": [
                    {
                        "id": "BENCH-001",
                        "claim": {
                            "title": "A proposed RBAC exposure",
                            "severity": "high",
                            "cvss": 8.0,
                            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
                            "cwes": ["CWE-269"],
                            "category": "authorization",
                        },
                        "probe_class": "rbac",
                        "controls_hint": "Compare the vulnerable fixture with its safe twin.",
                        "vuln_manifest": "rbac.vuln.yaml",
                    }
                ],
            }
        )
    )
    output = tmp_path / "results"

    cmd_plan(SimpleNamespace(benchmark_dir=bench), results_dir=output)

    [claim] = json.loads((output / "benchmark-findings.json").read_text())["findings"]
    assert "validation_status" not in claim
