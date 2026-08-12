from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
RUNNER = REPO_ROOT / "scripts" / "dogfood_externality.py"
SYNTHETIC_CANARY = "EXTERNALITY.DOGFOOD.CANARY.5F2A8C1D"


class ExternalityDogfoodTest(unittest.TestCase):
    def test_clean_artifact_externality_contract_is_value_free(self) -> None:
        result = subprocess.run(
            [sys.executable, str(RUNNER)],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertNotIn(SYNTHETIC_CANARY, result.stdout + result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual("passed", report["status"])
        self.assertTrue(all(report["checks"].values()))
        self.assertEqual(0, report["metrics"]["external_side_effect_count"])
        self.assertEqual(0, report["metrics"]["automatic_rule_promotion_count"])
        self.assertLessEqual(
            report["metrics"]["hook_latency_ms"]["p95"],
            report["metrics"]["hook_p95_budget_ms"],
        )


if __name__ == "__main__":
    unittest.main()
