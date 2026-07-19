from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
DEMO = REPO_ROOT / "scripts" / "demo_plugin.py"
DOGFOOD_CANARY = "DOGFOOD.CANARY.7E91A4C2B8D6"


class PluginDemoTest(unittest.TestCase):
    def test_demo_finishes_within_budget_and_is_value_free(self) -> None:
        result = subprocess.run(
            [sys.executable, str(DEMO), "--json"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=False,
            timeout=35,
        )

        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertNotIn(DOGFOOD_CANARY, result.stdout + result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual("passed", payload["status"])
        self.assertEqual("automated_phase_a_preview", payload["demo_kind"])
        self.assertLessEqual(payload["elapsed_ms"], payload["limit_ms"])
        self.assertEqual(0, payload["checks"]["external_side_effect_count"])
        self.assertFalse(payload["checks"]["raw_value_exposure"])
        self.assertEqual(
            "not_included_run_manual_phase_b",
            payload["manual_trust_evidence"],
        )


if __name__ == "__main__":
    unittest.main()
