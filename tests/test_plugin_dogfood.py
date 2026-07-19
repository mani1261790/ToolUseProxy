from __future__ import annotations

import json
import shutil
import subprocess
import sys
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
DOGFOOD_RUNNER = REPO_ROOT / "scripts" / "dogfood_plugin.py"
SYNTHETIC_CANARY = "DOGFOOD.CANARY.7E91A4C2B8D6"


class PluginDogfoodTest(unittest.TestCase):
    def test_extracted_artifact_lifecycle_is_value_free(self) -> None:
        result = subprocess.run(
            [sys.executable, str(DOGFOOD_RUNNER), "--installation-mode", "extracted"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertNotIn(SYNTHETIC_CANARY, result.stdout + result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual("passed", payload["status"])
        self.assertEqual(2, payload["schema_version"])
        self.assertEqual("manual_required_not_bypassed", payload["trust_review"])
        self.assertTrue(
            all(
                value
                for name, value in payload["checks"].items()
                if name != "raw_value_exposure"
            )
        )
        self.assertFalse(payload["checks"]["raw_value_exposure"])
        self.assertTrue(payload["checks"]["candidate_rejected"])
        self.assertTrue(payload["checks"]["candidate_ignored"])
        self.assertTrue(payload["checks"]["stale_source_rejected"])
        self.assertTrue(payload["checks"]["candidate_approved"])
        self.assertTrue(payload["checks"]["negative_reviews_suppressed"])
        self.assertEqual(0, payload["metrics"]["external_side_effect_count"])
        self.assertEqual(4, payload["metrics"]["proposal_review_count"])
        self.assertEqual(
            {"bounded_scan": 1, "explicit_suggestion": 3},
            payload["metrics"]["proposal_discovery_counts"],
        )
        self.assertEqual(
            {"approve": 1, "ignore": 1, "reject": 1},
            payload["metrics"]["explicit_decision_counts"],
        )
        self.assertEqual(1, payload["metrics"]["stale_proposal_rejection_count"])
        self.assertLess(payload["metrics"]["time_to_first_block_ms"], 300_000)

    @unittest.skipUnless(
        shutil.which("codex"),
        "Codex CLI is required for isolated marketplace lifecycle dogfood",
    )
    def test_isolated_codex_remove_preserves_then_explicitly_deletes_data(self) -> None:
        result = subprocess.run(
            [sys.executable, str(DOGFOOD_RUNNER), "--installation-mode", "codex"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertNotIn(SYNTHETIC_CANARY, result.stdout + result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual("passed", payload["status"])
        self.assertEqual(2, payload["schema_version"])
        self.assertEqual("codex", payload["installation_mode"])
        self.assertTrue(payload["checks"]["candidate_rejected"])
        self.assertTrue(payload["checks"]["candidate_ignored"])
        self.assertTrue(payload["checks"]["stale_source_rejected"])
        self.assertTrue(payload["checks"]["candidate_approved"])
        self.assertTrue(payload["checks"]["negative_reviews_suppressed"])
        self.assertTrue(payload["checks"]["plugin_code_removed"])
        self.assertTrue(payload["checks"]["runtime_data_retained"])
        self.assertTrue(
            payload["checks"]["runtime_data_deleted_after_confirmation"]
        )


if __name__ == "__main__":
    unittest.main()
