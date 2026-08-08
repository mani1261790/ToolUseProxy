from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
REHEARSAL = REPO_ROOT / "scripts" / "rehearse_plugin_lifecycle.py"
RELEASE_BUILDER = REPO_ROOT / "scripts" / "build_release_candidate.py"
SYNTHETIC_MARKER = "LIFECYCLE.CANARY.8B4E2D91"


class PluginLifecycleRehearsalTest(unittest.TestCase):
    def test_immutable_baseline_to_candidate_upgrade_and_rollback(self) -> None:
        self._assert_rehearsal("extracted")

    def test_existing_verified_candidate_can_be_rehearsed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            candidate = Path(temporary_directory) / "candidate"
            built = subprocess.run(
                [
                    sys.executable,
                    str(RELEASE_BUILDER),
                    "--outdir",
                    str(candidate),
                ],
                cwd=REPO_ROOT,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(0, built.returncode, built.stdout + built.stderr)
            self._assert_rehearsal("extracted", candidate=candidate)

    @unittest.skipUnless(
        shutil.which("codex"),
        "Codex CLI is required for isolated marketplace lifecycle rehearsal",
    )
    def test_isolated_codex_upgrade_and_rollback(self) -> None:
        self._assert_rehearsal("codex")

    def _assert_rehearsal(self, mode: str, *, candidate: Path | None = None) -> None:
        command = [sys.executable, str(REHEARSAL), "--installation-mode", mode]
        if candidate is not None:
            command.extend(("--candidate", str(candidate)))
        result = subprocess.run(
            command,
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertNotIn(SYNTHETIC_MARKER, result.stdout + result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual("passed", payload["status"])
        self.assertEqual(mode, payload["installation_mode"])
        self.assertEqual("0.1.0-alpha.1", payload["baseline"]["plugin_version"])
        self.assertEqual("0.1.0-alpha.4", payload["candidate"]["plugin_version"])
        self.assertTrue(
            all(
                value
                for name, value in payload["checks"].items()
                if name != "raw_value_exposure"
            )
        )
        self.assertFalse(payload["checks"]["raw_value_exposure"])
        self.assertEqual(0, payload["metrics"]["external_side_effect_count"])
        self.assertEqual("manual_required_not_bypassed", payload["trust_review"])


if __name__ == "__main__":
    unittest.main()
