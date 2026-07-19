from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
BUILDER = REPO_ROOT / "scripts" / "build_release_candidate.py"


def _run(*arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(BUILDER), *arguments],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )


class ReleaseCandidateTest(unittest.TestCase):
    def test_candidate_is_reproducible_complete_and_self_verifying(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            first = root / "first"
            second = root / "second"
            first_result = _run("--outdir", str(first))
            second_result = _run("--outdir", str(second))
            self.assertEqual(0, first_result.returncode, first_result.stderr)
            self.assertEqual(0, second_result.returncode, second_result.stderr)

            first_files = {path.name: path.read_bytes() for path in first.iterdir()}
            second_files = {path.name: path.read_bytes() for path in second.iterdir()}
            self.assertEqual(first_files, second_files)
            self.assertEqual(7, len(first_files))

            manifest = json.loads(first_files["release-manifest.json"])
            self.assertEqual(1, manifest["schema_version"])
            self.assertEqual("candidate", manifest["status"])
            self.assertEqual(3, len(manifest["artifacts"]))
            license_present = (REPO_ROOT / "LICENSE").is_file()
            self.assertEqual(license_present, manifest["gates"]["license_present"])
            self.assertEqual(
                license_present and not manifest["source"]["dirty"],
                manifest["gates"]["artifact_set_eligible"],
            )
            self.assertNotIn(str(REPO_ROOT), first_files["release-manifest.json"].decode())

            checksum_lines = first_files["SHA256SUMS"].decode("ascii").splitlines()
            checksums = {line[66:]: line[:64] for line in checksum_lines}
            self.assertEqual(set(first_files) - {"SHA256SUMS"}, set(checksums))
            for filename, expected in checksums.items():
                self.assertEqual(expected, hashlib.sha256(first_files[filename]).hexdigest())

            sbom_name = manifest["sbom"]["filename"]
            sbom = json.loads(first_files[sbom_name])
            self.assertEqual("CycloneDX", sbom["bomFormat"])
            self.assertEqual("1.7", sbom["specVersion"])
            self.assertEqual(3, len(sbom["components"]))

            verified = _run("--verify", str(first))
            self.assertEqual(0, verified.returncode, verified.stderr)
            verified_payload = json.loads(verified.stdout)
            self.assertEqual("verified", verified_payload["status"])
            self.assertEqual(3, verified_payload["artifact_count"])
            self.assertEqual(6, verified_payload["checked_file_count"])

    def test_verifier_rejects_tampering_and_unexpected_files(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            candidate = Path(temporary_directory) / "candidate"
            built = _run("--outdir", str(candidate))
            self.assertEqual(0, built.returncode, built.stderr)
            artifact = next(candidate.glob("*.whl"))
            artifact.write_bytes(artifact.read_bytes() + b"tampered")
            rejected = _run("--verify", str(candidate))
            self.assertEqual(1, rejected.returncode)
            self.assertIn("checksum mismatch", rejected.stderr)

            artifact.write_bytes(artifact.read_bytes()[:-8])
            (candidate / "unexpected.txt").write_text("unexpected\n", encoding="utf-8")
            rejected = _run("--verify", str(candidate))
            self.assertEqual(1, rejected.returncode)
            self.assertIn("missing or unexpected", rejected.stderr)


if __name__ == "__main__":
    unittest.main()
