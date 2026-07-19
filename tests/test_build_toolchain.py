from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
CHECKER = REPO_ROOT / "scripts" / "check_build_toolchain.py"
LOCK = REPO_ROOT / "requirements" / "build.txt"
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"


def _run(lock: Path, *, skip_environment: bool = False) -> subprocess.CompletedProcess[str]:
    command = [sys.executable, str(CHECKER), "--lock", str(lock)]
    if skip_environment:
        command.append("--skip-environment")
    return subprocess.run(
        command,
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )


def _without_lock_entry(content: str, package: str) -> str:
    lines = content.splitlines(keepends=True)
    for index, line in enumerate(lines):
        if line.startswith(f"{package}=="):
            return "".join((*lines[:index], *lines[index + 2 :]))
    raise AssertionError(f"missing lock fixture package: {package}")


class BuildToolchainContractTest(unittest.TestCase):
    def test_repository_lock_matches_environment(self) -> None:
        result = _run(LOCK)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn('"package_count": 5', result.stdout)
        self.assertIn('"environment_checked": true', result.stdout)

    def test_lock_requires_exact_complete_hashes(self) -> None:
        original = LOCK.read_text(encoding="ascii")
        cases = {
            "missing": _without_lock_entry(original, "wheel"),
            "mutable": original.replace("build==1.2.1", "build>=1.2.1"),
            "bad-hash": original.replace(
                "75e10f767a433d9a86e50d83f418e83efc18ede923ee5ff7df93b6cb0306c5d4",
                "not-a-sha256",
            ),
        }
        for label, content in cases.items():
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary_directory:
                lock = Path(temporary_directory) / "build.txt"
                lock.write_text(content, encoding="ascii")
                result = _run(lock, skip_environment=True)
                self.assertEqual(1, result.returncode)

    def test_installed_version_mismatch_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            lock = Path(temporary_directory) / "build.txt"
            lock.write_text(
                LOCK.read_text(encoding="ascii").replace("build==1.2.1", "build==9.9.9"),
                encoding="ascii",
            )
            result = _run(lock)
            self.assertEqual(1, result.returncode)
            self.assertIn("does not match lock", result.stderr)

    def test_ci_installs_the_lock_without_upgrading_pip(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertEqual(3, workflow.count("--require-hashes"))
        self.assertEqual(3, workflow.count("--only-binary=:all:"))
        self.assertNotIn("pip install --upgrade", workflow)
        self.assertEqual(3, workflow.count("python scripts/check_build_toolchain.py"))


if __name__ == "__main__":
    unittest.main()
