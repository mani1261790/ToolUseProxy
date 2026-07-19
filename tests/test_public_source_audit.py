from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[1]
AUDITOR = REPO_ROOT / "scripts" / "audit_public_source.py"
AUDITOR_SPEC = importlib.util.spec_from_file_location("audit_public_source", AUDITOR)
assert AUDITOR_SPEC is not None and AUDITOR_SPEC.loader is not None
AUDITOR_MODULE = importlib.util.module_from_spec(AUDITOR_SPEC)
AUDITOR_SPEC.loader.exec_module(AUDITOR_MODULE)


def _run(repo: Path, *, require_clean: bool = False) -> subprocess.CompletedProcess[str]:
    command = [sys.executable, str(AUDITOR), "--repo", str(repo)]
    if require_clean:
        command.append("--require-clean")
    return subprocess.run(
        command,
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )


def _git(repo: Path, *arguments: str) -> None:
    subprocess.run(
        ["git", *arguments],
        cwd=repo,
        check=True,
        capture_output=True,
    )


def _repository(root: Path) -> Path:
    root.mkdir()
    _git(root, "init", "--quiet")
    _git(root, "config", "user.name", "Public Audit Test")
    _git(root, "config", "user.email", "audit@example.invalid")
    (root / "README.md").write_text("safe public source\n", encoding="utf-8")
    _git(root, "add", "README.md")
    _git(root, "commit", "--quiet", "-m", "safe initial commit")
    return root


class PublicSourceAuditTest(unittest.TestCase):
    def test_current_repository_is_aggregate_only_and_passes(self) -> None:
        result = _run(REPO_ROOT)
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual("passed", payload["status"])
        self.assertTrue(payload["report_publishable"])
        self.assertFalse(payload["raw_value_exposure"])
        self.assertEqual(0, payload["finding_count"])
        self.assertGreater(payload["history"]["commit_count"], 0)
        self.assertGreater(payload["history"]["unique_blob_count"], 0)

    def test_deleted_history_credential_fails_without_exposure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            repo = _repository(Path(temporary_directory) / "repo")
            credential = "ghp_" + "A" * 36
            secret_path = repo / "temporary.txt"
            secret_path.write_text(f"TOKEN={credential}\n", encoding="utf-8")
            _git(repo, "add", "temporary.txt")
            _git(repo, "commit", "--quiet", "-m", "temporary historical content")
            secret_commit = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=repo,
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            secret_path.unlink()
            _git(repo, "add", "-u")
            _git(repo, "commit", "--quiet", "-m", "remove historical content")

            result = _run(repo)

            self.assertEqual(1, result.returncode)
            self.assertNotIn(credential, result.stdout + result.stderr)
            self.assertNotIn("temporary.txt", result.stdout + result.stderr)
            self.assertNotIn(secret_commit, result.stdout + result.stderr)
            payload = json.loads(result.stdout)
            self.assertEqual("failed", payload["status"])
            self.assertGreater(payload["finding_counts"]["github_token"], 0)

    def test_forbidden_content_classes_fail_closed(self) -> None:
        cases = {
            "forbidden-path": (".env", b"SAFE=value\n", "forbidden_path"),
            "binary": ("binary.dat", b"safe\x00binary", "binary_blob"),
            "oversized": ("large.txt", b"a" * (2 * 1024 * 1024 + 1), "oversized_blob"),
            "private-key": (
                "notes.txt",
                ("-----BEGIN " + "PRIVATE KEY-----\n").encode(),
                "private_key",
            ),
        }
        for label, (filename, content, category) in cases.items():
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary_directory:
                repo = _repository(Path(temporary_directory) / "repo")
                (repo / filename).write_bytes(content)
                _git(repo, "add", filename)
                _git(repo, "commit", "--quiet", "-m", "add audit case")
                result = _run(repo)
                self.assertEqual(1, result.returncode)
                payload = json.loads(result.stdout)
                self.assertGreater(payload["finding_counts"][category], 0)
                self.assertNotIn(filename, result.stdout + result.stderr)

    def test_public_binary_and_absolute_path_are_bounded_observations(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            repo = _repository(Path(temporary_directory) / "repo")
            private_path = "/Users/" + "privateperson" + "/project\n"
            (repo / "notes.txt").write_text(private_path, encoding="utf-8")
            (repo / "public.pdf").write_bytes(b"%PDF-1.4\n%\x80\x81\n")
            _git(repo, "add", "notes.txt", "public.pdf")
            _git(repo, "commit", "--quiet", "-m", "add bounded public artifacts")
            result = _run(repo)
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)
            self.assertNotIn(private_path.strip(), result.stdout + result.stderr)
            payload = json.loads(result.stdout)
            self.assertGreater(
                payload["observation_counts"]["private_absolute_path"],
                0,
            )
            self.assertGreater(payload["observation_counts"]["allowed_binary_blob"], 0)

    def test_commit_message_and_dirty_worktree_are_covered(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            repo = _repository(Path(temporary_directory) / "repo")
            credential = "sk-" + "B" * 32
            (repo / "safe.txt").write_text("safe\n", encoding="utf-8")
            _git(repo, "add", "safe.txt")
            _git(repo, "commit", "--quiet", "-m", f"message {credential}")
            result = _run(repo)
            self.assertEqual(1, result.returncode)
            self.assertNotIn(credential, result.stdout + result.stderr)
            self.assertGreater(json.loads(result.stdout)["finding_counts"]["openai_key"], 0)

            (repo / "README.md").write_text("changed\n", encoding="utf-8")
            dirty = _run(repo, require_clean=True)
            self.assertEqual(1, dirty.returncode)
            self.assertEqual("worktree_dirty", json.loads(dirty.stdout)["error_code"])

    def test_known_synthetic_credential_is_explicitly_ignored(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            repo = _repository(Path(temporary_directory) / "repo")
            synthetic = "AKIA" + "1234567890ABCDEF"
            (repo / "synthetic.txt").write_text(synthetic, encoding="utf-8")
            _git(repo, "add", "synthetic.txt")
            _git(repo, "commit", "--quiet", "-m", "add known synthetic fixture")
            result = _run(repo)
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)
            payload = json.loads(result.stdout)
            self.assertGreater(payload["known_synthetic_ignored_count"], 0)

    def test_non_utf8_git_output_fails_with_fixed_error_code(self) -> None:
        with mock.patch.object(AUDITOR_MODULE, "_git_bytes", return_value=b"\xff"):
            with self.assertRaisesRegex(
                AUDITOR_MODULE.PublicSourceAuditError,
                "^git_output_not_utf8$",
            ):
                AUDITOR_MODULE._git(REPO_ROOT, "status")


if __name__ == "__main__":
    unittest.main()
