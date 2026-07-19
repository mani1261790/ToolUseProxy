from __future__ import annotations

import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
CHECKER = REPO_ROOT / "scripts" / "check_ci_supply_chain.py"
CHECKOUT_SHA = "9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0"


def _run(workflow_root: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(CHECKER), "--workflow-root", str(workflow_root)],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )


def _workflow(*, uses: str, persist_credentials: bool = True) -> str:
    persist = "\n        with:\n          persist-credentials: false" if persist_credentials else ""
    return textwrap.dedent(
        f'''\
        name: test
        "on":
          pull_request:
        permissions:
          contents: read
        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              - name: Checkout
                uses: {uses}{persist}
        '''
    )


class CiSupplyChainContractTest(unittest.TestCase):
    def test_repository_workflows_pass(self) -> None:
        result = _run(REPO_ROOT / ".github" / "workflows")
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn('"status": "passed"', result.stdout)
        self.assertIn('"checkout_credentials_persisted": false', result.stdout)

    def test_mutable_or_unapproved_actions_fail_closed(self) -> None:
        cases = {
            "mutable": ("actions/checkout@v7", "full commit SHA"),
            "unapproved": (f"example/unreviewed@{CHECKOUT_SHA} # v1", "not approved"),
        }
        for label, (uses, message) in cases.items():
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary_directory:
                root = Path(temporary_directory)
                (root / "ci.yml").write_text(_workflow(uses=uses), encoding="utf-8")
                result = _run(root)
                self.assertEqual(1, result.returncode)
                self.assertIn(message, result.stderr)

    def test_job_level_remote_workflow_cannot_bypass_action_validation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            content = _workflow(uses=f"actions/checkout@{CHECKOUT_SHA} # v7")
            content += textwrap.dedent(
                '''\
                reusable:
                  uses: example/unreviewed/.github/workflows/ci.yml@main
                '''
            )
            (root / "ci.yml").write_text(content, encoding="utf-8")
            result = _run(root)
            self.assertEqual(1, result.returncode)
            self.assertIn("full commit SHA", result.stderr)

    def test_multiple_workflow_files_are_checked_independently(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            content = _workflow(uses=f"actions/checkout@{CHECKOUT_SHA} # v7")
            (root / "ci.yml").write_text(content, encoding="utf-8")
            (root / "release.yml").write_text(content, encoding="utf-8")
            result = _run(root)
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertIn('"workflow_count": 2', result.stdout)

    def test_checkout_credentials_and_workflow_authority_fail_closed(self) -> None:
        cases = {
            "credentials": (
                _workflow(uses=f"actions/checkout@{CHECKOUT_SHA} # v7", persist_credentials=False),
                "disable credential persistence",
            ),
            "trigger": (
                _workflow(uses=f"actions/checkout@{CHECKOUT_SHA} # v7").replace(
                    "pull_request:", "pull_request_target:"
                ),
                "pull_request_target is forbidden",
            ),
            "permissions": (
                _workflow(uses=f"actions/checkout@{CHECKOUT_SHA} # v7").replace(
                    "contents: read", "contents: write"
                ),
                "contents: read only",
            ),
        }
        for label, (content, message) in cases.items():
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary_directory:
                root = Path(temporary_directory)
                (root / "ci.yml").write_text(content, encoding="utf-8")
                result = _run(root)
                self.assertEqual(1, result.returncode)
                self.assertIn(message, result.stderr)


if __name__ == "__main__":
    unittest.main()
