from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from hook_monitor.analysis.bash_submission import extract_bash_http_submissions
from hook_monitor.analysis.bash_submission_resolution import (
    BASH_SUBMISSION_RESOLVER_VERSION,
    MAX_BASH_SUBMISSION_PATH_BYTES,
    resolve_bash_http_submissions,
)


class BashSubmissionResolutionTest(unittest.TestCase):
    def test_static_submission_preserves_existing_projection(self) -> None:
        command = "curl -X POST https://example.invalid --data-binary 'public'"
        with tempfile.TemporaryDirectory() as temporary_directory:
            workspace = Path(temporary_directory)
            resolved = resolve_bash_http_submissions(
                command,
                workspace_root=workspace,
                execution_cwd=workspace,
            )

        self.assertEqual("bash-submission-resolver-v1-data-binary-file", BASH_SUBMISSION_RESOLVER_VERSION)
        self.assertEqual(("public",), resolved[0].submitted_values)
        self.assertEqual("static_values", resolved[0].extraction)
        self.assertEqual("evaluated", resolved[0].status)
        self.assertEqual(
            ("public",),
            extract_bash_http_submissions(command)[0].submitted_values,
        )

    def test_relative_file_body_is_resolved_without_executing_curl(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            workspace = Path(temporary_directory)
            payload = workspace / "payload.txt"
            payload.write_text("synthetic protected payload\n", encoding="utf-8")

            resolved = resolve_bash_http_submissions(
                "curl --data-binary @payload.txt https://example.invalid",
                workspace_root=workspace,
                execution_cwd=workspace,
            )

        self.assertEqual(1, len(resolved))
        self.assertEqual("evaluated", resolved[0].status)
        self.assertEqual("resolved_file", resolved[0].extraction)
        self.assertEqual(
            ("synthetic protected payload\n",),
            resolved[0].submitted_values,
        )
        self.assertNotIn("synthetic", repr(resolved[0]))

    def test_equals_form_and_nested_execution_cwd_are_supported(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            workspace = Path(temporary_directory)
            nested = workspace / "nested"
            nested.mkdir()
            (nested / "payload.txt").write_text("nested payload", encoding="utf-8")

            resolved = resolve_bash_http_submissions(
                "curl --data-binary=@payload.txt https://example.invalid",
                workspace_root=workspace,
                execution_cwd=nested,
            )

        self.assertEqual(("nested payload",), resolved[0].submitted_values)

    def test_file_and_inline_data_binary_values_can_share_one_segment(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            workspace = Path(temporary_directory)
            (workspace / "payload.txt").write_text("file payload", encoding="utf-8")

            resolved = resolve_bash_http_submissions(
                "curl --data-binary inline --data-binary @payload.txt "
                "https://example.invalid",
                workspace_root=workspace,
                execution_cwd=workspace,
            )

        self.assertEqual(("inline", "file payload"), resolved[0].submitted_values)
        self.assertEqual("resolved_file", resolved[0].extraction)

    def test_unsupported_references_return_value_free_reasons(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            workspace = Path(temporary_directory)
            outside = workspace.parent / "outside-payload.txt"
            outside.write_text("outside secret", encoding="utf-8")
            cases = {
                "curl --data-binary @../outside-payload.txt https://example.invalid": (
                    "file_reference_outside_workspace"
                ),
                "curl --data-binary @missing.txt https://example.invalid": (
                    "file_reference_missing"
                ),
                "curl --data-binary @- https://example.invalid": (
                    "stdin_file_reference"
                ),
                "curl --data @payload.txt https://example.invalid": (
                    "unsupported_curl_option"
                ),
            }
            for command, expected_reason in cases.items():
                with self.subTest(command=command):
                    resolved = resolve_bash_http_submissions(
                        command,
                        workspace_root=workspace,
                        execution_cwd=workspace,
                    )
                    self.assertEqual("unsupported", resolved[0].status)
                    self.assertEqual(expected_reason, resolved[0].unsupported_reason)
                    self.assertEqual((), resolved[0].submitted_values)
                    self.assertNotIn("outside secret", repr(resolved[0]))

    def test_symlink_and_non_regular_file_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            workspace = Path(temporary_directory)
            target = workspace / "target.txt"
            target.write_text("target payload", encoding="utf-8")
            link = workspace / "link.txt"
            try:
                link.symlink_to(target)
            except OSError:
                self.skipTest("symlink creation is unavailable")

            symlink_result = resolve_bash_http_submissions(
                "curl --data-binary @link.txt https://example.invalid",
                workspace_root=workspace,
                execution_cwd=workspace,
            )
            self.assertEqual(
                "file_reference_symlink",
                symlink_result[0].unsupported_reason,
            )

            if hasattr(os, "mkfifo"):
                fifo = workspace / "payload.fifo"
                os.mkfifo(fifo)
                fifo_result = resolve_bash_http_submissions(
                    "curl --data-binary @payload.fifo https://example.invalid",
                    workspace_root=workspace,
                    execution_cwd=workspace,
                )
                self.assertEqual(
                    "file_reference_not_regular",
                    fifo_result[0].unsupported_reason,
                )

    def test_size_encoding_nul_and_path_limits_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            workspace = Path(temporary_directory)
            (workspace / "large.txt").write_bytes(b"x" * (32 * 1024 + 1))
            (workspace / "binary.txt").write_bytes(b"\xff\xfe")
            (workspace / "nul.txt").write_bytes(b"before\x00after")
            cases = {
                "large.txt": "resolved_payload_limit_exceeded",
                "binary.txt": "resolved_payload_not_utf8",
                "nul.txt": "resolved_payload_not_text",
            }
            for filename, expected_reason in cases.items():
                with self.subTest(filename=filename):
                    resolved = resolve_bash_http_submissions(
                        f"curl --data-binary @{filename} https://example.invalid",
                        workspace_root=workspace,
                        execution_cwd=workspace,
                    )
                    self.assertEqual(expected_reason, resolved[0].unsupported_reason)

            long_reference = "x" * (MAX_BASH_SUBMISSION_PATH_BYTES + 1)
            long_result = resolve_bash_http_submissions(
                f"curl --data-binary @{long_reference} https://example.invalid",
                workspace_root=workspace,
                execution_cwd=workspace,
            )
            self.assertEqual(
                "invalid_file_reference",
                long_result[0].unsupported_reason,
            )

    def test_execution_cwd_outside_workspace_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            workspace = root / "workspace"
            outside = root / "outside"
            workspace.mkdir()
            outside.mkdir()

            resolved = resolve_bash_http_submissions(
                "curl --data-binary @payload.txt https://example.invalid",
                workspace_root=workspace,
                execution_cwd=outside,
            )

        self.assertEqual(
            "execution_cwd_outside_workspace",
            resolved[0].unsupported_reason,
        )


if __name__ == "__main__":
    unittest.main()
