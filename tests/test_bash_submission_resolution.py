from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from hook_monitor.analysis.bash_submission import extract_bash_http_submissions
from hook_monitor.analysis.bash_submission_resolution import (
    BASH_SUBMISSION_RESOLVER_VERSION,
    MAX_BASH_SUBMISSION_FILE_REFERENCES,
    MAX_BASH_SUBMISSION_PATH_BYTES,
    component_safe_file_resolution_supported,
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

        self.assertEqual(
            "bash-submission-resolver-v3-fail-closed-data-binary-file",
            BASH_SUBMISSION_RESOLVER_VERSION,
        )
        self.assertEqual(("public",), resolved[0].submitted_values)
        self.assertEqual("static_values", resolved[0].extraction)
        self.assertEqual("evaluated", resolved[0].status)
        self.assertEqual(
            ("public",),
            extract_bash_http_submissions(command)[0].submitted_values,
        )

    def test_relative_file_body_is_resolved_without_executing_curl(self) -> None:
        self._require_component_safe()
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
        self._require_component_safe()
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
        self._require_component_safe()
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

    def test_common_non_payload_options_do_not_disable_file_resolution(self) -> None:
        self._require_component_safe()
        with tempfile.TemporaryDirectory() as temporary_directory:
            workspace = Path(temporary_directory)
            (workspace / "payload.txt").write_text("public", encoding="utf-8")
            commands = (
                "curl --max-time 1 --data-binary @payload.txt https://example.invalid",
                "curl --max-time=1 --data-binary @payload.txt https://example.invalid",
                "curl -m1 --data-binary @payload.txt https://example.invalid",
                "curl -H 'Content-Type: text/plain' --data-binary @payload.txt "
                "https://example.invalid",
                "curl --data-binary @payload.txt --retry 2 https://example.invalid",
            )
            for command in commands:
                with self.subTest(command=command):
                    resolved = resolve_bash_http_submissions(
                        command,
                        workspace_root=workspace,
                        execution_cwd=workspace,
                    )
                    self.assertEqual("evaluated", resolved[0].status)
                    self.assertEqual(("public",), resolved[0].submitted_values)

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
                    if component_safe_file_resolution_supported()
                    else "component_safe_open_unavailable"
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
        self._require_component_safe()
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

    def test_symlinked_parent_directory_is_rejected(self) -> None:
        if not component_safe_file_resolution_supported():
            self.skipTest("component-safe open is unavailable")
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            workspace = root / "workspace"
            outside = root / "outside"
            workspace.mkdir()
            outside.mkdir()
            (outside / "payload.txt").write_text(
                "outside payload",
                encoding="utf-8",
            )
            try:
                (workspace / "linked").symlink_to(
                    outside,
                    target_is_directory=True,
                )
            except OSError:
                self.skipTest("symlink creation is unavailable")

            resolved = resolve_bash_http_submissions(
                "curl --data-binary @linked/payload.txt https://example.invalid",
                workspace_root=workspace,
                execution_cwd=workspace,
            )

        self.assertIn(
            resolved[0].unsupported_reason,
            {
                "file_reference_symlink",
                "file_reference_parent_not_directory",
            },
        )

    def test_parent_path_swap_cannot_redirect_open_outside_workspace(self) -> None:
        if not component_safe_file_resolution_supported():
            self.skipTest("component-safe open is unavailable")
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            workspace = root / "workspace"
            nested = workspace / "nested"
            outside = root / "outside"
            workspace.mkdir()
            nested.mkdir()
            outside.mkdir()
            (nested / "payload.txt").write_text(
                "inside snapshot",
                encoding="utf-8",
            )
            (outside / "payload.txt").write_text(
                "outside payload",
                encoding="utf-8",
            )
            original_open = os.open
            swapped = False

            def swapping_open(
                path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
                flags: int,
                mode: int = 0o777,
                *,
                dir_fd: int | None = None,
            ) -> int:
                nonlocal swapped
                if path == "payload.txt" and dir_fd is not None and not swapped:
                    swapped = True
                    nested.rename(workspace / "nested-original")
                    nested.symlink_to(outside, target_is_directory=True)
                return original_open(path, flags, mode, dir_fd=dir_fd)

            with mock.patch(
                "hook_monitor.analysis.bash_submission_resolution.os.open",
                side_effect=swapping_open,
            ):
                resolved = resolve_bash_http_submissions(
                    "curl --data-binary @nested/payload.txt "
                    "https://example.invalid",
                    workspace_root=workspace,
                    execution_cwd=workspace,
                )

        self.assertTrue(swapped)
        self.assertEqual("evaluated", resolved[0].status)
        self.assertEqual(("inside snapshot",), resolved[0].submitted_values)

    def test_file_reference_count_is_bounded_across_one_command(self) -> None:
        self._require_component_safe()
        with tempfile.TemporaryDirectory() as temporary_directory:
            workspace = Path(temporary_directory)
            (workspace / "payload.txt").write_text("payload", encoding="utf-8")
            operands = " ".join(
                "--data-binary @payload.txt"
                for _ in range(MAX_BASH_SUBMISSION_FILE_REFERENCES + 1)
            )

            resolved = resolve_bash_http_submissions(
                f"curl {operands} https://example.invalid",
                workspace_root=workspace,
                execution_cwd=workspace,
            )

        self.assertEqual(
            "file_reference_limit_exceeded",
            resolved[0].unsupported_reason,
        )

    def test_size_encoding_nul_and_path_limits_are_rejected(self) -> None:
        self._require_component_safe()
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

    def test_non_positive_time_budget_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            workspace = Path(temporary_directory)
            with self.assertRaisesRegex(ValueError, "time_budget_ms"):
                resolve_bash_http_submissions(
                    "curl --data-binary @payload.txt https://example.invalid",
                    workspace_root=workspace,
                    execution_cwd=workspace,
                    time_budget_ms=0,
                )

    def _require_component_safe(self) -> None:
        if not component_safe_file_resolution_supported():
            self.skipTest("component-safe open is unavailable")


if __name__ == "__main__":
    unittest.main()
