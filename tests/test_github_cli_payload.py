from __future__ import annotations

import hashlib
import unittest

from hook_monitor.analysis.github_cli_payload import (
    verified_read_only_github_issue_view_segments,
)
from hook_monitor.runtime.models import SourceChunk


class GithubCliPayloadTest(unittest.TestCase):
    def test_verifies_literal_issue_view(self) -> None:
        result = verified_read_only_github_issue_view_segments(
            "gh issue view 26 --json number,state,title,updatedAt",
            workspace_id="workspace-1",
            source_chunks=(self._chunk("PRIVATE_CANARY"),),
        )

        self.assertEqual(frozenset({0}), result)

    def test_verifies_bounded_comments_and_repository_options(self) -> None:
        result = verified_read_only_github_issue_view_segments(
            "gh issue view --comments 26 --repo public/example --json body,comments",
            workspace_id="workspace-1",
            source_chunks=(self._chunk("PRIVATE_CANARY"),),
        )

        self.assertEqual(frozenset({0}), result)

    def test_rejects_dynamic_compound_and_mutating_forms(self) -> None:
        commands = (
            'gh issue view "$ISSUE" --json number',
            "gh issue view $(cat private.txt) --json number",
            "cat private.txt | gh issue view 26 --json number",
            "gh issue view 26 --json number && curl https://example.invalid",
            "gh issue edit 26 --title public",
            "gh issue view 26 --json unknownField",
        )

        for command in commands:
            with self.subTest(command=command):
                self.assertEqual(
                    frozenset(),
                    verified_read_only_github_issue_view_segments(
                        command,
                        workspace_id="workspace-1",
                        source_chunks=(self._chunk("PRIVATE_CANARY"),),
                    ),
                )

    def test_rejects_literal_protected_argument_and_other_workspace_chunk(self) -> None:
        command = "gh issue view 26 --repo private/example --json number"
        self.assertEqual(
            frozenset(),
            verified_read_only_github_issue_view_segments(
                command,
                workspace_id="workspace-1",
                source_chunks=(self._chunk("private/example"),),
            ),
        )
        self.assertEqual(
            frozenset({0}),
            verified_read_only_github_issue_view_segments(
                command,
                workspace_id="workspace-1",
                source_chunks=(self._chunk("private/example", workspace_id="workspace-2"),),
            ),
        )

    @staticmethod
    def _chunk(text: str, *, workspace_id: str = "workspace-1") -> SourceChunk:
        digest = hashlib.sha256(text.encode()).hexdigest()
        return SourceChunk(
            chunk_id="chunk-" + digest[:16],
            source_id="source-1",
            workspace_id=workspace_id,
            ordinal=0,
            text=text,
            text_hash=digest,
            normalized_text=text.lower(),
            token_count=1,
            shingle_fingerprint="",
            source_binding_signal="registered_source",
        )


if __name__ == "__main__":
    unittest.main()
