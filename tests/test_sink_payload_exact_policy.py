from __future__ import annotations

import unittest

from hook_monitor.analysis.sink_payload_evidence import (
    BashSinkPayloadEvidence,
    SinkPayloadSourceMatch,
)
from hook_monitor.policy.sink_payload_exact import (
    EXACT_FILE_PAYLOAD_POLICY_VERSION,
    build_exact_file_payload_decisions,
    build_unresolved_external_payload_decisions,
    build_unverified_external_sink_decisions,
)
from hook_monitor.policy.codex_output import render_codex_hook_output
from hook_monitor.runtime.models import SinkCandidate


class SinkPayloadExactPolicyTest(unittest.TestCase):
    def test_builds_block_for_resolved_exact_substring(self) -> None:
        decisions = build_exact_file_payload_decisions(
            (self._evidence(),),
            sink_candidates=(self._sink(),),
            analysis_run_id="analysis-1",
        )

        self.assertEqual(1, len(decisions))
        decision = decisions[0]
        self.assertEqual("block", decision.action)
        self.assertEqual("critical", decision.severity)
        self.assertEqual("PreToolUse", decision.hook_event)
        self.assertEqual("external_http_request", decision.sink_type)
        self.assertEqual("source-chunk-1", decision.source_node_id)
        self.assertEqual(1.0, decision.path_score)
        self.assertEqual("resolved_file_exact", decision.evidence_kind)

        output = render_codex_hook_output(decision, "PreToolUse")
        message = output["hookSpecificOutput"]["permissionDecisionReason"]
        self.assertIn("ToolUseProxyが外部送信を実行前に止めました", message)
        self.assertIn("外部操作は実行されていません", message)
        self.assertIn("保護対象の内容も表示していません", message)
        self.assertIn("技術情報（通常は読む必要なし）", message)
        self.assertNotIn("Protected source content", message)
        self.assertNotIn("Source:", message)
        self.assertNotIn("Score:", message)

    def test_fail_closed_blocks_unsupported_evidence_with_protected_sources(
        self,
    ) -> None:
        unsupported = self._evidence(
            resolution_status="unsupported",
            comparison_status="not_run",
            extraction="coarse_fallback",
            snapshot_semantics="unresolved",
            matches=(),
            resolution_reason="unsupported_curl_option",
        )

        decisions = build_exact_file_payload_decisions(
            (unsupported,),
            sink_candidates=(self._sink(),),
            analysis_run_id="analysis-1",
            protected_source_node_ids=("source-chunk-1",),
        )

        self.assertEqual(1, len(decisions))
        decision = decisions[0]
        self.assertEqual("block", decision.action)
        self.assertEqual("unresolved_external_payload", decision.evidence_kind)
        self.assertEqual("protected_source_scope", decision.source_node_kind)
        self.assertIn("unsupported_curl_option", decision.reason)

        output = render_codex_hook_output(decision, "PreToolUse")
        message = output["hookSpecificOutput"]["permissionDecisionReason"]
        self.assertIn("送信内容を安全に確認しきれなかった", message)
        self.assertNotIn("unsupported_curl_option", message)

    def test_unresolved_evidence_without_protected_sources_does_not_block(self) -> None:
        unsupported = self._evidence(
            resolution_status="unsupported",
            comparison_status="not_run",
            extraction="coarse_fallback",
            snapshot_semantics="unresolved",
            matches=(),
            resolution_reason="unsupported_curl_option",
        )

        decisions = build_exact_file_payload_decisions(
            (unsupported,),
            sink_candidates=(self._sink(),),
            analysis_run_id="analysis-1",
        )

        self.assertEqual([], decisions)

    def test_evaluated_non_file_payload_does_not_block_without_a_match(self) -> None:
        static = self._evidence(
            extraction="static_values",
            snapshot_semantics="tool_input_literal",
            matches=(),
        )

        decisions = build_exact_file_payload_decisions(
            (static,),
            sink_candidates=(self._sink(),),
            analysis_run_id="analysis-1",
            protected_source_node_ids=("source-chunk-1",),
        )

        self.assertEqual([], decisions)

    def test_inspection_error_blocks_each_current_curl_sink(self) -> None:
        sink = self._sink(metadata={"matched_program": "curl", "segment_index": 3})

        decisions = build_unresolved_external_payload_decisions(
            sink_candidates=(sink,),
            analysis_run_id="analysis-1",
            protected_source_node_ids=("source-chunk-1",),
            reason="payload_inspection_error",
        )

        self.assertEqual(1, len(decisions))
        self.assertEqual("block", decisions[0].action)
        self.assertIn("payload_inspection_error", decisions[0].reason)

    def test_unverified_non_curl_external_sink_fails_closed(self) -> None:
        sink = self._sink(
            metadata={"matched_program": "python", "segment_index": 0}
        )

        decisions = build_unverified_external_sink_decisions(
            sink_candidates=(sink,),
            analysis_run_id="analysis-1",
            protected_source_node_ids=("source-chunk-1",),
            verified_sink_node_ids=frozenset(),
        )

        self.assertEqual(1, len(decisions))
        self.assertEqual("block", decisions[0].action)
        self.assertIn(
            "external_payload_verification_unavailable",
            decisions[0].reason,
        )

    def test_verified_external_sink_is_not_blocked_as_unresolved(self) -> None:
        sink = self._sink(metadata={"matched_program": "curl"})

        decisions = build_unverified_external_sink_decisions(
            sink_candidates=(sink,),
            analysis_run_id="analysis-1",
            protected_source_node_ids=("source-chunk-1",),
            verified_sink_node_ids=frozenset({"sink-1"}),
        )

        self.assertEqual([], decisions)

    def test_requires_matching_external_http_sink(self) -> None:
        wrong_sink = self._sink(sink_type="external_git_publish")

        decisions = build_exact_file_payload_decisions(
            (self._evidence(),),
            sink_candidates=(wrong_sink,),
            analysis_run_id="analysis-1",
        )

        self.assertEqual([], decisions)

    def test_identity_is_stable_and_versioned(self) -> None:
        first = build_exact_file_payload_decisions(
            (self._evidence(),),
            sink_candidates=(self._sink(),),
            analysis_run_id="analysis-1",
        )[0]
        second = build_exact_file_payload_decisions(
            (self._evidence(),),
            sink_candidates=(self._sink(),),
            analysis_run_id="analysis-1",
        )[0]

        self.assertEqual(first, second)
        self.assertIn("v3", EXACT_FILE_PAYLOAD_POLICY_VERSION)

    @staticmethod
    def _evidence(
        *,
        resolution_status: str = "evaluated",
        comparison_status: str = "evaluated",
        extraction: str = "resolved_file",
        snapshot_semantics: str = "pre_execution_file_snapshot",
        matches: tuple[SinkPayloadSourceMatch, ...] | None = None,
        resolution_reason: str | None = None,
        comparison_reason: str | None = None,
    ) -> BashSinkPayloadEvidence:
        if matches is None:
            matches = (
                SinkPayloadSourceMatch(
                    source_node_kind="source_chunk",
                    source_node_id="source-chunk-1",
                    evidence_level="content_lexical",
                    method="resolved_payload_exact_substring",
                    score=0.75,
                ),
            )
        return BashSinkPayloadEvidence(
            workspace_id="workspace-1",
            sink_node_id="sink-1",
            segment_index=0,
            resolution_status=resolution_status,  # type: ignore[arg-type]
            comparison_status=comparison_status,  # type: ignore[arg-type]
            extraction=extraction,  # type: ignore[arg-type]
            snapshot_semantics=snapshot_semantics,  # type: ignore[arg-type]
            resolver_version="resolver-v1",
            evidence_version="evidence-v1",
            submitted_value_count=1,
            submitted_bytes=32,
            matches=matches,
            resolution_reason=resolution_reason,
            comparison_reason=comparison_reason,
            inspection_duration_ms=1.0,
        )

    @staticmethod
    def _sink(
        *,
        sink_type: str = "external_http_request",
        metadata: dict[str, object] | None = None,
    ) -> SinkCandidate:
        return SinkCandidate(
            node_id="sink-1",
            sink_type=sink_type,
            label="curl request",
            tool_name="Bash",
            tool_use_id="tool-1",
            session_id="session-1",
            sequence_no=1,
            metadata={} if metadata is None else metadata,
            workspace_id="workspace-1",
        )


if __name__ == "__main__":
    unittest.main()
