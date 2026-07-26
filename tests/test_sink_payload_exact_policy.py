from __future__ import annotations

import unittest

from hook_monitor.analysis.sink_payload_evidence import (
    BashSinkPayloadEvidence,
    SinkPayloadSourceMatch,
)
from hook_monitor.policy.sink_payload_exact import (
    EXACT_FILE_PAYLOAD_POLICY_VERSION,
    build_exact_file_payload_decisions,
)
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

    def test_rejects_unsupported_or_non_file_evidence(self) -> None:
        unsupported = self._evidence(
            resolution_status="unsupported",
            comparison_status="not_run",
            extraction="coarse_fallback",
            snapshot_semantics="unresolved",
            matches=(),
        )
        static = self._evidence(
            extraction="static_values",
            snapshot_semantics="tool_input_literal",
        )

        decisions = build_exact_file_payload_decisions(
            (unsupported, static),
            sink_candidates=(self._sink(),),
            analysis_run_id="analysis-1",
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
        self.assertIn("v1", EXACT_FILE_PAYLOAD_POLICY_VERSION)

    @staticmethod
    def _evidence(
        *,
        resolution_status: str = "evaluated",
        comparison_status: str = "evaluated",
        extraction: str = "resolved_file",
        snapshot_semantics: str = "pre_execution_file_snapshot",
        matches: tuple[SinkPayloadSourceMatch, ...] | None = None,
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
            resolution_reason=None,
            comparison_reason=None,
            inspection_duration_ms=1.0,
        )

    @staticmethod
    def _sink(
        *,
        sink_type: str = "external_http_request",
    ) -> SinkCandidate:
        return SinkCandidate(
            node_id="sink-1",
            sink_type=sink_type,
            label="curl request",
            tool_name="Bash",
            tool_use_id="tool-1",
            session_id="session-1",
            sequence_no=1,
            metadata={},
            workspace_id="workspace-1",
        )


if __name__ == "__main__":
    unittest.main()
