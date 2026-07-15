from __future__ import annotations

import hashlib
import json
import math
import time
import unittest
from dataclasses import asdict, replace
from pathlib import Path
from unittest.mock import patch

from hook_monitor.analysis.adapters.mcp import McpAdapter
from hook_monitor.analysis.adapters.mcp_profiles import (
    DEFAULT_MCP_PROFILE_REGISTRY,
    TOOLUSEPROXY_E2E_PUBLISH_TEXT_PROFILE,
    McpFieldSpec,
    McpInputLimits,
    McpProfileRegistry,
    McpToolProfile,
    escape_json_pointer_segment,
)
from hook_monitor.analysis.leak_detection import LeakFinding
from hook_monitor.policy.redaction_preview import (
    REPLACEMENT_TEXT,
    RedactionPreviewLimits,
    plan_mcp_redaction_preview,
)
from hook_monitor.runtime.models import (
    AnalysisRun,
    ArtifactContext,
    NormalizedEvent,
    SinkCandidate,
    SourceChunk,
)
from hook_monitor.runtime.parser import build_artifacts, build_fragments


SECRET = "private-alpha-7f30"
SECOND_SECRET = "private-beta-2c91"
SEQUENCE_NO = 7


MULTI_FIELD_PROFILE = McpToolProfile(
    profile_id="fixture/publish_bundle",
    server="fixture",
    tool="publish_bundle",
    sink_type="external_api_call",
    fields=(
        McpFieldSpec("/destination", "string", "control", required=True),
        McpFieldSpec(
            "/message",
            "string",
            "data",
            required=True,
            redactable=True,
        ),
        McpFieldSpec(
            "/attachment_text",
            "string",
            "data",
            required=True,
            redactable=True,
        ),
    ),
    post_input_stable=True,
)
MULTI_FIELD_REGISTRY = McpProfileRegistry((MULTI_FIELD_PROFILE,))


def _event(
    tool_input: object,
    *,
    tool_name: str = "mcp__tooluseproxy_e2e__publish_text",
    event_id: str = "event-1",
    workspace_id: str | None = "workspace-a",
    session_id: str | None = "session-a",
    tool_use_id: str | None = "tool-use-a",
    phase: str = "pre_tool_use",
    workspace_status: str = "ready",
) -> NormalizedEvent:
    return NormalizedEvent(
        event_id=event_id,
        phase=phase,
        session_id=session_id,
        turn_id="turn-a",
        tool_use_id=tool_use_id,
        tool_name=tool_name,
        cwd="/workspace",
        model=None,
        permission_mode=None,
        transcript_path=None,
        stop_hook_active=None,
        workspace_id=workspace_id,
        workspace_root="/workspace",
        workspace_lexical_root="/workspace",
        workspace_execution_cwd="/workspace",
        workspace_status=workspace_status,
        workspace_source="test",
        workspace_namespace_id="namespace-a",
        raw_payload={"tool_input": tool_input},
    )


def _analysis_run(event: NormalizedEvent, *, run_id: str = "run-a") -> AnalysisRun:
    return AnalysisRun(
        analysis_run_id=run_id,
        detector_version="test-detector",
        config_json="{}",
        started_at="2026-07-15T00:00:00Z",
        completed_at="2026-07-15T00:00:01Z",
        workspace_id=event.workspace_id,
        session_id=event.session_id,
    )


def _sinks(
    event: NormalizedEvent,
    profile: McpToolProfile,
    registry: McpProfileRegistry,
    *,
    sequence_no: int = SEQUENCE_NO,
) -> tuple[SinkCandidate, ...]:
    tool_input = event.raw_payload["tool_input"]
    assert isinstance(tool_input, dict)
    sinks: list[SinkCandidate] = []
    for key in tool_input:
        pointer = f"/{escape_json_pointer_segment(key)}"
        field = profile.field_for_pointer(pointer)
        sinks.append(
            SinkCandidate(
                node_id=f"sink:{pointer}",
                sink_type=profile.sink_type,
                label="external fixture sink",
                tool_name=event.tool_name,
                tool_use_id=event.tool_use_id,
                session_id=event.session_id,
                sequence_no=sequence_no,
                workspace_id=event.workspace_id,
                metadata={
                    "adapter": "mcp",
                    "event_id": event.event_id,
                    "server": profile.server,
                    "tool": profile.tool,
                    "argument_fragment_id": f"fragment:{pointer}",
                    "argument_fragment_kind": "payload",
                    "argument_json_pointer": pointer,
                    "argument_relative_json_pointer": pointer,
                    "argument_field_class": (
                        field.field_class if field is not None else "unclassified"
                    ),
                    "argument_redactable": (
                        field.redactable if field is not None else False
                    ),
                    "profile_id": profile.profile_id,
                    "profile_version": profile.profile_version,
                    "profile_registry_version": registry.registry_version,
                    "profile_status": "matched",
                    "profile_rejection_code": "",
                    "profile_preview_eligible": profile.preview_eligible,
                    "call_shape": "real_codex",
                    "matched_rule": "test",
                },
            )
        )
    return tuple(sinks)


def _source(
    text: str,
    *,
    chunk_id: str = "source-a:0",
    workspace_id: str | None = "workspace-a",
) -> SourceChunk:
    return SourceChunk(
        chunk_id=chunk_id,
        source_id=chunk_id.split(":", 1)[0],
        ordinal=0,
        text=text,
        normalized_text=text.lower(),
        text_hash=hashlib.sha256(text.encode("utf-8")).hexdigest(),
        shingle_fingerprint="[]",
        token_count=1,
        workspace_id=workspace_id,
    )


def _finding(
    analysis_run: AnalysisRun,
    sink: SinkCandidate,
    source: SourceChunk,
    *,
    finding_id: str = "finding-a",
    source_node_kind: str = "source_chunk",
    severity: str = "critical",
    sink_type: str | None = None,
    reason: str = "test finding",
) -> LeakFinding:
    resolved_sink_type = sink_type or sink.sink_type
    return LeakFinding(
        finding_id=finding_id,
        analysis_run_id=analysis_run.analysis_run_id,
        source_node_kind=source_node_kind,
        source_node_id=source.chunk_id,
        sink_node_id=sink.node_id,
        sink_type=resolved_sink_type,
        sink_label=sink.label,
        severity=severity,
        path_score=1.0,
        hop_count=2,
        predecessor_edge_id="edge-a",
        reason=reason,
    )


def _source_map(
    event: NormalizedEvent,
    *sources: SourceChunk,
) -> dict[tuple[str, str], SourceChunk]:
    assert event.workspace_id is not None
    return {
        (event.workspace_id, source.chunk_id): source
        for source in sources
    }


def _many_target_fixture(
    count: int,
) -> tuple[
    NormalizedEvent,
    AnalysisRun,
    tuple[SinkCandidate, ...],
    tuple[SourceChunk, ...],
    tuple[LeakFinding, ...],
    McpProfileRegistry,
]:
    fields = tuple(
        McpFieldSpec(
            f"/field_{index:02d}",
            "string",
            "data",
            required=True,
            redactable=True,
        )
        for index in range(count)
    )
    profile = McpToolProfile(
        profile_id=f"fixture/many-{count}",
        server="fixture",
        tool=f"many_{count}",
        sink_type="external_api_call",
        fields=fields,
        post_input_stable=True,
    )
    registry = McpProfileRegistry((profile,))
    arguments = {
        f"field_{index:02d}": f"private-value-{index:02d}"
        for index in range(count)
    }
    event = _event(
        arguments,
        tool_name=f"mcp__fixture__many_{count}",
    )
    run = _analysis_run(event)
    sinks = _sinks(event, profile, registry)
    sources = tuple(
        _source(
            f"private-value-{index:02d}",
            chunk_id=f"source-{index:02d}:0",
        )
        for index in range(count)
    )
    findings = tuple(
        _finding(
            run,
            sinks[index],
            sources[index],
            finding_id=f"finding-{index:02d}",
        )
        for index in range(count)
    )
    return event, run, sinks, sources, findings, registry


def _max_envelope_fixture() -> tuple[
    NormalizedEvent,
    AnalysisRun,
    tuple[SinkCandidate, ...],
    tuple[SourceChunk, ...],
    tuple[LeakFinding, ...],
    McpProfileRegistry,
]:
    target_fields = tuple(
        McpFieldSpec(
            f"/target_{index:02d}",
            "string",
            "data",
            required=True,
            redactable=True,
        )
        for index in range(16)
    )
    public_fields = tuple(
        McpFieldSpec(
            f"/public_{index:02d}",
            "string",
            "data",
            required=True,
        )
        for index in range(16)
    )
    profile = McpToolProfile(
        profile_id="fixture/max-envelope",
        server="fixture",
        tool="max_envelope",
        sink_type="external_api_call",
        fields=target_fields + public_fields,
        post_input_stable=True,
    )
    registry = McpProfileRegistry((profile,))
    arguments = {
        **{
            f"target_{index:02d}": f"protected-value-{index:02d}"
            for index in range(16)
        },
        **{f"public_{index:02d}": "" for index in range(16)},
    }
    initial_size = len(
        json.dumps(
            arguments,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    )
    arguments["public_00"] = "x" * (32 * 1024 - initial_size)
    event = _event(
        arguments,
        tool_name="mcp__fixture__max_envelope",
    )
    run = _analysis_run(event)
    sinks = _sinks(event, profile, registry)
    sources = tuple(
        _source(
            f"protected-value-{index:02d}",
            chunk_id=f"max-source-{index:02d}:0",
        )
        for index in range(16)
    )
    findings = tuple(
        _finding(
            run,
            sinks[index],
            sources[index],
            finding_id=f"max-finding-{index:02d}",
        )
        for index in range(16)
    )
    return event, run, sinks, sources, findings, registry


def _adapter_sinks(
    event: NormalizedEvent,
    registry: McpProfileRegistry,
) -> tuple[SinkCandidate, ...]:
    artifacts = build_artifacts(event)
    fragments = build_fragments(artifacts)
    role_by_artifact = {artifact.artifact_id: artifact.role for artifact in artifacts}
    contexts = [
        ArtifactContext(
            fragment=fragment,
            artifact_role=role_by_artifact[fragment.artifact_id],
            event_id=event.event_id,
            phase=event.phase,
            session_id=event.session_id,
            turn_id=event.turn_id,
            tool_use_id=event.tool_use_id,
            tool_name=event.tool_name,
            cwd=event.cwd,
            sequence_no=SEQUENCE_NO,
            workspace_id=event.workspace_id,
            workspace_root=event.workspace_root,
            workspace_lexical_root=event.workspace_lexical_root,
            workspace_execution_cwd=event.workspace_execution_cwd,
            workspace_status=event.workspace_status,
        )
        for fragment in fragments
    ]
    return McpAdapter(registry).analyze(contexts, Path("/workspace")).sinks


class _Clock:
    def __init__(self, values: list[int]) -> None:
        self._values = iter(values)
        self._last = values[-1]

    def __call__(self) -> int:
        try:
            self._last = next(self._values)
        except StopIteration:
            pass
        return self._last


class RedactionPreviewHappyPathTest(unittest.TestCase):
    def test_exact_raw_substring_builds_hash_only_whole_field_plan(self) -> None:
        original = {"content": f"prefix {SECRET} suffix"}
        event = _event(original)
        run = _analysis_run(event)
        sinks = _sinks(
            event,
            TOOLUSEPROXY_E2E_PUBLISH_TEXT_PROFILE,
            DEFAULT_MCP_PROFILE_REGISTRY,
        )
        source = _source(SECRET)
        finding = _finding(
            run,
            replace(sinks[0], label=f"sink label {SECRET}"),
            source,
            reason=f"reason {SECRET}",
        )

        result = plan_mcp_redaction_preview(
            current_event=event,
            current_sequence_no=SEQUENCE_NO,
            analysis_run=run,
            current_sinks=sinks,
            current_critical_findings=(finding,),
            source_chunks=_source_map(event, source),
        )

        self.assertEqual("eligible", result.disposition)
        assert result.plan is not None
        self.assertEqual("eligible", result.plan.status)
        self.assertEqual(1, result.plan.replacement_count)
        self.assertEqual(1, result.plan.critical_finding_count)
        self.assertEqual("/content", result.plan.targets[0].json_pointer)
        self.assertEqual(
            hashlib.sha256(original["content"].encode("utf-8")).hexdigest(),
            result.plan.targets[0].original_value_sha256,
        )
        self.assertEqual(
            result.plan.structure_sha256_before,
            result.plan.structure_sha256_after,
        )
        self.assertEqual({"content": REPLACEMENT_TEXT}, result.materialize_rewritten_input())
        self.assertEqual({"content": f"prefix {SECRET} suffix"}, original)
        self.assertNotIn(SECRET, repr(result))
        self.assertNotIn(SECRET, json.dumps(asdict(result.plan)))

        materialized = result.materialize_rewritten_input()
        assert materialized is not None
        materialized["content"] = "mutated"
        self.assertEqual({"content": REPLACEMENT_TEXT}, result.materialize_rewritten_input())

    def test_public_call_without_critical_finding_is_not_applicable(self) -> None:
        event = _event({"content": "public"})
        result = plan_mcp_redaction_preview(
            current_event=event,
            current_sequence_no=SEQUENCE_NO,
            analysis_run=_analysis_run(event),
            current_sinks=(),
            current_critical_findings=(),
            source_chunks={},
        )

        self.assertEqual("not_applicable", result.disposition)
        self.assertIsNone(result.plan)
        self.assertIsNone(result.materialize_rewritten_input())

    def test_multiple_findings_for_one_pointer_keep_all_audit_targets(self) -> None:
        event = _event({"content": f"{SECRET} and {SECOND_SECRET}"})
        run = _analysis_run(event)
        sinks = _sinks(
            event,
            TOOLUSEPROXY_E2E_PUBLISH_TEXT_PROFILE,
            DEFAULT_MCP_PROFILE_REGISTRY,
        )
        first = _source(SECRET)
        second = _source(SECOND_SECRET, chunk_id="source-b:0")
        findings = (
            _finding(run, sinks[0], second, finding_id="finding-b"),
            _finding(run, sinks[0], first, finding_id="finding-a"),
        )

        result = plan_mcp_redaction_preview(
            current_event=event,
            current_sequence_no=SEQUENCE_NO,
            analysis_run=run,
            current_sinks=sinks,
            current_critical_findings=findings,
            source_chunks=_source_map(event, first, second),
        )

        assert result.plan is not None
        self.assertEqual("eligible", result.disposition)
        self.assertEqual(1, result.plan.replacement_count)
        self.assertEqual(2, len(result.plan.targets))
        self.assertEqual(
            ["finding-a", "finding-b"],
            [target.finding_id for target in result.plan.targets],
        )

    def test_multi_field_profile_preserves_public_data_and_control(self) -> None:
        original = {
            "destination": "channel-1",
            "message": "public body",
            "attachment_text": f"attachment {SECRET}",
        }
        event = _event(
            original,
            tool_name="mcp__fixture__publish_bundle",
        )
        run = _analysis_run(event)
        sinks = _sinks(event, MULTI_FIELD_PROFILE, MULTI_FIELD_REGISTRY)
        source = _source(SECRET)
        attachment_sink = next(
            sink
            for sink in sinks
            if sink.metadata["argument_json_pointer"] == "/attachment_text"
        )

        result = plan_mcp_redaction_preview(
            current_event=event,
            current_sequence_no=SEQUENCE_NO,
            analysis_run=run,
            current_sinks=sinks,
            current_critical_findings=(_finding(run, attachment_sink, source),),
            source_chunks=_source_map(event, source),
            profile_registry=MULTI_FIELD_REGISTRY,
        )

        self.assertEqual(
            {
                "destination": "channel-1",
                "message": "public body",
                "attachment_text": REPLACEMENT_TEXT,
            },
            result.materialize_rewritten_input(),
        )
        self.assertEqual(
            {
                "destination": "channel-1",
                "message": "public body",
                "attachment_text": f"attachment {SECRET}",
            },
            original,
        )

    def test_real_adapter_metadata_drives_default_and_multi_field_plans(self) -> None:
        cases = (
            (
                _event({"content": SECRET}),
                DEFAULT_MCP_PROFILE_REGISTRY,
                "/content",
                {"content": REPLACEMENT_TEXT},
            ),
            (
                _event(
                    {
                        "destination": "channel-1",
                        "message": "public body",
                        "attachment_text": SECRET,
                    },
                    tool_name="mcp__fixture__publish_bundle",
                ),
                MULTI_FIELD_REGISTRY,
                "/attachment_text",
                {
                    "destination": "channel-1",
                    "message": "public body",
                    "attachment_text": REPLACEMENT_TEXT,
                },
            ),
        )
        for event, registry, target_pointer, expected in cases:
            with self.subTest(tool_name=event.tool_name):
                run = _analysis_run(event)
                sinks = _adapter_sinks(event, registry)
                sink = next(
                    candidate
                    for candidate in sinks
                    if candidate.metadata["argument_json_pointer"] == target_pointer
                )
                source = _source(SECRET)
                result = plan_mcp_redaction_preview(
                    current_event=event,
                    current_sequence_no=SEQUENCE_NO,
                    analysis_run=run,
                    current_sinks=sinks,
                    current_critical_findings=(_finding(run, sink, source),),
                    source_chunks=_source_map(event, source),
                    profile_registry=registry,
                )

                self.assertEqual("eligible", result.disposition)
                self.assertEqual(expected, result.materialize_rewritten_input())


class RedactionPreviewAllOrNothingTest(unittest.TestCase):
    def test_input_contract_rejects_noncritical_finding(self) -> None:
        event = _event({"content": SECRET})
        run = _analysis_run(event)
        sinks = _sinks(
            event,
            TOOLUSEPROXY_E2E_PUBLISH_TEXT_PROFILE,
            DEFAULT_MCP_PROFILE_REGISTRY,
        )
        source = _source(SECRET)
        result = plan_mcp_redaction_preview(
            current_event=event,
            current_sequence_no=SEQUENCE_NO,
            analysis_run=run,
            current_sinks=sinks,
            current_critical_findings=(
                _finding(run, sinks[0], source, severity="high"),
            ),
            source_chunks=_source_map(event, source),
        )

        assert result.plan is not None
        self.assertEqual("critical_policy_mismatch", result.plan.rejection_code)

    def test_one_control_finding_rejects_supported_target_without_partial_plan(self) -> None:
        event = _event(
            {
                "destination": SECOND_SECRET,
                "message": SECRET,
                "attachment_text": "public attachment",
            },
            tool_name="mcp__fixture__publish_bundle",
        )
        run = _analysis_run(event)
        sinks = _sinks(event, MULTI_FIELD_PROFILE, MULTI_FIELD_REGISTRY)
        by_pointer = {
            sink.metadata["argument_json_pointer"]: sink for sink in sinks
        }
        first = _source(SECRET)
        second = _source(SECOND_SECRET, chunk_id="source-b:0")

        result = plan_mcp_redaction_preview(
            current_event=event,
            current_sequence_no=SEQUENCE_NO,
            analysis_run=run,
            current_sinks=sinks,
            current_critical_findings=(
                _finding(run, by_pointer["/message"], first, finding_id="supported"),
                _finding(
                    run,
                    by_pointer["/destination"],
                    second,
                    finding_id="unsupported",
                ),
            ),
            source_chunks=_source_map(event, first, second),
            profile_registry=MULTI_FIELD_REGISTRY,
        )

        self.assertEqual("rejected", result.disposition)
        assert result.plan is not None
        self.assertEqual("target_not_redactable", result.plan.rejection_code)
        self.assertEqual((), result.plan.targets)
        self.assertEqual(0, result.plan.replacement_count)
        self.assertIsNone(result.rewritten_input_json)
        self.assertIsNone(result.materialize_rewritten_input())

    def test_finding_and_input_order_do_not_change_plan(self) -> None:
        first_input = {
            "destination": "channel-1",
            "message": SECRET,
            "attachment_text": SECOND_SECRET,
        }
        second_input = {
            "attachment_text": SECOND_SECRET,
            "message": SECRET,
            "destination": "channel-1",
        }
        first_event = _event(first_input)
        first_event = replace(
            first_event,
            tool_name="mcp__fixture__publish_bundle",
            raw_payload={"tool_input": first_input},
        )
        second_event = replace(first_event, raw_payload={"tool_input": second_input})
        run = _analysis_run(first_event)
        first_sinks = _sinks(first_event, MULTI_FIELD_PROFILE, MULTI_FIELD_REGISTRY)
        second_sinks = _sinks(second_event, MULTI_FIELD_PROFILE, MULTI_FIELD_REGISTRY)
        first_by_pointer = {
            sink.metadata["argument_json_pointer"]: sink for sink in first_sinks
        }
        second_by_pointer = {
            sink.metadata["argument_json_pointer"]: sink for sink in second_sinks
        }
        source_a = _source(SECRET)
        source_b = _source(SECOND_SECRET, chunk_id="source-b:0")
        first_findings = (
            _finding(run, first_by_pointer["/message"], source_a, finding_id="a"),
            _finding(
                run,
                first_by_pointer["/attachment_text"],
                source_b,
                finding_id="b",
            ),
        )
        second_findings = (
            _finding(
                run,
                second_by_pointer["/attachment_text"],
                source_b,
                finding_id="b",
            ),
            _finding(run, second_by_pointer["/message"], source_a, finding_id="a"),
        )

        first = plan_mcp_redaction_preview(
            current_event=first_event,
            current_sequence_no=SEQUENCE_NO,
            analysis_run=run,
            current_sinks=first_sinks,
            current_critical_findings=first_findings,
            source_chunks=_source_map(first_event, source_a, source_b),
            profile_registry=MULTI_FIELD_REGISTRY,
        )
        second = plan_mcp_redaction_preview(
            current_event=second_event,
            current_sequence_no=SEQUENCE_NO,
            analysis_run=run,
            current_sinks=tuple(reversed(second_sinks)),
            current_critical_findings=second_findings,
            source_chunks=_source_map(second_event, source_b, source_a),
            profile_registry=MULTI_FIELD_REGISTRY,
        )

        assert first.plan is not None and second.plan is not None
        self.assertEqual(first.plan, second.plan)
        self.assertEqual(first.rewritten_input_json, second.rewritten_input_json)

    def test_fresh_analysis_run_gets_a_distinct_plan_identity(self) -> None:
        event = _event({"content": SECRET})
        first_run = _analysis_run(event, run_id="run-a")
        second_run = _analysis_run(event, run_id="run-b")
        sinks = _sinks(
            event,
            TOOLUSEPROXY_E2E_PUBLISH_TEXT_PROFILE,
            DEFAULT_MCP_PROFILE_REGISTRY,
        )
        source = _source(SECRET)
        first = plan_mcp_redaction_preview(
            current_event=event,
            current_sequence_no=SEQUENCE_NO,
            analysis_run=first_run,
            current_sinks=sinks,
            current_critical_findings=(
                _finding(first_run, sinks[0], source, finding_id="finding-run-a"),
            ),
            source_chunks=_source_map(event, source),
        )
        second = plan_mcp_redaction_preview(
            current_event=event,
            current_sequence_no=SEQUENCE_NO,
            analysis_run=second_run,
            current_sinks=sinks,
            current_critical_findings=(
                _finding(second_run, sinks[0], source, finding_id="finding-run-b"),
            ),
            source_chunks=_source_map(event, source),
        )

        assert first.plan is not None and second.plan is not None
        self.assertNotEqual(first.plan.plan_id, second.plan.plan_id)
        self.assertEqual(
            first.plan.original_input_sha256,
            second.plan.original_input_sha256,
        )


class RedactionPreviewProfileAndCoverageTest(unittest.TestCase):
    def _default_fixture(self) -> tuple[
        NormalizedEvent,
        AnalysisRun,
        tuple[SinkCandidate, ...],
        SourceChunk,
        LeakFinding,
    ]:
        event = _event({"content": SECRET})
        run = _analysis_run(event)
        sinks = _sinks(
            event,
            TOOLUSEPROXY_E2E_PUBLISH_TEXT_PROFILE,
            DEFAULT_MCP_PROFILE_REGISTRY,
        )
        source = _source(SECRET)
        return event, run, sinks, source, _finding(run, sinks[0], source)

    def test_unknown_profile_and_shape_errors_are_sanitized(self) -> None:
        event, run, sinks, source, finding = self._default_fixture()
        unknown = replace(event, tool_name="mcp__unknown__publish")
        unknown_sink = replace(sinks[0], tool_name=unknown.tool_name)
        unknown_finding = replace(finding, sink_node_id=unknown_sink.node_id)
        unknown_result = plan_mcp_redaction_preview(
            current_event=unknown,
            current_sequence_no=SEQUENCE_NO,
            analysis_run=run,
            current_sinks=(unknown_sink,),
            current_critical_findings=(unknown_finding,),
            source_chunks=_source_map(unknown, source),
        )

        shaped_event = _event({"content": SECRET, "unknown": "value"})
        shaped_run = _analysis_run(shaped_event)
        shaped_sinks = _sinks(
            shaped_event,
            TOOLUSEPROXY_E2E_PUBLISH_TEXT_PROFILE,
            DEFAULT_MCP_PROFILE_REGISTRY,
        )
        shaped_finding = _finding(shaped_run, shaped_sinks[0], source)
        shaped_result = plan_mcp_redaction_preview(
            current_event=shaped_event,
            current_sequence_no=SEQUENCE_NO,
            analysis_run=shaped_run,
            current_sinks=shaped_sinks,
            current_critical_findings=(shaped_finding,),
            source_chunks=_source_map(shaped_event, source),
        )

        assert unknown_result.plan is not None and shaped_result.plan is not None
        self.assertEqual("unknown_profile", unknown_result.plan.rejection_code)
        self.assertEqual(
            "profile_unknown_field",
            shaped_result.plan.rejection_code,
        )

    def test_noncanonical_mcp_prefix_is_not_preview_eligible(self) -> None:
        event, run, sinks, source, finding = self._default_fixture()
        uppercase = replace(event, tool_name="MCP__tooluseproxy_e2e__publish_text")
        uppercase_sink = replace(sinks[0], tool_name=uppercase.tool_name)
        result = plan_mcp_redaction_preview(
            current_event=uppercase,
            current_sequence_no=SEQUENCE_NO,
            analysis_run=run,
            current_sinks=(uppercase_sink,),
            current_critical_findings=(finding,),
            source_chunks=_source_map(uppercase, source),
        )

        assert result.plan is not None
        self.assertEqual("unsupported_tool", result.plan.rejection_code)

    def test_nested_input_is_rejected_before_sink_planning(self) -> None:
        event = _event({"content": [SECRET]})
        run = _analysis_run(event)
        source = _source(SECRET)
        fake_sink = SinkCandidate(
            node_id="sink:/content/0",
            sink_type="external_api_call",
            label="sink",
            tool_name=event.tool_name,
            tool_use_id=event.tool_use_id,
            session_id=event.session_id,
            sequence_no=SEQUENCE_NO,
            workspace_id=event.workspace_id,
            metadata={},
        )
        result = plan_mcp_redaction_preview(
            current_event=event,
            current_sequence_no=SEQUENCE_NO,
            analysis_run=run,
            current_sinks=(fake_sink,),
            current_critical_findings=(_finding(run, fake_sink, source),),
            source_chunks=_source_map(event, source),
        )

        assert result.plan is not None
        self.assertEqual("profile_unsupported_nesting", result.plan.rejection_code)

    def test_rejected_plan_is_independent_of_input_key_order(self) -> None:
        profile = McpToolProfile(
            profile_id="fixture/rejection-order",
            server="fixture",
            tool="rejection_order",
            sink_type="external_api_call",
            fields=(
                McpFieldSpec("/a", "string", "data", redactable=True),
                McpFieldSpec("/b", "string", "data", redactable=True),
            ),
            post_input_stable=True,
        )
        registry = McpProfileRegistry((profile,))
        forward_event = _event(
            {"a": {}, "b": None},
            tool_name="mcp__fixture__rejection_order",
        )
        reverse_event = replace(
            forward_event,
            raw_payload={"tool_input": {"b": None, "a": {}}},
        )
        run = _analysis_run(forward_event)
        source = _source(SECRET)
        fake_sink = SinkCandidate(
            node_id="sink:/a",
            sink_type=profile.sink_type,
            label="sink",
            tool_name=forward_event.tool_name,
            tool_use_id=forward_event.tool_use_id,
            session_id=forward_event.session_id,
            sequence_no=SEQUENCE_NO,
            workspace_id=forward_event.workspace_id,
            metadata={},
        )
        finding = _finding(run, fake_sink, source)

        forward = plan_mcp_redaction_preview(
            current_event=forward_event,
            current_sequence_no=SEQUENCE_NO,
            analysis_run=run,
            current_sinks=(fake_sink,),
            current_critical_findings=(finding,),
            source_chunks=_source_map(forward_event, source),
            profile_registry=registry,
        )
        reverse = plan_mcp_redaction_preview(
            current_event=reverse_event,
            current_sequence_no=SEQUENCE_NO,
            analysis_run=run,
            current_sinks=(fake_sink,),
            current_critical_findings=(finding,),
            source_chunks=_source_map(reverse_event, source),
            profile_registry=registry,
        )

        self.assertEqual(forward.plan, reverse.plan)
        assert forward.plan is not None
        self.assertEqual(
            "profile_unsupported_nesting",
            forward.plan.rejection_code,
        )

    def test_post_unstable_and_file_profiles_are_rejected_separately(self) -> None:
        unstable = McpToolProfile(
            profile_id="fixture/unstable",
            server="fixture",
            tool="unstable",
            sink_type="external_api_call",
            fields=(McpFieldSpec("/content", "string", "data", redactable=True),),
            post_input_stable=False,
        )
        file_profile = McpToolProfile(
            profile_id="fixture/file",
            server="fixture",
            tool="file",
            sink_type="external_file_transfer",
            fields=(McpFieldSpec("/file", "string", "file"),),
            post_input_stable=False,
        )
        for profile, expected in (
            (unstable, "post_input_unstable"),
            (file_profile, "file_input_unsupported"),
        ):
            with self.subTest(expected=expected):
                pointer = profile.fields[0].pointer
                key = pointer[1:]
                event = _event(
                    {key: SECRET},
                    tool_name=f"mcp__{profile.server}__{profile.tool}",
                )
                run = _analysis_run(event)
                registry = McpProfileRegistry((profile,))
                sinks = _sinks(event, profile, registry)
                source = _source(SECRET)
                result = plan_mcp_redaction_preview(
                    current_event=event,
                    current_sequence_no=SEQUENCE_NO,
                    analysis_run=run,
                    current_sinks=sinks,
                    current_critical_findings=(_finding(run, sinks[0], source),),
                    source_chunks=_source_map(event, source),
                    profile_registry=registry,
                )
                assert result.plan is not None
                self.assertEqual(expected, result.plan.rejection_code)

    def test_missing_or_duplicate_sink_pointer_rejects_full_coverage(self) -> None:
        event = _event(
            {
                "destination": "channel",
                "message": SECRET,
                "attachment_text": "public",
            },
            tool_name="mcp__fixture__publish_bundle",
        )
        run = _analysis_run(event)
        sinks = _sinks(event, MULTI_FIELD_PROFILE, MULTI_FIELD_REGISTRY)
        source = _source(SECRET)
        message_sink = next(
            sink for sink in sinks if sink.metadata["argument_json_pointer"] == "/message"
        )
        finding = _finding(run, message_sink, source)

        missing = plan_mcp_redaction_preview(
            current_event=event,
            current_sequence_no=SEQUENCE_NO,
            analysis_run=run,
            current_sinks=tuple(sink for sink in sinks if sink is not sinks[-1]),
            current_critical_findings=(finding,),
            source_chunks=_source_map(event, source),
            profile_registry=MULTI_FIELD_REGISTRY,
        )
        duplicate = plan_mcp_redaction_preview(
            current_event=event,
            current_sequence_no=SEQUENCE_NO,
            analysis_run=run,
            current_sinks=sinks + (replace(message_sink, node_id="duplicate"),),
            current_critical_findings=(finding,),
            source_chunks=_source_map(event, source),
            profile_registry=MULTI_FIELD_REGISTRY,
        )

        assert missing.plan is not None and duplicate.plan is not None
        self.assertEqual("sink_coverage_incomplete", missing.plan.rejection_code)
        self.assertEqual("sink_coverage_incomplete", duplicate.plan.rejection_code)

    def test_profile_version_and_fragment_kind_mismatch_reject(self) -> None:
        event, run, sinks, source, finding = self._default_fixture()
        version_sink = replace(
            sinks[0],
            metadata={**sinks[0].metadata, "profile_version": "stale"},
        )
        fragment_sink = replace(
            sinks[0],
            metadata={**sinks[0].metadata, "argument_fragment_kind": "json_key"},
        )
        version = plan_mcp_redaction_preview(
            current_event=event,
            current_sequence_no=SEQUENCE_NO,
            analysis_run=run,
            current_sinks=(version_sink,),
            current_critical_findings=(finding,),
            source_chunks=_source_map(event, source),
        )
        fragment = plan_mcp_redaction_preview(
            current_event=event,
            current_sequence_no=SEQUENCE_NO,
            analysis_run=run,
            current_sinks=(fragment_sink,),
            current_critical_findings=(finding,),
            source_chunks=_source_map(event, source),
        )

        assert version.plan is not None and fragment.plan is not None
        self.assertEqual("profile_version_mismatch", version.plan.rejection_code)
        self.assertEqual("unsupported_target_fragment", fragment.plan.rejection_code)

    def test_field_depth_type_and_pointer_boundaries_reject(self) -> None:
        event, run, sinks, source, finding = self._default_fixture()
        wrong_type_event = replace(
            event,
            raw_payload={"tool_input": {"content": 7}},
        )
        wrong_type = plan_mcp_redaction_preview(
            current_event=wrong_type_event,
            current_sequence_no=SEQUENCE_NO,
            analysis_run=run,
            current_sinks=sinks,
            current_critical_findings=(finding,),
            source_chunks=_source_map(wrong_type_event, source),
        )

        unresolved_sink = replace(
            sinks[0],
            metadata={
                **sinks[0].metadata,
                "argument_json_pointer": "/missing",
                "argument_relative_json_pointer": "/missing",
            },
        )
        unresolved = plan_mcp_redaction_preview(
            current_event=event,
            current_sequence_no=SEQUENCE_NO,
            analysis_run=run,
            current_sinks=(unresolved_sink,),
            current_critical_findings=(finding,),
            source_chunks=_source_map(event, source),
        )

        too_many_arguments = {
            "content": SECRET,
            **{f"extra_{index}": index for index in range(32)},
        }
        field_event = replace(
            event,
            raw_payload={"tool_input": too_many_arguments},
        )
        field_result = plan_mcp_redaction_preview(
            current_event=field_event,
            current_sequence_no=SEQUENCE_NO,
            analysis_run=run,
            current_sinks=sinks,
            current_critical_findings=(finding,),
            source_chunks=_source_map(field_event, source),
        )

        nested: object = SECRET
        for _ in range(9):
            nested = {"child": nested}
        depth_event = replace(
            event,
            raw_payload={"tool_input": {"content": nested}},
        )
        depth_result = plan_mcp_redaction_preview(
            current_event=depth_event,
            current_sequence_no=SEQUENCE_NO,
            analysis_run=run,
            current_sinks=sinks,
            current_critical_findings=(finding,),
            source_chunks=_source_map(depth_event, source),
        )

        assert wrong_type.plan and unresolved.plan and field_result.plan and depth_result.plan
        self.assertEqual("profile_wrong_field_type", wrong_type.plan.rejection_code)
        self.assertEqual("sink_pointer_unresolved", unresolved.plan.rejection_code)
        self.assertEqual("field_count_exceeded", field_result.plan.rejection_code)
        self.assertEqual("nesting_depth_exceeded", depth_result.plan.rejection_code)


class RedactionPreviewEvidenceAndScopeTest(unittest.TestCase):
    def _fixture(self) -> tuple[
        NormalizedEvent,
        AnalysisRun,
        tuple[SinkCandidate, ...],
        SourceChunk,
        LeakFinding,
    ]:
        event = _event({"content": SECRET})
        run = _analysis_run(event)
        sinks = _sinks(
            event,
            TOOLUSEPROXY_E2E_PUBLISH_TEXT_PROFILE,
            DEFAULT_MCP_PROFILE_REGISTRY,
        )
        source = _source(SECRET)
        return event, run, sinks, source, _finding(run, sinks[0], source)

    def test_raw_match_is_case_sensitive_and_does_not_use_normalized_text(self) -> None:
        event, run, sinks, source, finding = self._fixture()
        mismatched_source = replace(
            source,
            text=SECRET.upper(),
            text_hash=hashlib.sha256(SECRET.upper().encode()).hexdigest(),
            normalized_text=SECRET.lower(),
        )
        finding = replace(finding, source_node_id=mismatched_source.chunk_id)

        result = plan_mcp_redaction_preview(
            current_event=event,
            current_sequence_no=SEQUENCE_NO,
            analysis_run=run,
            current_sinks=sinks,
            current_critical_findings=(finding,),
            source_chunks=_source_map(event, mismatched_source),
        )

        assert result.plan is not None
        self.assertEqual("direct_raw_match_missing", result.plan.rejection_code)

    def test_cross_field_source_match_is_not_used(self) -> None:
        event = _event(
            {
                "destination": "channel",
                "message": SECRET,
                "attachment_text": "different protected payload",
            },
            tool_name="mcp__fixture__publish_bundle",
        )
        run = _analysis_run(event)
        sinks = _sinks(event, MULTI_FIELD_PROFILE, MULTI_FIELD_REGISTRY)
        attachment_sink = next(
            sink
            for sink in sinks
            if sink.metadata["argument_json_pointer"] == "/attachment_text"
        )
        source = _source(SECRET)

        with patch(
            "hook_monitor.policy.redaction_preview._has_direct_raw_match",
            wraps=lambda source_text, target: source_text in target,
        ) as matcher:
            result = plan_mcp_redaction_preview(
                current_event=event,
                current_sequence_no=SEQUENCE_NO,
                analysis_run=run,
                current_sinks=sinks,
                current_critical_findings=(_finding(run, attachment_sink, source),),
                source_chunks=_source_map(event, source),
                profile_registry=MULTI_FIELD_REGISTRY,
            )

        assert result.plan is not None
        self.assertEqual("direct_raw_match_missing", result.plan.rejection_code)
        self.assertEqual(1, matcher.call_count)

    def test_source_kind_scope_integrity_and_empty_text_are_rejected(self) -> None:
        event, run, sinks, source, finding = self._fixture()
        cases: list[tuple[str, LeakFinding, SourceChunk | None, str]] = [
            (
                "kind",
                replace(finding, source_node_kind="protected_source"),
                source,
                "unsupported_source_kind",
            ),
            ("missing", finding, None, "source_evidence_missing"),
            (
                "workspace",
                finding,
                replace(source, workspace_id="workspace-b"),
                "source_scope_mismatch",
            ),
            (
                "hash",
                finding,
                replace(source, text_hash="0" * 64),
                "source_integrity_mismatch",
            ),
        ]
        empty = _source("", chunk_id="empty:0")
        cases.append(
            (
                "empty",
                replace(finding, source_node_id=empty.chunk_id),
                empty,
                "empty_source_text",
            )
        )

        for label, current_finding, current_source, expected in cases:
            with self.subTest(label=label):
                sources = (
                    {}
                    if current_source is None
                    else _source_map(event, current_source)
                )
                result = plan_mcp_redaction_preview(
                    current_event=event,
                    current_sequence_no=SEQUENCE_NO,
                    analysis_run=run,
                    current_sinks=sinks,
                    current_critical_findings=(current_finding,),
                    source_chunks=sources,
                )
                assert result.plan is not None
                self.assertEqual(expected, result.plan.rejection_code)

    def test_event_analysis_sink_and_finding_scope_are_closed(self) -> None:
        event, run, sinks, source, finding = self._fixture()
        invalid_event = replace(event, workspace_status="unresolved")
        invalid_sink = replace(sinks[0], workspace_id="workspace-b")
        invalid_finding = replace(finding, analysis_run_id="other-run")

        event_result = plan_mcp_redaction_preview(
            current_event=invalid_event,
            current_sequence_no=SEQUENCE_NO,
            analysis_run=run,
            current_sinks=sinks,
            current_critical_findings=(finding,),
            source_chunks=_source_map(event, source),
        )
        sink_result = plan_mcp_redaction_preview(
            current_event=event,
            current_sequence_no=SEQUENCE_NO,
            analysis_run=run,
            current_sinks=(invalid_sink,),
            current_critical_findings=(finding,),
            source_chunks=_source_map(event, source),
        )
        finding_result = plan_mcp_redaction_preview(
            current_event=event,
            current_sequence_no=SEQUENCE_NO,
            analysis_run=run,
            current_sinks=sinks,
            current_critical_findings=(invalid_finding,),
            source_chunks=_source_map(event, source),
        )

        self.assertIsNone(event_result.plan)
        self.assertEqual("invalid_call_scope", event_result.diagnostic_code)
        assert sink_result.plan and finding_result.plan
        self.assertEqual("sink_scope_mismatch", sink_result.plan.rejection_code)
        self.assertEqual("finding_scope_mismatch", finding_result.plan.rejection_code)

    def test_unknown_external_policy_action_rejects_critical_plan(self) -> None:
        profile = replace(
            TOOLUSEPROXY_E2E_PUBLISH_TEXT_PROFILE,
            profile_id="fixture/unknown-policy",
            server="fixture",
            tool="unknown_policy",
            sink_type="external_unknown",
        )
        registry = McpProfileRegistry((profile,))
        event = _event(
            {"content": SECRET},
            tool_name="mcp__fixture__unknown_policy",
        )
        run = _analysis_run(event)
        sinks = _sinks(event, profile, registry)
        source = _source(SECRET)
        result = plan_mcp_redaction_preview(
            current_event=event,
            current_sequence_no=SEQUENCE_NO,
            analysis_run=run,
            current_sinks=sinks,
            current_critical_findings=(_finding(run, sinks[0], source),),
            source_chunks=_source_map(event, source),
            profile_registry=registry,
        )

        assert result.plan is not None
        self.assertEqual("critical_policy_mismatch", result.plan.rejection_code)


class RedactionPreviewLimitsTest(unittest.TestCase):
    def _fixture(
        self,
        content: str = SECRET,
    ) -> tuple[
        NormalizedEvent,
        AnalysisRun,
        tuple[SinkCandidate, ...],
        SourceChunk,
        LeakFinding,
    ]:
        event = _event({"content": content})
        run = _analysis_run(event)
        sinks = _sinks(
            event,
            TOOLUSEPROXY_E2E_PUBLISH_TEXT_PROFILE,
            DEFAULT_MCP_PROFILE_REGISTRY,
        )
        source = _source(SECRET)
        return event, run, sinks, source, _finding(run, sinks[0], source)

    def test_critical_finding_and_distinct_target_caps(self) -> None:
        event, run, sinks, source, finding = self._fixture(
            f"{SECRET} {SECOND_SECRET}"
        )
        second = _source(SECOND_SECRET, chunk_id="source-b:0")
        findings = (
            finding,
            _finding(run, sinks[0], second, finding_id="finding-b"),
        )
        finding_result = plan_mcp_redaction_preview(
            current_event=event,
            current_sequence_no=SEQUENCE_NO,
            analysis_run=run,
            current_sinks=sinks,
            current_critical_findings=findings,
            source_chunks=_source_map(event, source, second),
            limits=RedactionPreviewLimits(max_critical_findings=1),
        )

        multi_event = _event(
            {
                "destination": "channel",
                "message": SECRET,
                "attachment_text": SECOND_SECRET,
            },
            tool_name="mcp__fixture__publish_bundle",
        )
        multi_run = _analysis_run(multi_event)
        multi_sinks = _sinks(
            multi_event,
            MULTI_FIELD_PROFILE,
            MULTI_FIELD_REGISTRY,
        )
        by_pointer = {
            sink.metadata["argument_json_pointer"]: sink for sink in multi_sinks
        }
        target_result = plan_mcp_redaction_preview(
            current_event=multi_event,
            current_sequence_no=SEQUENCE_NO,
            analysis_run=multi_run,
            current_sinks=multi_sinks,
            current_critical_findings=(
                _finding(multi_run, by_pointer["/message"], source, finding_id="a"),
                _finding(
                    multi_run,
                    by_pointer["/attachment_text"],
                    second,
                    finding_id="b",
                ),
            ),
            source_chunks=_source_map(multi_event, source, second),
            profile_registry=MULTI_FIELD_REGISTRY,
            limits=RedactionPreviewLimits(max_distinct_targets=1),
        )

        assert finding_result.plan is not None and target_result.plan is not None
        self.assertEqual(
            "critical_finding_limit_exceeded",
            finding_result.plan.rejection_code,
        )
        self.assertEqual("target_limit_exceeded", target_result.plan.rejection_code)

    def test_default_critical_finding_boundary_is_32(self) -> None:
        def fixture(count: int):
            source_texts = tuple(f"protected-{index:02d}" for index in range(count))
            event = _event({"content": " ".join(source_texts)})
            run = _analysis_run(event)
            sinks = _sinks(
                event,
                TOOLUSEPROXY_E2E_PUBLISH_TEXT_PROFILE,
                DEFAULT_MCP_PROFILE_REGISTRY,
            )
            sources = tuple(
                _source(text, chunk_id=f"source-{index:02d}:0")
                for index, text in enumerate(source_texts)
            )
            findings = tuple(
                _finding(
                    run,
                    sinks[0],
                    source,
                    finding_id=f"finding-{index:02d}",
                )
                for index, source in enumerate(sources)
            )
            return event, run, sinks, sources, findings

        accepted_event, accepted_run, accepted_sinks, accepted_sources, accepted_findings = (
            fixture(32)
        )
        rejected_event, rejected_run, rejected_sinks, rejected_sources, rejected_findings = (
            fixture(33)
        )
        accepted = plan_mcp_redaction_preview(
            current_event=accepted_event,
            current_sequence_no=SEQUENCE_NO,
            analysis_run=accepted_run,
            current_sinks=accepted_sinks,
            current_critical_findings=accepted_findings,
            source_chunks=_source_map(accepted_event, *accepted_sources),
        )
        rejected = plan_mcp_redaction_preview(
            current_event=rejected_event,
            current_sequence_no=SEQUENCE_NO,
            analysis_run=rejected_run,
            current_sinks=rejected_sinks,
            current_critical_findings=rejected_findings,
            source_chunks=_source_map(rejected_event, *rejected_sources),
        )

        assert accepted.plan is not None and rejected.plan is not None
        self.assertEqual("eligible", accepted.disposition)
        self.assertEqual(1, accepted.plan.replacement_count)
        self.assertEqual(32, len(accepted.plan.targets))
        self.assertEqual(
            "critical_finding_limit_exceeded",
            rejected.plan.rejection_code,
        )

    def test_default_distinct_target_boundary_is_16(self) -> None:
        accepted_fixture = _many_target_fixture(16)
        rejected_fixture = _many_target_fixture(17)
        accepted_event, accepted_run, accepted_sinks, accepted_sources, accepted_findings, accepted_registry = accepted_fixture
        rejected_event, rejected_run, rejected_sinks, rejected_sources, rejected_findings, rejected_registry = rejected_fixture

        with patch(
            "hook_monitor.policy.redaction_preview._has_direct_raw_match",
            wraps=lambda source_text, target: source_text in target,
        ) as matcher:
            accepted = plan_mcp_redaction_preview(
                current_event=accepted_event,
                current_sequence_no=SEQUENCE_NO,
                analysis_run=accepted_run,
                current_sinks=accepted_sinks,
                current_critical_findings=accepted_findings,
                source_chunks=_source_map(accepted_event, *accepted_sources),
                profile_registry=accepted_registry,
            )
        rejected = plan_mcp_redaction_preview(
            current_event=rejected_event,
            current_sequence_no=SEQUENCE_NO,
            analysis_run=rejected_run,
            current_sinks=rejected_sinks,
            current_critical_findings=rejected_findings,
            source_chunks=_source_map(rejected_event, *rejected_sources),
            profile_registry=rejected_registry,
        )

        assert accepted.plan is not None and rejected.plan is not None
        self.assertEqual("eligible", accepted.disposition)
        self.assertEqual(16, accepted.plan.replacement_count)
        self.assertEqual(16, matcher.call_count)
        self.assertEqual("target_limit_exceeded", rejected.plan.rejection_code)

    def test_source_byte_caps_accept_boundary_and_reject_one_over(self) -> None:
        content = "abcdefg"
        event, run, sinks, _, _ = self._fixture(content)
        first = _source("abcd", chunk_id="first:0")
        second = _source("efg", chunk_id="second:0")
        findings = (
            _finding(run, sinks[0], first, finding_id="a"),
            _finding(run, sinks[0], second, finding_id="b"),
        )
        accepted = plan_mcp_redaction_preview(
            current_event=event,
            current_sequence_no=SEQUENCE_NO,
            analysis_run=run,
            current_sinks=sinks,
            current_critical_findings=findings,
            source_chunks=_source_map(event, first, second),
            limits=RedactionPreviewLimits(
                max_source_bytes_per_finding=4,
                max_source_bytes_total=7,
            ),
        )
        total_rejected = plan_mcp_redaction_preview(
            current_event=event,
            current_sequence_no=SEQUENCE_NO,
            analysis_run=run,
            current_sinks=sinks,
            current_critical_findings=findings,
            source_chunks=_source_map(event, first, second),
            limits=RedactionPreviewLimits(
                max_source_bytes_per_finding=4,
                max_source_bytes_total=6,
            ),
        )
        per_rejected = plan_mcp_redaction_preview(
            current_event=event,
            current_sequence_no=SEQUENCE_NO,
            analysis_run=run,
            current_sinks=sinks,
            current_critical_findings=(findings[0],),
            source_chunks=_source_map(event, first),
            limits=RedactionPreviewLimits(max_source_bytes_per_finding=3),
        )

        assert total_rejected.plan is not None and per_rejected.plan is not None
        self.assertEqual("eligible", accepted.disposition)
        self.assertEqual(
            "source_bytes_total_exceeded",
            total_rejected.plan.rejection_code,
        )
        self.assertEqual(
            "source_bytes_per_finding_exceeded",
            per_rejected.plan.rejection_code,
        )

    def test_total_source_cap_stops_before_later_source_work(self) -> None:
        class ExplodingText(str):
            def encode(self, *args, **kwargs):  # type: ignore[no-untyped-def]
                raise AssertionError("source after total cap must not be encoded")

        event, run, sinks, _, _ = self._fixture("aaaa bbbb cccc")
        first = _source("aaaa", chunk_id="a:0")
        second = _source("bbbb", chunk_id="b:0")
        third = replace(
            _source("cccc", chunk_id="c:0"),
            text=ExplodingText("cccc"),
        )
        findings = (
            _finding(run, sinks[0], first, finding_id="a"),
            _finding(run, sinks[0], second, finding_id="b"),
            _finding(run, sinks[0], third, finding_id="c"),
        )

        result = plan_mcp_redaction_preview(
            current_event=event,
            current_sequence_no=SEQUENCE_NO,
            analysis_run=run,
            current_sinks=sinks,
            current_critical_findings=findings,
            source_chunks=_source_map(event, first, second, third),
            limits=RedactionPreviewLimits(
                max_source_bytes_per_finding=4,
                max_source_bytes_total=6,
            ),
        )

        assert result.plan is not None
        self.assertEqual("source_bytes_total_exceeded", result.plan.rejection_code)

    def test_input_byte_boundary_uses_canonical_utf8_bytes(self) -> None:
        event, run, sinks, source, finding = self._fixture()
        canonical_size = len(b'{"content":"private-alpha-7f30"}')
        accepted = plan_mcp_redaction_preview(
            current_event=event,
            current_sequence_no=SEQUENCE_NO,
            analysis_run=run,
            current_sinks=sinks,
            current_critical_findings=(finding,),
            source_chunks=_source_map(event, source),
            limits=RedactionPreviewLimits(
                input_limits=McpInputLimits(max_input_bytes=canonical_size)
            ),
        )
        rejected = plan_mcp_redaction_preview(
            current_event=event,
            current_sequence_no=SEQUENCE_NO,
            analysis_run=run,
            current_sinks=sinks,
            current_critical_findings=(finding,),
            source_chunks=_source_map(event, source),
            limits=RedactionPreviewLimits(
                input_limits=McpInputLimits(max_input_bytes=canonical_size - 1)
            ),
        )

        assert rejected.plan is not None
        self.assertEqual("eligible", accepted.disposition)
        self.assertEqual("input_bytes_exceeded", rejected.plan.rejection_code)

    def test_oversized_input_is_rejected_before_canonical_hashing(self) -> None:
        event, run, sinks, source, finding = self._fixture("x" * 128)
        with patch(
            "hook_monitor.policy.redaction_preview._canonical_json_bytes"
        ) as canonicalize:
            result = plan_mcp_redaction_preview(
                current_event=event,
                current_sequence_no=SEQUENCE_NO,
                analysis_run=run,
                current_sinks=sinks,
                current_critical_findings=(finding,),
                source_chunks=_source_map(event, source),
                limits=RedactionPreviewLimits(
                    input_limits=McpInputLimits(max_input_bytes=32)
                ),
            )

        assert result.plan is not None
        self.assertEqual("input_bytes_exceeded", result.plan.rejection_code)
        canonicalize.assert_not_called()
        self.assertIsNone(result.plan.original_input_sha256)

    def test_deadline_is_cooperative_and_exact_boundary_rejects(self) -> None:
        event, run, sinks, source, finding = self._fixture()
        accepted = plan_mcp_redaction_preview(
            current_event=event,
            current_sequence_no=SEQUENCE_NO,
            analysis_run=run,
            current_sinks=sinks,
            current_critical_findings=(finding,),
            source_chunks=_source_map(event, source),
            monotonic_ns=_Clock([0, 49_999_999]),
        )
        rejected = plan_mcp_redaction_preview(
            current_event=event,
            current_sequence_no=SEQUENCE_NO,
            analysis_run=run,
            current_sinks=sinks,
            current_critical_findings=(finding,),
            source_chunks=_source_map(event, source),
            monotonic_ns=_Clock([0, 50_000_000]),
        )
        late_rejected = plan_mcp_redaction_preview(
            current_event=event,
            current_sequence_no=SEQUENCE_NO,
            analysis_run=run,
            current_sinks=sinks,
            current_critical_findings=(finding,),
            source_chunks=_source_map(event, source),
            monotonic_ns=_Clock(
                [0, 0, 0, 0, 0, 0, 50_000_000]
            ),
        )

        assert rejected.plan is not None and late_rejected.plan is not None
        self.assertEqual("eligible", accepted.disposition)
        self.assertEqual("planner_deadline_exceeded", rejected.plan.rejection_code)
        self.assertEqual(
            "planner_deadline_exceeded",
            late_rejected.plan.rejection_code,
        )
        self.assertIsNone(rejected.rewritten_input_json)
        self.assertIsNone(late_rejected.rewritten_input_json)

    def test_limits_reject_nonfinite_or_noninteger_values(self) -> None:
        invalid_options = (
            {"hard_deadline_ms": float("nan")},
            {"hard_deadline_ms": float("inf")},
            {"hard_deadline_ms": True},
            {"max_critical_findings": 1.5},
            {"max_distinct_targets": True},
        )
        for options in invalid_options:
            with self.subTest(options=options):
                with self.assertRaisesRegex(ValueError, "redaction preview"):
                    RedactionPreviewLimits(**options)

    def test_max_envelope_three_case_p95_is_below_ten_milliseconds(self) -> None:
        event, run, sinks, sources, findings, registry = _max_envelope_fixture()
        eligible = {
            "current_event": event,
            "current_sequence_no": SEQUENCE_NO,
            "analysis_run": run,
            "current_sinks": sinks,
            "current_critical_findings": findings,
            "source_chunks": _source_map(event, *sources),
            "profile_registry": registry,
        }
        mismatch_text = "absent-protected-value"
        mismatch = replace(
            sources[-1],
            text=mismatch_text,
            normalized_text=mismatch_text,
            text_hash=hashlib.sha256(mismatch_text.encode()).hexdigest(),
        )
        rejected = {
            **eligible,
            "source_chunks": _source_map(event, *sources[:-1], mismatch),
        }
        single_event, single_run, single_sinks, single_source, single_finding = (
            self._fixture()
        )
        single = {
            "current_event": single_event,
            "current_sequence_no": SEQUENCE_NO,
            "analysis_run": single_run,
            "current_sinks": single_sinks,
            "current_critical_findings": (single_finding,),
            "source_chunks": _source_map(single_event, single_source),
        }
        cases = (
            ("single", single, "eligible"),
            ("max_eligible", eligible, "eligible"),
            ("max_rejected", rejected, "rejected"),
        )
        for _ in range(25):
            for _, kwargs, _ in cases:
                plan_mcp_redaction_preview(**kwargs)

        durations = {name: [] for name, _, _ in cases}
        for _ in range(150):
            for name, kwargs, expected in cases:
                started = time.perf_counter_ns()
                result = plan_mcp_redaction_preview(**kwargs)
                durations[name].append(
                    (time.perf_counter_ns() - started) / 1_000_000
                )
                self.assertEqual(expected, result.disposition)

        for name, samples in durations.items():
            rank = math.ceil(0.95 * len(samples)) - 1
            p95 = sorted(samples)[rank]
            with self.subTest(case=name, p95=p95):
                self.assertLessEqual(p95, 10.0)


if __name__ == "__main__":
    unittest.main()
