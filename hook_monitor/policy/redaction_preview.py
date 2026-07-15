from __future__ import annotations

import hashlib
import json
import math
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any, Literal

from hook_monitor.analysis.adapters.mcp import parse_mcp_tool_name
from hook_monitor.analysis.adapters.mcp_profiles import (
    DEFAULT_MCP_INPUT_LIMITS,
    DEFAULT_MCP_PROFILE_REGISTRY,
    McpInputLimits,
    McpProfileRegistry,
    McpToolProfile,
    escape_json_pointer_segment,
    inspect_mcp_input,
)
from hook_monitor.analysis.leak_detection import LeakFinding
from hook_monitor.policy.engine import evaluate_policy
from hook_monitor.policy.models import PolicyDecision
from hook_monitor.runtime.models import (
    AnalysisRun,
    NormalizedEvent,
    SinkCandidate,
    SourceChunk,
    SourceChunkEvidence,
)
from hook_monitor.runtime.redaction_integrity import (
    REDACTION_PREVIEW_MAX_CRITICAL_FINDINGS,
    REDACTION_PREVIEW_MAX_DISTINCT_TARGETS,
    REDACTION_PREVIEW_MAX_SOURCE_BYTES_PER_FINDING,
    REDACTION_PREVIEW_MAX_SOURCE_BYTES_TOTAL,
    REDACTION_PREVIEW_PLANNER_VERSION,
    REDACTION_PREVIEW_REJECTION_ORDER,
    REDACTION_REPLACEMENT_PROFILE as REPLACEMENT_PROFILE,
    REDACTION_REPLACEMENT_TEXT as REPLACEMENT_TEXT,
    canonical_json_bytes as _canonical_json_bytes,
    replace_top_level_pointer as _replace_top_level_pointer,
    sha256_bytes as _sha256_bytes,
    structure_sha256 as _structure_sha256,
    top_level_pointer_key as _top_level_pointer_key,
    top_level_pointer_value as _top_level_pointer_value,
)


PLANNER_VERSION = REDACTION_PREVIEW_PLANNER_VERSION


@dataclass(frozen=True)
class RedactionPreviewLimits:
    input_limits: McpInputLimits = DEFAULT_MCP_INPUT_LIMITS
    max_critical_findings: int = REDACTION_PREVIEW_MAX_CRITICAL_FINDINGS
    max_distinct_targets: int = REDACTION_PREVIEW_MAX_DISTINCT_TARGETS
    max_source_bytes_per_finding: int = (
        REDACTION_PREVIEW_MAX_SOURCE_BYTES_PER_FINDING
    )
    max_source_bytes_total: int = REDACTION_PREVIEW_MAX_SOURCE_BYTES_TOTAL
    hard_deadline_ms: float = 50.0

    def __post_init__(self) -> None:
        integer_limits = (
            self.max_critical_findings,
            self.max_distinct_targets,
            self.max_source_bytes_per_finding,
            self.max_source_bytes_total,
        )
        if not isinstance(self.input_limits, McpInputLimits):
            raise ValueError("redaction preview input limits must be MCP limits")
        if any(type(value) is not int for value in integer_limits):
            raise ValueError("redaction preview count and byte limits must be integers")
        if (
            isinstance(self.hard_deadline_ms, bool)
            or not isinstance(self.hard_deadline_ms, (int, float))
            or not math.isfinite(self.hard_deadline_ms)
        ):
            raise ValueError("redaction preview deadline must be finite")
        if (
            min(
                *integer_limits,
                self.hard_deadline_ms,
            )
            <= 0
        ):
            raise ValueError("redaction preview limits must be positive")


DEFAULT_REDACTION_PREVIEW_LIMITS = RedactionPreviewLimits()


@dataclass(frozen=True)
class RedactionPreviewTarget:
    ordinal: int
    finding_id: str
    decision_id: str
    source_node_kind: str
    source_node_id: str
    sink_node_id: str
    json_pointer: str
    original_value_sha256: str
    replacement_profile: str


@dataclass(frozen=True)
class RedactionPreviewPlan:
    plan_id: str
    analysis_run_id: str
    pre_event_id: str
    workspace_id: str
    session_id: str
    tool_use_id: str
    tool_name: str
    adapter: str
    profile_id: str
    profile_version: str
    profile_registry_version: str
    mode: str
    status: Literal["eligible", "rejected"]
    planner_version: str
    original_input_sha256: str | None
    rewritten_input_sha256: str | None
    structure_sha256_before: str | None
    structure_sha256_after: str | None
    critical_finding_count: int
    replacement_count: int
    rejection_code: str | None
    targets: tuple[RedactionPreviewTarget, ...]


@dataclass(frozen=True)
class RedactionPreviewResult:
    disposition: Literal["not_applicable", "eligible", "rejected"]
    plan: RedactionPreviewPlan | None
    diagnostic_code: str | None = None
    rewritten_input_json: bytes | None = field(
        default=None,
        repr=False,
        compare=False,
    )

    def materialize_rewritten_input(self) -> dict[str, Any] | None:
        """Return a fresh candidate object without exposing it in result reprs."""
        if self.disposition != "eligible" or self.rewritten_input_json is None:
            return None
        value = json.loads(self.rewritten_input_json)
        if not isinstance(value, dict):
            raise ValueError("eligible MCP redaction preview must contain an object")
        return value


@dataclass(frozen=True)
class _TargetCandidate:
    finding: LeakFinding
    decision: PolicyDecision
    sink: SinkCandidate
    pointer: str
    original_value_sha256: str


_REJECTION_RANK = {
    rejection_code: index
    for index, rejection_code in enumerate(REDACTION_PREVIEW_REJECTION_ORDER)
}


def plan_mcp_redaction_preview(
    *,
    current_event: NormalizedEvent,
    current_sequence_no: int,
    analysis_run: AnalysisRun,
    current_sinks: tuple[SinkCandidate, ...],
    current_critical_findings: tuple[LeakFinding, ...],
    source_chunks: Mapping[
        tuple[str, str],
        SourceChunk | SourceChunkEvidence,
    ],
    profile_registry: McpProfileRegistry = DEFAULT_MCP_PROFILE_REGISTRY,
    limits: RedactionPreviewLimits = DEFAULT_REDACTION_PREVIEW_LIMITS,
    monotonic_ns: Callable[[], int] = time.monotonic_ns,
) -> RedactionPreviewResult:
    """Build a side-effect-free, all-or-nothing preview for one real MCP call.

    ``current_critical_findings`` must be the complete, unfiltered critical subset
    from the current call's ``detect_leaks`` result. A caller must never pass only
    ``select_strongest_decision``. The planner also receives only bounded source
    evidence. It performs no storage, filesystem, network, or model access and is
    intentionally not connected to Hook output rendering.
    """
    started_ns = monotonic_ns()
    critical_findings = current_critical_findings
    if not critical_findings:
        return RedactionPreviewResult("not_applicable", None)

    tool_input = current_event.raw_payload.get("tool_input")
    canonical_input: bytes | None = None
    original_input_sha256: str | None = None
    structure_sha256_before: str | None = None
    parsed_tool_name = parse_mcp_tool_name(current_event.tool_name)
    profile = (
        profile_registry.resolve(*parsed_tool_name)
        if parsed_tool_name is not None
        else None
    )

    def reject(rejection_code: str) -> RedactionPreviewResult:
        return _rejected_result(
            current_event=current_event,
            analysis_run=analysis_run,
            parsed_tool_name=parsed_tool_name,
            profile=profile,
            profile_registry=profile_registry,
            original_input_sha256=original_input_sha256,
            structure_sha256_before=structure_sha256_before,
            critical_finding_count=len(critical_findings),
            rejection_code=rejection_code,
        )

    if not _valid_call_scope(current_event, current_sequence_no, analysis_run):
        return RedactionPreviewResult(
            "rejected",
            None,
            diagnostic_code="invalid_call_scope",
        )
    if (
        parsed_tool_name is None
        or current_event.tool_name is None
        or not current_event.tool_name.startswith("mcp__")
    ):
        return reject("unsupported_tool")

    try:
        inspection = inspect_mcp_input(tool_input, limits.input_limits)
    except (TypeError, ValueError, UnicodeEncodeError):
        return reject("unsupported_input_type")
    if not inspection.accepted:
        return reject(inspection.rejection_code or "unsupported_input_type")
    if not isinstance(tool_input, dict) or any(
        not isinstance(key, str) for key in tool_input
    ):
        return reject("unsupported_input_type")
    canonical_input = _canonical_json_bytes(tool_input)
    assert canonical_input is not None
    original_input_sha256 = _sha256_bytes(canonical_input)
    structure_sha256_before = _structure_sha256(tool_input)
    if _deadline_exceeded(started_ns, limits, monotonic_ns):
        return reject("planner_deadline_exceeded")

    if profile is None:
        return reject("unknown_profile")
    validation = profile.validate(tool_input)
    if not validation.accepted:
        return reject(f"profile_{validation.rejection_code}")
    if profile.file_input_pointers:
        return reject("file_input_unsupported")
    if not profile.post_input_stable:
        return reject("post_input_unstable")
    if len(current_sinks) > limits.input_limits.max_fields:
        return reject("sink_coverage_incomplete")
    profile_version = profile.profile_version
    profile_registry_version = profile_registry.registry_version

    sink_by_id, sink_errors = _validate_sink_coverage(
        current_event=current_event,
        current_sequence_no=current_sequence_no,
        current_sinks=current_sinks,
        tool_input=tool_input,
        profile=profile,
        profile_version=profile_version,
        profile_registry_version=profile_registry_version,
    )
    if sink_errors:
        return reject(_primary_rejection(sink_errors))
    if _deadline_exceeded(started_ns, limits, monotonic_ns):
        return reject("planner_deadline_exceeded")

    if len(critical_findings) > limits.max_critical_findings:
        return reject("critical_finding_limit_exceeded")
    if any(finding.severity != "critical" for finding in critical_findings):
        return reject("critical_policy_mismatch")
    if len({finding.finding_id for finding in critical_findings}) != len(
        critical_findings
    ):
        return reject("duplicate_finding_id")

    decisions = evaluate_policy(list(critical_findings))
    decisions_by_finding = {decision.finding_id: decision for decision in decisions}
    candidates: list[_TargetCandidate] = []
    finding_errors: list[str] = []
    total_source_bytes = 0

    for finding in sorted(critical_findings, key=_finding_key):
        if _deadline_exceeded(started_ns, limits, monotonic_ns):
            return reject("planner_deadline_exceeded")
        decision = decisions_by_finding.get(finding.finding_id)
        sink = sink_by_id.get(finding.sink_node_id)
        finding_error = _validate_finding_scope(
            finding,
            decision,
            sink,
            analysis_run,
        )
        if finding_error is not None:
            finding_errors.append(finding_error)
            continue
        assert decision is not None
        assert sink is not None

        if finding.source_node_kind != "source_chunk":
            finding_errors.append("unsupported_source_kind")
            continue
        workspace_id = current_event.workspace_id
        assert workspace_id is not None
        source = source_chunks.get((workspace_id, finding.source_node_id))
        if source is None or source.chunk_id != finding.source_node_id:
            finding_errors.append("source_evidence_missing")
            continue
        if source.workspace_id != workspace_id:
            finding_errors.append("source_scope_mismatch")
            continue

        if not isinstance(source.text, str):
            finding_errors.append("source_integrity_mismatch")
            continue
        if len(source.text) > limits.max_source_bytes_per_finding:
            finding_errors.append("source_bytes_per_finding_exceeded")
            continue
        try:
            source_bytes = source.text.encode("utf-8")
        except UnicodeEncodeError:
            finding_errors.append("source_integrity_mismatch")
            continue
        if hashlib.sha256(source_bytes).hexdigest() != source.text_hash:
            finding_errors.append("source_integrity_mismatch")
            continue
        if not source.text:
            finding_errors.append("empty_source_text")
            continue
        if len(source_bytes) > limits.max_source_bytes_per_finding:
            finding_errors.append("source_bytes_per_finding_exceeded")
            continue
        total_source_bytes += len(source_bytes)
        if total_source_bytes > limits.max_source_bytes_total:
            return reject("source_bytes_total_exceeded")

        pointer = sink.metadata.get("argument_relative_json_pointer")
        if not isinstance(pointer, str):
            finding_errors.append("sink_pointer_unresolved")
            continue
        field_spec = profile.field_for_pointer(pointer)
        if (
            field_spec is None
            or field_spec.field_class != "data"
            or not field_spec.redactable
        ):
            finding_errors.append("target_not_redactable")
            continue
        value = _top_level_pointer_value(tool_input, pointer)
        if not isinstance(value, str) or field_spec.value_type != "string":
            finding_errors.append("target_not_string")
            continue
        if source.text in REPLACEMENT_TEXT:
            finding_errors.append("replacement_contains_source")
            continue
        if not _has_direct_raw_match(source.text, value):
            finding_errors.append("direct_raw_match_missing")
            continue
        if value == REPLACEMENT_TEXT:
            finding_errors.append("replacement_noop")
            continue
        candidates.append(
            _TargetCandidate(
                finding=finding,
                decision=decision,
                sink=sink,
                pointer=pointer,
                original_value_sha256=hashlib.sha256(
                    value.encode("utf-8")
                ).hexdigest(),
            )
        )

    if finding_errors:
        return reject(_primary_rejection(finding_errors))
    if len(candidates) != len(critical_findings):
        return reject("finding_scope_mismatch")

    distinct_pointers = tuple(sorted({candidate.pointer for candidate in candidates}))
    if len(distinct_pointers) > limits.max_distinct_targets:
        return reject("target_limit_exceeded")
    if _deadline_exceeded(started_ns, limits, monotonic_ns):
        return reject("planner_deadline_exceeded")

    rewritten_input = json.loads(canonical_input)
    assert isinstance(rewritten_input, dict)
    for pointer in distinct_pointers:
        _replace_top_level_pointer(rewritten_input, pointer, REPLACEMENT_TEXT)

    structure_sha256_after = _structure_sha256(rewritten_input)
    rewrite_error = _validate_rewrite(
        original=tool_input,
        rewritten=rewritten_input,
        target_pointers=frozenset(distinct_pointers),
        profile=profile,
        structure_sha256_before=structure_sha256_before,
        structure_sha256_after=structure_sha256_after,
    )
    if rewrite_error is not None:
        return reject(rewrite_error)
    rewritten_input_json = _canonical_json_bytes(rewritten_input)
    if rewritten_input_json is None:
        return reject("profile_revalidation_failed")
    rewritten_input_sha256 = _sha256_bytes(rewritten_input_json)
    if _deadline_exceeded(started_ns, limits, monotonic_ns):
        return reject("planner_deadline_exceeded")

    targets = tuple(
        RedactionPreviewTarget(
            ordinal=index,
            finding_id=candidate.finding.finding_id,
            decision_id=candidate.decision.decision_id,
            source_node_kind=candidate.finding.source_node_kind,
            source_node_id=candidate.finding.source_node_id,
            sink_node_id=candidate.sink.node_id,
            json_pointer=candidate.pointer,
            original_value_sha256=candidate.original_value_sha256,
            replacement_profile=REPLACEMENT_PROFILE,
        )
        for index, candidate in enumerate(sorted(candidates, key=_candidate_key))
    )
    plan = _make_plan(
        current_event=current_event,
        analysis_run=analysis_run,
        profile_id=profile.profile_id,
        profile_version=profile_version,
        profile_registry_version=profile_registry_version,
        status="eligible",
        original_input_sha256=original_input_sha256,
        rewritten_input_sha256=rewritten_input_sha256,
        structure_sha256_before=structure_sha256_before,
        structure_sha256_after=structure_sha256_after,
        critical_finding_count=len(critical_findings),
        replacement_count=len(distinct_pointers),
        rejection_code=None,
        targets=targets,
    )
    if _deadline_exceeded(started_ns, limits, monotonic_ns):
        return reject("planner_deadline_exceeded")
    return RedactionPreviewResult(
        "eligible",
        plan,
        rewritten_input_json=rewritten_input_json,
    )


def _valid_call_scope(
    event: NormalizedEvent,
    current_sequence_no: int,
    analysis_run: AnalysisRun,
) -> bool:
    return bool(
        event.phase == "pre_tool_use"
        and event.workspace_status == "ready"
        and event.workspace_id
        and event.session_id
        and event.tool_use_id
        and event.tool_name
        and current_sequence_no > 0
        and analysis_run.workspace_id == event.workspace_id
        and analysis_run.session_id == event.session_id
    )


def _validate_sink_coverage(
    *,
    current_event: NormalizedEvent,
    current_sequence_no: int,
    current_sinks: tuple[SinkCandidate, ...],
    tool_input: dict[str, Any],
    profile: McpToolProfile,
    profile_version: str,
    profile_registry_version: str,
) -> tuple[dict[str, SinkCandidate], list[str]]:
    errors: list[str] = []
    sink_by_id: dict[str, SinkCandidate] = {}
    pointers: list[str] = []
    expected_pointers = {
        f"/{escape_json_pointer_segment(key)}" for key in tool_input
    }

    for sink in sorted(current_sinks, key=lambda candidate: candidate.node_id):
        if sink.node_id in sink_by_id:
            errors.append("duplicate_sink_id")
        sink_by_id[sink.node_id] = sink
        metadata = sink.metadata
        if (
            sink.workspace_id != current_event.workspace_id
            or sink.session_id != current_event.session_id
            or sink.tool_use_id != current_event.tool_use_id
            or sink.tool_name != current_event.tool_name
            or sink.sequence_no != current_sequence_no
            or metadata.get("event_id") != current_event.event_id
        ):
            errors.append("sink_scope_mismatch")
        if (
            metadata.get("adapter") != "mcp"
            or metadata.get("call_shape") != "real_codex"
            or metadata.get("server") != profile.server
            or metadata.get("tool") != profile.tool
            or sink.sink_type != profile.sink_type
            or metadata.get("profile_status") != "matched"
            or metadata.get("profile_rejection_code") != ""
            or metadata.get("profile_preview_eligible") is not True
        ):
            errors.append("sink_field_metadata_mismatch")
        if (
            metadata.get("profile_id") != profile.profile_id
            or metadata.get("profile_version") != profile_version
            or metadata.get("profile_registry_version")
            != profile_registry_version
        ):
            errors.append("profile_version_mismatch")
        if metadata.get("argument_fragment_kind") != "payload":
            errors.append("unsupported_target_fragment")

        pointer = metadata.get("argument_relative_json_pointer")
        absolute_pointer = metadata.get("argument_json_pointer")
        if not isinstance(pointer, str) or absolute_pointer != pointer:
            errors.append("sink_pointer_unresolved")
            continue
        field_spec = profile.field_for_pointer(pointer)
        if field_spec is None:
            errors.append("sink_pointer_unresolved")
            continue
        pointers.append(pointer)
        redactable = metadata.get("argument_redactable")
        if (
            metadata.get("argument_field_class") != field_spec.field_class
            or type(redactable) is not bool
            or redactable != field_spec.redactable
        ):
            errors.append("sink_field_metadata_mismatch")

    if len(pointers) != len(set(pointers)) or set(pointers) != expected_pointers:
        errors.append("sink_coverage_incomplete")
    return sink_by_id, errors


def _validate_finding_scope(
    finding: LeakFinding,
    decision: PolicyDecision | None,
    sink: SinkCandidate | None,
    analysis_run: AnalysisRun,
) -> str | None:
    if (
        finding.analysis_run_id != analysis_run.analysis_run_id
        or sink is None
        or finding.sink_type != sink.sink_type
        or not finding.sink_type.startswith("external_")
    ):
        return "finding_scope_mismatch"
    if (
        decision is None
        or decision.action != "block"
        or decision.severity != "critical"
        or decision.hook_event != "PreToolUse"
        or decision.finding_id != finding.finding_id
        or decision.source_node_kind != finding.source_node_kind
        or decision.source_node_id != finding.source_node_id
        or decision.sink_node_id != finding.sink_node_id
        or decision.sink_type != finding.sink_type
    ):
        return "critical_policy_mismatch"
    return None


def _validate_rewrite(
    *,
    original: dict[str, Any],
    rewritten: dict[str, Any],
    target_pointers: frozenset[str],
    profile: McpToolProfile,
    structure_sha256_before: str | None,
    structure_sha256_after: str | None,
) -> str | None:
    if not profile.validate(rewritten).accepted:
        return "profile_revalidation_failed"
    if structure_sha256_before != structure_sha256_after:
        return "structure_changed"

    for field_spec in profile.fields:
        key = _top_level_pointer_key(field_spec.pointer)
        if key not in original:
            continue
        original_value = original[key]
        rewritten_value = rewritten.get(key)
        if field_spec.pointer in target_pointers:
            if rewritten_value != REPLACEMENT_TEXT or original_value == rewritten_value:
                return "replacement_noop"
        elif rewritten_value != original_value:
            if field_spec.field_class == "control":
                return "control_changed"
            return "unexpected_input_diff"
    if original.keys() != rewritten.keys():
        return "unexpected_input_diff"
    return None


def _rejected_result(
    *,
    current_event: NormalizedEvent,
    analysis_run: AnalysisRun,
    parsed_tool_name: tuple[str, str] | None,
    profile: McpToolProfile | None,
    profile_registry: McpProfileRegistry,
    original_input_sha256: str | None,
    structure_sha256_before: str | None,
    critical_finding_count: int,
    rejection_code: str,
) -> RedactionPreviewResult:
    server, tool = parsed_tool_name or ("unknown_server", "unknown_tool")
    profile_id = profile.profile_id if profile else f"unprofiled:{server}/{tool}"
    profile_version = (
        profile.profile_version if profile else profile_registry.registry_version
    )
    plan = _make_plan(
        current_event=current_event,
        analysis_run=analysis_run,
        profile_id=profile_id,
        profile_version=profile_version,
        profile_registry_version=profile_registry.registry_version,
        status="rejected",
        original_input_sha256=original_input_sha256,
        rewritten_input_sha256=None,
        structure_sha256_before=structure_sha256_before,
        structure_sha256_after=None,
        critical_finding_count=critical_finding_count,
        replacement_count=0,
        rejection_code=rejection_code,
        targets=(),
    )
    return RedactionPreviewResult(
        "rejected",
        plan,
        diagnostic_code=rejection_code,
    )


def _make_plan(
    *,
    current_event: NormalizedEvent,
    analysis_run: AnalysisRun,
    profile_id: str,
    profile_version: str,
    profile_registry_version: str,
    status: Literal["eligible", "rejected"],
    original_input_sha256: str | None,
    rewritten_input_sha256: str | None,
    structure_sha256_before: str | None,
    structure_sha256_after: str | None,
    critical_finding_count: int,
    replacement_count: int,
    rejection_code: str | None,
    targets: tuple[RedactionPreviewTarget, ...],
) -> RedactionPreviewPlan:
    workspace_id = current_event.workspace_id or ""
    session_id = current_event.session_id or ""
    tool_use_id = current_event.tool_use_id or ""
    tool_name = current_event.tool_name or ""
    identity = "\0".join(
        (
            workspace_id,
            current_event.event_id,
            analysis_run.analysis_run_id,
            PLANNER_VERSION,
            profile_version,
            "preview",
        )
    )
    return RedactionPreviewPlan(
        plan_id=hashlib.sha256(identity.encode("utf-8")).hexdigest(),
        analysis_run_id=analysis_run.analysis_run_id,
        pre_event_id=current_event.event_id,
        workspace_id=workspace_id,
        session_id=session_id,
        tool_use_id=tool_use_id,
        tool_name=tool_name,
        adapter="mcp",
        profile_id=profile_id,
        profile_version=profile_version,
        profile_registry_version=profile_registry_version,
        mode="preview",
        status=status,
        planner_version=PLANNER_VERSION,
        original_input_sha256=original_input_sha256,
        rewritten_input_sha256=rewritten_input_sha256,
        structure_sha256_before=structure_sha256_before,
        structure_sha256_after=structure_sha256_after,
        critical_finding_count=critical_finding_count,
        replacement_count=replacement_count,
        rejection_code=rejection_code,
        targets=targets,
    )


def _candidate_key(
    candidate: _TargetCandidate,
) -> tuple[str, str, str, str, str]:
    return (
        candidate.pointer,
        candidate.finding.finding_id,
        candidate.finding.source_node_kind,
        candidate.finding.source_node_id,
        candidate.sink.node_id,
    )


def _finding_key(finding: LeakFinding) -> tuple[str, str, str, str]:
    return (
        finding.finding_id,
        finding.source_node_kind,
        finding.source_node_id,
        finding.sink_node_id,
    )


def _primary_rejection(rejection_codes: list[str]) -> str:
    return min(
        rejection_codes,
        key=lambda code: (_REJECTION_RANK.get(code, len(_REJECTION_RANK)), code),
    )


def _deadline_exceeded(
    started_ns: int,
    limits: RedactionPreviewLimits,
    monotonic_ns: Callable[[], int],
) -> bool:
    elapsed_ns = monotonic_ns() - started_ns
    return elapsed_ns >= int(limits.hard_deadline_ms * 1_000_000)


def _has_direct_raw_match(source_text: str, target_value: str) -> bool:
    return source_text in target_value
