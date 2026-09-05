from __future__ import annotations

from dataclasses import dataclass, replace
from pathlib import Path
from typing import Literal
from hook_monitor.runtime.pilot_recording import PilotPolicyFacts
from hook_monitor.runtime.pilot_models import PayloadResolution, EvidenceSource, ReasonCode

from hook_monitor.analysis.adapters.mcp import (
    classify_mcp_sink_type,
    parse_mcp_tool_name,
)
from hook_monitor.analysis.adapters.externality_rule import ExternalityPolicyRisk
from hook_monitor.analysis.adapters.mcp_profiles import (
    MCP_TOOL_NAME_MAX_BYTES,
    inspect_mcp_input,
)
from hook_monitor.analysis.leak_detection import LeakFinding, detect_leaks
from hook_monitor.analysis.mcp_payload_evidence import (
    verify_mcp_payload_against_sources,
)
from hook_monitor.analysis.sink_payload_evidence import (
    BashSinkPayloadEvidence,
    inspect_bash_sink_payload_evidence,
)
from hook_monitor.policy.codex_output import (
    render_codex_hook_output,
    select_strongest_decision,
)
from hook_monitor.policy.engine import evaluate_policy, make_policy_decision_id
from hook_monitor.policy.models import PolicyDecision
from hook_monitor.policy.sink_payload_exact import (
    build_exact_file_payload_decisions,
    build_unresolved_external_payload_decisions,
    build_unverified_external_sink_decisions,
)
from hook_monitor.policy.redaction_preview import (
    DEFAULT_REDACTION_PREVIEW_LIMITS,
    plan_mcp_redaction_preview,
)
from hook_monitor.runtime.incremental_analysis import (
    RUNTIME_GRAPH_DETECTOR_VERSION,
    RuntimeAnalysisResult,
    update_runtime_analysis,
)
from hook_monitor.runtime.models import AnalysisRun, NormalizedEvent, SinkCandidate
from hook_monitor.runtime.policy_audit import store_policy_decision
from hook_monitor.runtime.redaction_audit import store_redaction_preview_plan
from hook_monitor.runtime.source_config import ProtectedSourceUnavailableError
from hook_monitor.runtime.sink_payload_shadow import (
    build_sink_payload_shadow_observation,
    store_sink_payload_shadow_observations,
)
from hook_monitor.runtime.storage import EventStore
from hook_monitor.runtime.externality_rules import ExternalityHookDecision
from hook_monitor.runtime.tool_compat import (
    is_enforced_shell_tool,
    shell_command_from_input,
)


DEFAULT_PRE_TOOL_ADAPTERS = frozenset({"bash"})
LOCAL_FILE_TOOL_NAMES = frozenset(
    {"apply_patch", "edit", "glob", "grep", "read", "write"}
)
MCP_INPUT_LIMIT_DENY_REASON = (
    "ToolUseProxy blocked this MCP call because its input exceeds bounded "
    "static-analysis limits"
)
PRE_TOOL_PREREQUISITE_DENY_REASON = (
    "ToolUseProxy blocked this call because required Hook identity could not "
    "be verified"
)
MCP_INPUT_REJECTION_CODES = frozenset(
    {
        "field_count_exceeded",
        "input_bytes_exceeded",
        "input_not_object",
        "invalid_unicode_scalar",
        "json_envelope_bytes_exceeded",
        "json_envelope_nesting_exceeded",
        "nesting_depth_exceeded",
        "numeric_token_exceeded",
        "numeric_value_non_finite",
        "tool_name_bytes_exceeded",
        "unsupported_input_type",
        "unsupported_numeric_constant",
    }
)


@dataclass(frozen=True)
class PreToolInputGuardResult:
    disposition: Literal["continue", "deny", "bypass"]
    hook_output: dict[str, object]


def render_mcp_input_limit_deny(rejection_code: str) -> dict[str, object]:
    safe_code = (
        rejection_code
        if rejection_code in MCP_INPUT_REJECTION_CODES
        else "input_rejected"
    )
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": (
                f"{MCP_INPUT_LIMIT_DENY_REASON} ({safe_code})."
            ),
        }
    }


def render_pre_tool_prerequisite_deny(rejection_code: str) -> dict[str, object]:
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": (
                f"{PRE_TOOL_PREREQUISITE_DENY_REASON} ({rejection_code})."
            ),
        }
    }


def render_protected_source_unavailable_deny() -> dict[str, object]:
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "additionalContext": (
                "登録済みの保護対象が現在の場所に見つかりません。"
                "（技術情報: protected_source_unavailable）"
            ),
            "permissionDecision": "deny",
            "permissionDecisionReason": (
                "ToolUseProxyが操作を実行前に止めました。登録済みの保護対象を"
                "確認できない間は、外部通信の可能性がある操作を許可できません。"
                "保護対象の登録を確認してからやり直してください。\n"
                "結果：外部操作は実行されていません。"
                "保護対象の内容も表示していません。"
            ),
        }
    }


def is_enforced_bash_tool(tool_name: str | None) -> bool:
    return is_enforced_shell_tool(tool_name)


def pre_tool_adapter(tool_name: str | None) -> str | None:
    if is_enforced_bash_tool(tool_name):
        return "bash"
    if parse_mcp_tool_name(tool_name) is not None:
        return "mcp"
    if (
        isinstance(tool_name, str)
        and tool_name.strip()
        and tool_name.casefold() not in LOCAL_FILE_TOOL_NAMES
    ):
        return "function"
    return None


def evaluate_pre_tool_input_bounds(
    current_event: NormalizedEvent,
    *,
    enabled_adapters: frozenset[str] = DEFAULT_PRE_TOOL_ADAPTERS,
) -> PreToolInputGuardResult:
    """Deny oversized writes and bypass oversized reads before materialization."""
    if (
        current_event.workspace_status != "ready"
        or "mcp" not in enabled_adapters
        or pre_tool_adapter(current_event.tool_name) != "mcp"
    ):
        return PreToolInputGuardResult("continue", {})
    try:
        tool_name_bytes = len((current_event.tool_name or "").encode("utf-8"))
    except UnicodeEncodeError:
        tool_name_bytes = MCP_TOOL_NAME_MAX_BYTES + 1
    if tool_name_bytes > MCP_TOOL_NAME_MAX_BYTES:
        return PreToolInputGuardResult(
            "deny",
            render_mcp_input_limit_deny("tool_name_bytes_exceeded"),
        )
    arguments = current_event.raw_payload.get("tool_input")
    inspection = inspect_mcp_input(arguments)
    if inspection.accepted:
        return PreToolInputGuardResult("continue", {})
    classifier_payload = arguments if isinstance(arguments, dict) else {}
    if classify_mcp_sink_type(current_event.tool_name, classifier_payload) is None:
        return PreToolInputGuardResult("bypass", {})
    rejection_code = inspection.rejection_code or "input_rejected"
    return PreToolInputGuardResult(
        "deny",
        render_mcp_input_limit_deny(rejection_code),
    )


def evaluate_pre_tool_hook_policy(
    store: EventStore,
    repo_root: Path,
    *,
    current_event: NormalizedEvent,
    enabled_adapters: frozenset[str] = DEFAULT_PRE_TOOL_ADAPTERS,
    sink_payload_shadow_enabled: bool = False,
    sink_payload_exact_enforcement_enabled: bool = False,
    minimum_path_score: float = 0.15,
    leak_min_score: float = 0.3,
    externality_decision: ExternalityHookDecision | None = None,
    recovery_externality_decision: ExternalityHookDecision | None = None,
    pilot_facts: PilotPolicyFacts | None = None,
) -> dict[str, object]:
    current_adapter = pre_tool_adapter(current_event.tool_name)
    if pilot_facts is not None:
        pilot_facts.eligible = True
        pilot_facts.reason = ReasonCode.POLICY_SAFETY_FAILURE
    if current_event.session_id is None:
        return render_pre_tool_prerequisite_deny("session_identity_missing")
    if current_event.workspace_status != "ready" or current_event.workspace_id is None:
        return render_pre_tool_prerequisite_deny("workspace_identity_unavailable")
    if not isinstance(current_event.tool_name, str) or not current_event.tool_name.strip():
        return render_pre_tool_prerequisite_deny("tool_identity_missing")
    if (
        current_adapter is None
        or current_adapter not in enabled_adapters
    ):
        if pilot_facts is not None:
            pilot_facts.eligible = False
        return {}

    bounded_input_guard = evaluate_pre_tool_input_bounds(
        current_event,
        enabled_adapters=enabled_adapters,
    )
    if bounded_input_guard.disposition != "continue":
        return bounded_input_guard.hook_output

    externality_risk = _externality_policy_risk(
        current_event,
        current_adapter=current_adapter,
        decision=externality_decision,
    )
    try:
        runtime_result = update_runtime_analysis(
            store,
            current_event_id=current_event.event_id,
            detector_version=RUNTIME_GRAPH_DETECTOR_VERSION,
            minimum_path_score=minimum_path_score,
            externality_policy_risk=externality_risk,
        )
    except ProtectedSourceUnavailableError:
        if (
            recovery_externality_decision is not None
            and recovery_externality_decision.state == "known_local"
        ):
            if pilot_facts is not None:
                pilot_facts.eligible = False
            return {}
        return render_protected_source_unavailable_deny()
    current_sequence_no = store.get_event_sequence_no(current_event.event_id)
    current_sinks = _current_external_sinks(
        list(runtime_result.sinks),
        current_event,
        current_sequence_no,
        current_adapter,
    )
    if pilot_facts is not None:
        pilot_facts.eligible = bool(current_sinks) or (
            externality_decision is not None and externality_decision.state != "known_local"
        )
        pilot_facts.completed = True
    findings = detect_leaks(
        analysis_run=runtime_result.analysis_run,
        assignments=list(runtime_result.assignments),
        sink_candidates=current_sinks,
        min_score=leak_min_score,
        sink_types={sink.sink_type for sink in current_sinks},
    )
    decisions = evaluate_policy(findings)
    if externality_risk is not None:
        externality_sink_ids = {
            sink.node_id
            for sink in current_sinks
            if sink.metadata.get("basis") == externality_risk.basis
            and sink.metadata.get("envelope_sha256")
            == externality_risk.envelope_sha256
        }
        decisions = [
            replace(
                decision,
                action="block",
                decision_id=make_policy_decision_id(
                    decision.finding_id,
                    "block",
                    decision.hook_event,
                ),
                reason=(
                    "block because protected lineage reached a conservatively "
                    "classified externality sink"
                ),
            )
            if decision.sink_node_id in externality_sink_ids
            else decision
            for decision in decisions
        ]
    selected = select_strongest_decision(decisions, "PreToolUse")
    if pilot_facts is not None:
        pilot_facts.selected(selected)
    if selected is not None and selected.action != "allow":
        store_policy_decision(
            store,
            selected,
            runtime_result.analysis_run.analysis_run_id,
        )
    hook_output = render_codex_hook_output(
        selected,
        "PreToolUse",
        db_path=store.db_path,
        analysis_run_id=runtime_result.analysis_run.analysis_run_id,
    )
    critical_findings = tuple(
        finding for finding in findings if finding.severity == "critical"
    )
    if (
        current_adapter == "mcp"
        and selected is not None
        and selected.action == "block"
        and critical_findings
    ):
        try:
            _store_mcp_redaction_preview(
                store,
                current_event=current_event,
                current_sequence_no=current_sequence_no,
                analysis_run=runtime_result.analysis_run,
                current_sinks=tuple(current_sinks),
                current_critical_findings=critical_findings,
            )
        except Exception:
            # A preview-only failure must never weaken the already-rendered block.
            pass
    if current_adapter == "bash" and (
        sink_payload_shadow_enabled or sink_payload_exact_enforcement_enabled
    ):
        inspection_failed = False
        try:
            payload_evidence = _inspect_bash_sink_payload(
                current_event=current_event,
                runtime_result=runtime_result,
                current_sinks=tuple(current_sinks),
            )
        except Exception:
            # Exact enforcement must fail closed below. Shadow-only mode keeps
            # its observation semantics and never changes the baseline action.
            payload_evidence = ()
            inspection_failed = True
        if pilot_facts is not None and payload_evidence:
            if all(item.resolution_status == "evaluated" for item in payload_evidence):
                pilot_facts.resolution = (
                    PayloadResolution.FILE
                    if any(item.extraction == "resolved_file" for item in payload_evidence)
                    else PayloadResolution.DIRECT
                )
        if sink_payload_shadow_enabled:
            try:
                _store_bash_sink_payload_shadow(
                    store,
                    evidence=payload_evidence,
                    current_event=current_event,
                    runtime_result=runtime_result,
                    baseline_action=(
                        selected.action if selected is not None else "allow"
                    ),
                )
            except Exception:
                # Observation must never change the already-rendered policy output.
                pass
        if sink_payload_exact_enforcement_enabled:
            protected_source_node_ids = tuple(
                chunk.chunk_id for chunk in runtime_result.source_chunks
            )
            if inspection_failed or (
                not payload_evidence
                and any(
                    sink.sink_type == "external_http_request"
                    and sink.metadata.get("matched_program") == "curl"
                    for sink in current_sinks
                )
            ):
                exact_decisions = build_unresolved_external_payload_decisions(
                    sink_candidates=tuple(current_sinks),
                    analysis_run_id=runtime_result.analysis_run.analysis_run_id,
                    protected_source_node_ids=protected_source_node_ids,
                    reason=(
                        "payload_inspection_error"
                        if inspection_failed
                        else "payload_evidence_missing"
                    ),
                )
            else:
                exact_decisions = build_exact_file_payload_decisions(
                    payload_evidence,
                    sink_candidates=tuple(current_sinks),
                    analysis_run_id=runtime_result.analysis_run.analysis_run_id,
                    protected_source_node_ids=protected_source_node_ids,
                )
            exact_decisions.extend(
                build_unverified_external_sink_decisions(
                    sink_candidates=tuple(current_sinks),
                    analysis_run_id=runtime_result.analysis_run.analysis_run_id,
                    protected_source_node_ids=protected_source_node_ids,
                    verified_sink_node_ids=_verified_external_sink_ids(
                        payload_evidence,
                        tuple(current_sinks),
                        tuple(exact_decisions),
                    ),
                )
            )
            exact_selected = select_strongest_decision(
                exact_decisions,
                "PreToolUse",
            )
            if exact_selected is not None and exact_selected.action == "block":
                if pilot_facts is not None:
                    pilot_facts.selected(exact_selected)
                try:
                    store_policy_decision(
                        store,
                        exact_selected,
                        runtime_result.analysis_run.analysis_run_id,
                    )
                except Exception:
                    # Exact evidence has already been established; audit failure
                    # must not allow the external side effect.
                    pass
                return render_codex_hook_output(
                    exact_selected,
                    "PreToolUse",
                    db_path=store.db_path,
                    analysis_run_id=runtime_result.analysis_run.analysis_run_id,
                )
    if (
        sink_payload_exact_enforcement_enabled
        and current_adapter == "mcp"
        and runtime_result.source_chunks
    ):
        try:
            verification = verify_mcp_payload_against_sources(
                current_event.raw_payload.get("tool_input"),
                runtime_result.source_chunks,
            )
        except Exception:
            verified_sink_node_ids = frozenset()
        else:
            if pilot_facts is not None and verification.status == "safe":
                pilot_facts.resolution = PayloadResolution.DIRECT
                pilot_facts.evidence = EvidenceSource.DIRECT
            verified_sink_node_ids = (
                frozenset(
                    sink.node_id
                    for sink in current_sinks
                    if sink.sink_type.startswith("external_")
                )
                if verification.status == "safe"
                else frozenset()
            )
        conservative_decisions = build_unverified_external_sink_decisions(
            sink_candidates=tuple(current_sinks),
            analysis_run_id=runtime_result.analysis_run.analysis_run_id,
            protected_source_node_ids=tuple(
                chunk.chunk_id for chunk in runtime_result.source_chunks
            ),
            verified_sink_node_ids=verified_sink_node_ids,
        )
        conservative_selected = select_strongest_decision(
            conservative_decisions,
            "PreToolUse",
        )
        if conservative_selected is not None:
            if pilot_facts is not None:
                pilot_facts.selected(conservative_selected)
            try:
                store_policy_decision(
                    store,
                    conservative_selected,
                    runtime_result.analysis_run.analysis_run_id,
                )
            except Exception:
                pass
            return render_codex_hook_output(
                conservative_selected,
                "PreToolUse",
                db_path=store.db_path,
                analysis_run_id=runtime_result.analysis_run.analysis_run_id,
            )
    if (
        sink_payload_exact_enforcement_enabled
        and current_adapter == "function"
        and runtime_result.source_chunks
    ):
        conservative_decisions = build_unverified_external_sink_decisions(
            sink_candidates=tuple(current_sinks),
            analysis_run_id=runtime_result.analysis_run.analysis_run_id,
            protected_source_node_ids=tuple(
                chunk.chunk_id for chunk in runtime_result.source_chunks
            ),
            verified_sink_node_ids=frozenset(),
        )
        conservative_selected = select_strongest_decision(
            conservative_decisions,
            "PreToolUse",
        )
        if (
            conservative_selected is not None
            and conservative_selected.action == "block"
        ):
            if pilot_facts is not None:
                pilot_facts.selected(conservative_selected)
            try:
                store_policy_decision(
                    store,
                    conservative_selected,
                    runtime_result.analysis_run.analysis_run_id,
                )
            except Exception:
                pass
            return render_codex_hook_output(
                conservative_selected,
                "PreToolUse",
                db_path=store.db_path,
                analysis_run_id=runtime_result.analysis_run.analysis_run_id,
            )
    return hook_output


def _verified_external_sink_ids(
    payload_evidence: tuple[BashSinkPayloadEvidence, ...],
    current_sinks: tuple[SinkCandidate, ...],
    exact_decisions: tuple[PolicyDecision, ...],
) -> frozenset[str]:
    direct_ids = {item.sink_node_id for item in payload_evidence}
    direct_ids.update(
        decision.sink_node_id for decision in exact_decisions
    )
    verified_fragment_ids = {
        sink.metadata.get("command_fragment_id")
        for sink in current_sinks
        if sink.node_id in direct_ids
        and isinstance(sink.metadata.get("command_fragment_id"), str)
    }
    return frozenset(
        sink.node_id
        for sink in current_sinks
        if sink.node_id in direct_ids
        or (
            sink.metadata.get("basis") == "static_external"
            and sink.metadata.get("command_fragment_id") in verified_fragment_ids
        )
    )


def _externality_policy_risk(
    current_event: NormalizedEvent,
    *,
    current_adapter: str,
    decision: ExternalityHookDecision | None,
) -> ExternalityPolicyRisk | None:
    if decision is None:
        return None
    if decision.state == "known_external":
        return ExternalityPolicyRisk(
            event_id=current_event.event_id,
            adapter=current_adapter,
            envelope_sha256=decision.envelope_sha256,
            verdict="external",
            basis="static_external",
        )
    if decision.state == "queued":
        return ExternalityPolicyRisk(
            event_id=current_event.event_id,
            adapter=current_adapter,
            envelope_sha256=decision.envelope_sha256,
            verdict="unknown",
            basis="unknown_pending",
        )
    if decision.state == "analysis_failed":
        return ExternalityPolicyRisk(
            event_id=current_event.event_id,
            adapter=current_adapter,
            envelope_sha256=decision.envelope_sha256,
            verdict="unknown",
            basis="analysis_failed",
        )
    if (
        decision.state == "cache_hit"
        and decision.rule is not None
        and decision.rule.adds_external_sink
    ):
        return ExternalityPolicyRisk(
            event_id=current_event.event_id,
            adapter=current_adapter,
            envelope_sha256=decision.envelope_sha256,
            verdict=decision.rule.verdict,
            basis="approved_rule",
            review_revision=decision.rule.review_revision,
        )
    return None


def _store_mcp_redaction_preview(
    store: EventStore,
    *,
    current_event: NormalizedEvent,
    current_sequence_no: int,
    analysis_run: AnalysisRun,
    current_sinks: tuple[SinkCandidate, ...],
    current_critical_findings: tuple[LeakFinding, ...],
) -> None:
    source_chunks = {}
    if (
        len(current_critical_findings)
        <= DEFAULT_REDACTION_PREVIEW_LIMITS.max_critical_findings
    ):
        source_ids = tuple(
            sorted(
                {
                    finding.source_node_id
                    for finding in current_critical_findings
                    if finding.source_node_kind == "source_chunk"
                }
            )
        )
        chunks = store.list_source_chunks_for_workspace_ids(
            current_event.workspace_id or "",
            source_ids,
            max_ids=DEFAULT_REDACTION_PREVIEW_LIMITS.max_critical_findings,
            max_bytes_per_chunk=(
                DEFAULT_REDACTION_PREVIEW_LIMITS.max_source_bytes_per_finding
            ),
            max_bytes_total=(
                DEFAULT_REDACTION_PREVIEW_LIMITS.max_source_bytes_total
            ),
        )
        source_chunks = {
            (chunk.workspace_id or "", chunk.chunk_id): chunk for chunk in chunks
        }
    result = plan_mcp_redaction_preview(
        current_event=current_event,
        current_sequence_no=current_sequence_no,
        analysis_run=analysis_run,
        current_sinks=current_sinks,
        current_critical_findings=current_critical_findings,
        source_chunks=source_chunks,
    )
    if result.plan is not None:
        store_redaction_preview_plan(store, result.plan)


def _current_external_sinks(
    sinks: list[SinkCandidate],
    current_event: NormalizedEvent,
    current_sequence_no: int,
    current_adapter: str,
) -> list[SinkCandidate]:
    return [
        sink
        for sink in sinks
        if sink.sink_type.startswith("external_")
        and sink.sequence_no == current_sequence_no
        and sink.workspace_id == current_event.workspace_id
        and sink.session_id == current_event.session_id
        and sink.metadata.get("adapter") == current_adapter
        and sink.metadata.get("event_id") == current_event.event_id
        and (
            current_event.tool_use_id is None
            or sink.tool_use_id == current_event.tool_use_id
        )
    ]


def _inspect_bash_sink_payload(
    *,
    current_event: NormalizedEvent,
    runtime_result: RuntimeAnalysisResult,
    current_sinks: tuple[SinkCandidate, ...],
) -> tuple[BashSinkPayloadEvidence, ...]:
    tool_input = current_event.raw_payload.get("tool_input")
    if not isinstance(tool_input, dict):
        return ()
    command = shell_command_from_input(current_event.tool_name, tool_input)
    if command is None:
        return ()
    if (
        current_event.workspace_root is None
        or current_event.workspace_execution_cwd is None
        or current_event.workspace_id is None
        or current_event.session_id is None
    ):
        return ()
    current_http_sinks = tuple(
        sink
        for sink in current_sinks
        if sink.sink_type == "external_http_request"
        and sink.metadata.get("matched_program") == "curl"
    )
    sink_node_ids_by_segment: dict[int, str] = {}
    for sink in current_http_sinks:
        segment_index = sink.metadata.get("segment_index")
        if type(segment_index) is not int or segment_index < 0:
            raise ValueError("current curl sink has no segment identity")
        if segment_index in sink_node_ids_by_segment:
            raise ValueError("current curl segment has multiple sink identities")
        sink_node_ids_by_segment[segment_index] = sink.node_id
    if not sink_node_ids_by_segment:
        return ()
    return inspect_bash_sink_payload_evidence(
        command,
        workspace_root=Path(current_event.workspace_root),
        execution_cwd=Path(current_event.workspace_execution_cwd),
        workspace_id=current_event.workspace_id,
        sink_node_ids_by_segment=sink_node_ids_by_segment,
        source_chunks=runtime_result.source_chunks,
    )


def _store_bash_sink_payload_shadow(
    store: EventStore,
    *,
    evidence: tuple[BashSinkPayloadEvidence, ...],
    current_event: NormalizedEvent,
    runtime_result: RuntimeAnalysisResult,
    baseline_action: str,
) -> None:
    observations = tuple(
        observation
        for item in evidence
        if (
            observation := build_sink_payload_shadow_observation(
                item,
                pre_event_id=current_event.event_id,
                analysis_run_id=runtime_result.analysis_run.analysis_run_id,
                session_id=current_event.session_id,
                tool_use_id=current_event.tool_use_id,
                baseline_action=baseline_action,
            )
        )
        is not None
    )
    store_sink_payload_shadow_observations(store.db_path, observations)
