from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

from hook_monitor.analysis.adapters.mcp import (
    classify_mcp_sink_type,
    parse_mcp_tool_name,
)
from hook_monitor.analysis.adapters.mcp_profiles import MCP_TOOL_NAME_MAX_BYTES
from hook_monitor.runtime.parser import (
    HookPayloadError,
    HookPayloadLimitError,
    build_artifacts,
    build_fragments,
    inspect_top_level_json_strings,
    json_nesting_exceeds_limit,
    normalize_event,
    parse_hook_payload,
)
from hook_monitor.runtime.operations import extract_tool_operations
from hook_monitor.runtime.models import NormalizedEvent, ResourceSnapshot, ToolOperation
from hook_monitor.runtime.pre_tool_policy import (
    evaluate_pre_tool_input_bounds,
    evaluate_pre_tool_hook_policy,
    pre_tool_adapter,
    render_mcp_input_limit_deny,
)
from hook_monitor.runtime.externality_rules import (
    classify_static_externality_hook_analysis,
    conservative_function_tool_decision,
    failed_externality_hook_decision,
    prepare_externality_hook_decision,
)
from hook_monitor.runtime.settings import (
    EXTERNALITY_PROTECTION_KEY,
    FILE_PAYLOAD_EXACT_ENFORCEMENT_KEY,
    FILE_PAYLOAD_SHADOW_KEY,
    PRE_TOOL_POLICY_KEY,
    EffectiveRuntimeSettings,
    empty_workspace_runtime_settings,
    resolve_effective_runtime_settings,
)
from hook_monitor.runtime.storage import EventStore, SchemaCompatibilityError
from hook_monitor.runtime.snapshot_capture import (
    capture_operation_snapshots,
    limits_from_environment,
    plaintext_snapshots_enabled,
)
from hook_monitor.runtime.stop_policy import evaluate_stop_hook_policy
from hook_monitor.runtime.tool_outcome import ToolOutcome, classify_post_tool_outcome
from hook_monitor.runtime.workspace import WORKSPACE_ROOT_ENV, WorkspaceContext, resolve_workspace
from tooluseproxy.paths import resolve_runtime_paths

PRE_TOOL_RAW_JSON_MAX_BYTES = 1024 * 1024
PRE_TOOL_RAW_JSON_MAX_DEPTH = 64
PRE_TOOL_RAW_JSON_MAX_NUMBER_CHARS = 128
PRE_TOOL_ENVELOPE_STRING_MAX_BYTES = MCP_TOOL_NAME_MAX_BYTES
PRE_TOOL_ENVELOPE_KEYS = frozenset({"cwd", "tool_name"})


def run_hook(
    phase: str,
    *,
    db_path: Path | None = None,
    allow_schema_migration: bool = True,
) -> int:
    resolved_db_path = db_path if db_path is not None else _resolve_db_path()
    store = EventStore(resolved_db_path)
    if not allow_schema_migration:
        try:
            store.require_runtime_schema()
        except SchemaCompatibilityError as exc:
            print(
                json.dumps(
                    inactive_hook_output(
                        phase,
                        _schema_inactive_message(exc),
                        deny_pre_tool=(
                            phase == "pre_tool_use"
                            and exc.code != "database_missing"
                        ),
                    ),
                    ensure_ascii=False,
                )
            )
            return 0
    bounded_pre_tool_input = phase == "pre_tool_use"
    raw_payload = sys.stdin.buffer.read(
        PRE_TOOL_RAW_JSON_MAX_BYTES + 1
        if bounded_pre_tool_input
        else -1
    )
    raw_mcp_tool_name: str | None = None
    raw_mcp_workspace: WorkspaceContext | None = None
    if bounded_pre_tool_input:
        envelope, oversized_envelope = inspect_top_level_json_strings(
            raw_payload,
            PRE_TOOL_ENVELOPE_KEYS,
            max_value_bytes=PRE_TOOL_ENVELOPE_STRING_MAX_BYTES,
        )
        candidate_tool_name = envelope.get("tool_name")
        if parse_mcp_tool_name(candidate_tool_name) is not None:
            raw_mcp_tool_name = candidate_tool_name
            configured_root = _configured_workspace_root(
                envelope.get("cwd"),
                resolved_db_path,
            )
            raw_mcp_workspace = resolve_workspace(
                envelope.get("cwd"),
                configured_root,
                discovered_by=(
                    "registered_root"
                    if configured_root is not None
                    and os.environ.get(WORKSPACE_ROOT_ENV) is None
                    else None
                ),
            )
        elif oversized_envelope.get("tool_name", "").lower().startswith(
            "mcp__"
        ):
            configured_root = _configured_workspace_root(
                envelope.get("cwd"),
                resolved_db_path,
            )
            raw_mcp_workspace = resolve_workspace(
                envelope.get("cwd"),
                configured_root,
            )
            if envelope.get("cwd") is None and configured_root is not None:
                # Real Codex orders tool_name before cwd. If an anomalous name
                # itself crosses the bounded read, validate the explicitly
                # configured root as the narrow rejection scope rather than
                # treating the unread later cwd as an unscoped allow.
                raw_mcp_workspace = resolve_workspace(
                    configured_root,
                    configured_root,
                )
            _render_scoped_raw_mcp_rejection(
                raw_mcp_workspace,
                "tool_name_bytes_exceeded",
            )
            return 0

        if len(raw_payload) > PRE_TOOL_RAW_JSON_MAX_BYTES:
            if raw_mcp_tool_name is not None:
                _render_raw_mcp_rejection(
                    raw_mcp_tool_name,
                    raw_mcp_workspace,
                    "json_envelope_bytes_exceeded",
                )
                return 0
            if candidate_tool_name is None:
                _emit_pre_tool_safety_stop("hook_payload_too_large")
                return 0
            # A known non-MCP call is outside this gate and keeps its prior path.
            raw_payload += sys.stdin.buffer.read()
        elif raw_mcp_tool_name is not None and json_nesting_exceeds_limit(
            raw_payload,
            PRE_TOOL_RAW_JSON_MAX_DEPTH,
        ):
            _render_raw_mcp_rejection(
                raw_mcp_tool_name,
                raw_mcp_workspace,
                "json_envelope_nesting_exceeded",
            )
            return 0
    try:
        payload = parse_hook_payload(
            raw_payload,
            max_number_chars=(
                PRE_TOOL_RAW_JSON_MAX_NUMBER_CHARS
                if raw_mcp_tool_name is not None
                else None
            ),
        )
    except HookPayloadLimitError as exc:
        assert raw_mcp_tool_name is not None
        _render_raw_mcp_rejection(
            raw_mcp_tool_name,
            raw_mcp_workspace,
            exc.rejection_code,
        )
        return 0
    except HookPayloadError:
        if phase == "pre_tool_use":
            _emit_pre_tool_safety_stop("hook_payload_invalid")
        else:
            _emit_inactive_hook_output(
                phase,
                "hook_payload_invalid",
                "Codex supplied a Hook payload that ToolUseProxy could not parse",
            )
        return 0

    payload_cwd = payload.get("cwd")
    configured_root = _configured_workspace_root(
        payload_cwd if isinstance(payload_cwd, str) else None,
        resolved_db_path,
    )
    event = normalize_event(
        phase,
        payload,
        workspace_root=configured_root,
        workspace_discovered_by=(
            "registered_root"
            if configured_root is not None
            and os.environ.get(WORKSPACE_ROOT_ENV) is None
            else None
        ),
    )
    if phase == "pre_tool_use":
        if event.session_id is None:
            _emit_pre_tool_safety_stop("session_identity_missing")
            return 0
        if not isinstance(event.tool_name, str) or not event.tool_name.strip():
            _emit_pre_tool_safety_stop("tool_identity_missing")
            return 0
        if not _runtime_policy_workspace_enabled(event):
            _emit_pre_tool_safety_stop("workspace_identity_unavailable")
            return 0
    early_pre_tool_adapters = _enabled_pre_tool_adapters(
        resolve_effective_runtime_settings(
            empty_workspace_runtime_settings(
                event.workspace_id or "unregistered"
            ),
            os.environ,
        )
    )
    event_pre_tool_adapter = pre_tool_adapter(event.tool_name)
    if (
        phase == "pre_tool_use"
        and event_pre_tool_adapter == "mcp"
        and event_pre_tool_adapter in early_pre_tool_adapters
        and _runtime_policy_workspace_enabled(event)
    ):
        bounded_input_guard = evaluate_pre_tool_input_bounds(
            event,
            enabled_adapters=early_pre_tool_adapters,
        )
        if bounded_input_guard.disposition == "deny":
            print(json.dumps(bounded_input_guard.hook_output, ensure_ascii=False))
            return 0
        if bounded_input_guard.disposition == "bypass":
            return 0
    if allow_schema_migration:
        store.initialize()
    try:
        effective_runtime_settings = _effective_runtime_settings(store, event)
    except Exception:  # pragma: no cover - defensive hook boundary
        if phase == "pre_tool_use":
            _emit_pre_tool_safety_stop("runtime_settings_failed")
        else:
            _emit_inactive_hook_output(
                phase,
                "runtime_settings_failed",
                "workspace runtime settings could not be loaded",
            )
        return 0
    enabled_pre_tool_adapters = _enabled_pre_tool_adapters(
        effective_runtime_settings
    )
    if (
        phase == "pre_tool_use"
        and event_pre_tool_adapter in enabled_pre_tool_adapters
        and event_pre_tool_adapter != "mcp"
        and _runtime_policy_workspace_enabled(event)
    ):
        bounded_input_guard = evaluate_pre_tool_input_bounds(
            event,
            enabled_adapters=enabled_pre_tool_adapters,
        )
        if bounded_input_guard.disposition == "deny":
            print(json.dumps(bounded_input_guard.hook_output, ensure_ascii=False))
            return 0
        if bounded_input_guard.disposition == "bypass":
            return 0

    artifacts = build_artifacts(event)
    fragments = build_fragments(artifacts)
    extraction = extract_tool_operations(event, artifacts, fragments)
    fragments.extend(extraction.fragments)

    post_outcome: ToolOutcome | None = None
    post_snapshots: list[ResourceSnapshot] = []
    post_operation_ids: tuple[str, ...] = ()
    post_diagnostic: tuple[str, str] | None = None
    if phase == "post_tool_use":
        try:
            (
                post_outcome,
                post_snapshots,
                post_operation_ids,
                post_diagnostic,
            ) = _prepare_post_tool_evidence(store, event)
        except Exception:  # pragma: no cover - defensive hook boundary
            _emit_inactive_hook_output(
                phase,
                "post_tool_snapshot_failed",
                "post-tool evidence could not be prepared",
            )
            return 0
    store.record(
        event,
        artifacts,
        fragments,
        list(extraction.operations),
        post_outcome=(
            None
            if post_outcome is None or not post_operation_ids
            else (post_outcome.status, post_outcome.evidence)
        ),
        post_operation_ids=post_operation_ids,
        resource_snapshots=post_snapshots,
    )
    externality_decision = None
    recovery_externality_decision = None
    static_externality_analysis = None
    if (
        phase == "pre_tool_use"
        and event_pre_tool_adapter in {"bash", "mcp"}
        and event_pre_tool_adapter in enabled_pre_tool_adapters
        and _runtime_policy_workspace_enabled(event)
    ):
        try:
            static_externality_analysis = classify_static_externality_hook_analysis(
                event,
                workspace_root=Path(event.workspace_root or ""),
                trusted_plugin_root=(
                    Path(os.environ["PLUGIN_ROOT"])
                    if os.environ.get("PLUGIN_ROOT")
                    else None
                ),
                plugin_data=store.db_path.parent,
            )
            recovery_externality_decision = static_externality_analysis[0]
        except Exception:
            recovery_externality_decision = failed_externality_hook_decision()
    if phase == "pre_tool_use" and event_pre_tool_adapter == "function":
        externality_decision = conservative_function_tool_decision(event.tool_name)
    elif (
        phase == "pre_tool_use"
        and effective_runtime_settings.enabled(EXTERNALITY_PROTECTION_KEY)
        and _runtime_policy_workspace_enabled(event)
    ):
        try:
            externality_decision = prepare_externality_hook_decision(
                store.db_path,
                event,
                workspace_root=Path(event.workspace_root or ""),
                trusted_plugin_root=(
                    Path(os.environ["PLUGIN_ROOT"])
                    if os.environ.get("PLUGIN_ROOT")
                    else None
                ),
                static_analysis=static_externality_analysis,
            )
        except Exception:
            # Preserve a value-free conservative sink when queue/cache/static
            # preparation fails. The existing policy still decides based on
            # whether protected lineage reaches that sink.
            externality_decision = failed_externality_hook_decision()
    if phase == "post_tool_use":
        try:
            store.confirm_redaction_post_input(event)
        except Exception:  # pragma: no cover - defensive hook boundary
            post_diagnostic = (
                "post_redaction_confirmation_failed",
                "post-tool redaction confirmation could not be recorded",
            )
        if post_diagnostic is not None:
            _emit_inactive_hook_output(
                phase,
                post_diagnostic[0],
                post_diagnostic[1],
            )
            return 0
    if phase == "pre_tool_use" and pre_tool_adapter(
        event.tool_name
    ) in enabled_pre_tool_adapters:
        if not _runtime_policy_workspace_enabled(event):
            return 0
        try:
            hook_output = evaluate_pre_tool_hook_policy(
                store,
                Path(event.workspace_root or ""),
                current_event=event,
                enabled_adapters=enabled_pre_tool_adapters,
                sink_payload_shadow_enabled=effective_runtime_settings.enabled(
                    FILE_PAYLOAD_SHADOW_KEY
                ),
                sink_payload_exact_enforcement_enabled=(
                    effective_runtime_settings.enabled(
                        FILE_PAYLOAD_EXACT_ENFORCEMENT_KEY
                    )
                ),
                externality_decision=externality_decision,
                recovery_externality_decision=recovery_externality_decision,
            )
        except Exception:  # pragma: no cover - defensive hook boundary
            _emit_pre_tool_safety_stop("pre_tool_policy_failed")
            return 0
        if hook_output:
            print(json.dumps(hook_output, ensure_ascii=False))
        return 0
    if phase == "stop" and _stop_policy_enabled():
        if not _runtime_policy_workspace_enabled(event):
            return 0
        try:
            hook_output = evaluate_stop_hook_policy(
                store,
                Path(event.workspace_root or ""),
                current_event_id=event.event_id,
            )
        except Exception:  # pragma: no cover - defensive hook boundary
            _emit_inactive_hook_output(
                phase,
                "stop_policy_failed",
                "Stop policy evaluation could not be completed",
            )
            return 0
        if hook_output:
            print(json.dumps(hook_output, ensure_ascii=False))
    return 0


def _resolve_db_path() -> Path:
    return resolve_runtime_paths().db_path


def _configured_workspace_root(cwd: str | None, db_path: Path) -> str | None:
    explicit_root = os.environ.get(WORKSPACE_ROOT_ENV)
    if explicit_root is not None:
        return explicit_root
    registered_root = EventStore(db_path).find_registered_workspace_root(cwd)
    if registered_root is None:
        return None
    direct_workspace = resolve_workspace(cwd)
    if direct_workspace.canonical_root == registered_root:
        # Keep the historical event identity when Codex already reports the
        # registered root as cwd. Registration is only needed for nested cwd.
        return None
    return registered_root


def _stop_policy_enabled() -> bool:
    configured = os.environ.get("TOOLUSEPROXY_STOP_POLICY", "1")
    return configured.lower() not in {"0", "false", "no", "off"}


def _effective_runtime_settings(
    store: EventStore,
    event: NormalizedEvent,
) -> EffectiveRuntimeSettings:
    workspace_id = event.workspace_id
    if workspace_id is None:
        return resolve_effective_runtime_settings(
            empty_workspace_runtime_settings("unregistered"),
            os.environ,
        )
    state = store.get_workspace_runtime_settings(
        workspace_id,
        busy_timeout_ms=10,
    )
    return resolve_effective_runtime_settings(state, os.environ)


def _enabled_pre_tool_adapters(
    settings: EffectiveRuntimeSettings,
) -> frozenset[str]:
    if not settings.enabled(PRE_TOOL_POLICY_KEY):
        return frozenset()
    return frozenset({"bash", "mcp", "function"})


def _inactive_message(code: str) -> str:
    messages = {
        "database_missing": (
            "ToolUseProxyはこのプロジェクトではまだ準備されていません。"
        ),
        "schema_upgrade_required": (
            "ToolUseProxyの保存データを更新する必要があります。"
        ),
        "database_unreadable": (
            "ToolUseProxyの保存データを読み取れないため、保護機能は動作していません。"
        ),
        "schema_too_new": (
            "保存データがこのToolUseProxyより新しいため、保護機能は動作していません。"
        ),
        "schema_incomplete": (
            "ToolUseProxyの保存データが不完全なため、保護機能は動作していません。"
        ),
        "plugin_environment": (
            "ToolUseProxy Pluginの設定を読み込めないため、保護機能は動作していません。"
        ),
        "python_missing": (
            "Python 3.11または3.12が見つからないため、ToolUseProxyの保護機能は動作していません。"
        ),
        "runtime_start_failed": (
            "ToolUseProxyを開始できなかったため、保護機能は動作していません。"
        ),
    }
    message = messages.get(
        code,
        "ToolUseProxyを安全に開始できないため、保護機能は動作していません。",
    )
    return f"{message}（技術情報: {code}）"


def _schema_inactive_message(exc: SchemaCompatibilityError) -> str:
    return (
        f"{_inactive_message(exc.code)}\n"
        "Codexに「ToolUseProxyをこのプロジェクトで使えるようにして」"
        "と依頼してください。"
    )


def inactive_hook_output(
    phase: str,
    message: str,
    *,
    deny_pre_tool: bool = False,
) -> dict[str, object]:
    if phase == "pre_tool_use":
        hook_output: dict[str, object] = {
            "hookEventName": "PreToolUse",
            "additionalContext": message,
        }
        if deny_pre_tool:
            hook_output.update(
                {
                    "permissionDecision": "deny",
                    "permissionDecisionReason": (
                        "ToolUseProxyが操作を実行前に止めました。保護判定を"
                        "安全に完了できなかったため、この操作を許可できません。"
                        "ToolUseProxyの診断を行ってからやり直してください。\n"
                        "結果：外部操作は実行されていません。保護対象の内容も"
                        "表示していません。"
                    ),
                }
            )
        return {"hookSpecificOutput": hook_output}
    if phase == "post_tool_use":
        return {
            "hookSpecificOutput": {
                "hookEventName": "PostToolUse",
                "additionalContext": message,
            }
        }
    if phase == "stop":
        return {"systemMessage": message}
    raise ValueError(f"unsupported Codex hook phase: {phase}")


def _emit_inactive_hook_output(
    phase: str,
    code: str,
    detail: str,
) -> None:
    del detail
    message = _inactive_message(code)
    print(
        json.dumps(
            inactive_hook_output(phase, message),
            ensure_ascii=False,
        )
    )


def _emit_pre_tool_safety_stop(code: str) -> None:
    print(
        json.dumps(
            inactive_hook_output(
                "pre_tool_use",
                _inactive_message(code),
                deny_pre_tool=True,
            ),
            ensure_ascii=False,
        )
    )


def _runtime_policy_workspace_enabled(event: NormalizedEvent) -> bool:
    return (
        event.workspace_status == "ready"
        and event.workspace_id is not None
        and event.workspace_root is not None
        and event.workspace_execution_cwd is not None
    )


def _render_raw_mcp_rejection(
    tool_name: str,
    workspace: WorkspaceContext | None,
    rejection_code: str,
) -> None:
    if workspace is None or not workspace.ready:
        return
    if classify_mcp_sink_type(tool_name, {}) is None:
        return
    _render_scoped_raw_mcp_rejection(workspace, rejection_code)


def _render_scoped_raw_mcp_rejection(
    workspace: WorkspaceContext | None,
    rejection_code: str,
) -> None:
    if workspace is None or not workspace.ready:
        return
    print(
        json.dumps(
            render_mcp_input_limit_deny(rejection_code),
            ensure_ascii=False,
        )
    )


def _capture_post_tool_evidence(
    store: EventStore,
    event: NormalizedEvent,
) -> None:
    outcome, snapshots, operation_ids, diagnostic = _prepare_post_tool_evidence(
        store,
        event,
    )
    if outcome is None or not operation_ids:
        return
    store.update_tool_operation_outcome(
        event,
        operation_ids,
        outcome=outcome.status,
        evidence=outcome.evidence,
        resource_snapshots=snapshots,
    )
    if diagnostic is not None:
        print(
            _inactive_message(diagnostic[0]),
            file=sys.stderr,
        )


def _prepare_post_tool_evidence(
    store: EventStore,
    event: NormalizedEvent,
) -> tuple[
    ToolOutcome | None,
    list[ResourceSnapshot],
    tuple[str, ...],
    tuple[str, str] | None,
]:
    if event.workspace_status != "ready":
        return None, [], (), None
    operations = store.list_tool_operations_for_post_event(event)
    if not operations:
        return None, [], (), None
    outcome = classify_post_tool_outcome(event)
    owner_matches = _validated_operation_owner(
        store,
        event,
        operations,
    )
    if not owner_matches:
        return (
            ToolOutcome("unknown", "post_operation_owner_mismatch"),
            [],
            (),
            None,
        )
    operation_ids = tuple(sorted(operation.operation_id for operation in operations))
    if outcome.status != "succeeded":
        return outcome, [], operation_ids, None
    try:
        snapshots = capture_operation_snapshots(
            event,
            operations,
            limits=limits_from_environment(),
            store_plaintext=plaintext_snapshots_enabled(),
        )
    except Exception as exc:  # pragma: no cover - defensive capture boundary
        return (
            ToolOutcome(
                outcome.status,
                (
                    f"{outcome.evidence};"
                    f"snapshot_capture_error:{type(exc).__name__}"
                ),
            ),
            [],
            operation_ids,
            (
                "post_tool_snapshot_failed",
                "post-tool evidence could not be prepared",
            ),
        )
    return outcome, snapshots, operation_ids, None


def _validated_operation_owner(
    store: EventStore,
    event: NormalizedEvent,
    operations: list[ToolOperation],
) -> bool:
    owner_event_ids = {operation.event_id for operation in operations}
    if len(owner_event_ids) != 1:
        return False
    owner_contexts = store.list_event_execution_contexts(
        owner_event_ids
    )
    if len(owner_contexts) != 1:
        return False
    identities = set(owner_contexts.values())
    if len(identities) != 1:
        return False
    phase, session_id, tool_use_id, tool_name, _owner_cwd = identities.pop()
    owner_workspace = store.get_event_workspace_context(next(iter(owner_event_ids)))
    if (
        phase != "pre_tool_use"
        or session_id != event.session_id
        or tool_use_id != event.tool_use_id
        or _normalized_tool_name(tool_name) != _normalized_tool_name(event.tool_name)
        or not owner_workspace.ready
        or owner_workspace.workspace_id != event.workspace_id
        or owner_workspace.canonical_root != event.workspace_root
        or owner_workspace.execution_cwd != event.workspace_execution_cwd
    ):
        return False
    if any(
        operation.session_id != session_id
        or operation.tool_use_id != tool_use_id
        or _normalized_tool_name(operation.tool_name) != _normalized_tool_name(tool_name)
        for operation in operations
    ):
        return False
    return True


def _normalized_tool_name(tool_name: str | None) -> str | None:
    if not tool_name:
        return None
    normalized = re.sub(r"[^a-z0-9]+", "_", tool_name.casefold()).strip("_")
    return normalized or None
