from __future__ import annotations

import json
import os
import re
import shlex
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
                _schema_inactive_message(exc),
                file=sys.stderr,
            )
            return 0
    bounded_pre_tool_input = (
        phase == "pre_tool_use"
        and _pre_tool_policy_enabled()
        and _pre_tool_mcp_policy_enabled()
    )
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
                # The bounded prefix cannot prove which adapter owns the call.
                # Preserve the Hook fail-open contract without materializing it.
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
    except HookPayloadError as exc:
        print(str(exc), file=sys.stderr)
        return 1

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
    enabled_pre_tool_adapters = _enabled_pre_tool_adapters()
    if (
        phase == "pre_tool_use"
        and pre_tool_adapter(event.tool_name) in enabled_pre_tool_adapters
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

    if allow_schema_migration:
        store.initialize()
    post_outcome: ToolOutcome | None = None
    post_snapshots: list[ResourceSnapshot] = []
    post_operation_ids: tuple[str, ...] = ()
    if phase == "post_tool_use":
        try:
            (
                post_outcome,
                post_snapshots,
                post_operation_ids,
            ) = _prepare_post_tool_evidence(store, event)
        except Exception as exc:  # pragma: no cover - defensive hook boundary
            _report_policy_failure("post-tool snapshot", exc)
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
    if phase == "post_tool_use":
        try:
            store.confirm_redaction_post_input(event)
        except Exception as exc:  # pragma: no cover - defensive hook boundary
            _report_policy_failure("post-redaction confirmation", exc)
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
                sink_payload_shadow_enabled=_sink_payload_shadow_enabled(),
            )
        except Exception as exc:  # pragma: no cover - defensive hook boundary
            _report_policy_failure("pre-tool", exc)
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
        except Exception as exc:  # pragma: no cover - defensive hook boundary
            _report_policy_failure("stop", exc)
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


def _pre_tool_policy_enabled() -> bool:
    configured = os.environ.get("TOOLUSEPROXY_PRE_TOOL_POLICY", "0")
    return configured.lower() in {"1", "true", "yes", "on"}


def _pre_tool_mcp_policy_enabled() -> bool:
    configured = os.environ.get("TOOLUSEPROXY_PRE_TOOL_MCP_POLICY", "0")
    return configured.lower() in {"1", "true", "yes", "on"}


def _sink_payload_shadow_enabled() -> bool:
    configured = os.environ.get(
        "TOOLUSEPROXY_PRE_TOOL_FILE_PAYLOAD_SHADOW",
        "0",
    )
    return configured.lower() in {"1", "true", "yes", "on"}


def _enabled_pre_tool_adapters() -> frozenset[str]:
    if not _pre_tool_policy_enabled():
        return frozenset()
    adapters = {"bash"}
    if _pre_tool_mcp_policy_enabled():
        adapters.add("mcp")
    return frozenset(adapters)


def _report_policy_failure(policy_name: str, exc: Exception) -> None:
    print(
        f"{policy_name} policy evaluation failed: {type(exc).__name__}",
        file=sys.stderr,
    )


def _schema_inactive_message(exc: SchemaCompatibilityError) -> str:
    message = f"ToolUseProxy inactive ({exc.code}): {exc}"
    if exc.code not in {"database_missing", "schema_upgrade_required"}:
        return message
    plugin_root = os.environ.get("PLUGIN_ROOT")
    plugin_data = os.environ.get("PLUGIN_DATA")
    if not plugin_root or not plugin_data:
        return message
    if os.name == "nt":
        launcher = Path(plugin_root) / "hooks" / "run_cli.cmd"
        command = (
            f'"{launcher}" init --codex --data-dir "{plugin_data}"'
        )
    else:
        launcher = Path(plugin_root) / "hooks" / "run_cli.sh"
        command = " ".join(
            (
                "sh",
                shlex.quote(str(launcher)),
                "init",
                "--codex",
                "--data-dir",
                shlex.quote(plugin_data),
            )
        )
    return f"{message}\nRun from the workspace root: {command}"


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
    outcome, snapshots, operation_ids = _prepare_post_tool_evidence(store, event)
    if outcome is None or not operation_ids:
        return
    store.update_tool_operation_outcome(
        event,
        operation_ids,
        outcome=outcome.status,
        evidence=outcome.evidence,
        resource_snapshots=snapshots,
    )


def _prepare_post_tool_evidence(
    store: EventStore,
    event: NormalizedEvent,
) -> tuple[ToolOutcome | None, list[ResourceSnapshot], tuple[str, ...]]:
    if event.workspace_status != "ready":
        return None, [], ()
    operations = store.list_tool_operations_for_post_event(event)
    if not operations:
        return None, [], ()
    outcome = classify_post_tool_outcome(event)
    owner_matches = _validated_operation_owner(
        store,
        event,
        operations,
    )
    if not owner_matches:
        return ToolOutcome("unknown", "post_operation_owner_mismatch"), [], ()
    operation_ids = tuple(sorted(operation.operation_id for operation in operations))
    if outcome.status != "succeeded":
        return outcome, [], operation_ids
    try:
        snapshots = capture_operation_snapshots(
            event,
            operations,
            limits=limits_from_environment(),
            store_plaintext=plaintext_snapshots_enabled(),
        )
    except Exception as exc:  # pragma: no cover - defensive capture boundary
        _report_policy_failure("post-tool snapshot", exc)
        outcome = ToolOutcome(
            outcome.status,
            f"{outcome.evidence};snapshot_capture_error:{type(exc).__name__}",
        )
        snapshots = []
    return outcome, snapshots, operation_ids


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
