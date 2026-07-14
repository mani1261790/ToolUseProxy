from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

from hook_monitor.runtime.parser import (
    HookPayloadError,
    build_artifacts,
    build_fragments,
    normalize_event,
    parse_hook_payload,
)
from hook_monitor.runtime.operations import extract_tool_operations
from hook_monitor.runtime.models import NormalizedEvent, ResourceSnapshot, ToolOperation
from hook_monitor.runtime.pre_tool_policy import (
    evaluate_pre_tool_hook_policy,
    pre_tool_adapter,
)
from hook_monitor.runtime.storage import DEFAULT_DB_PATH, EventStore
from hook_monitor.runtime.snapshot_capture import (
    capture_operation_snapshots,
    limits_from_environment,
    plaintext_snapshots_enabled,
)
from hook_monitor.runtime.stop_policy import evaluate_stop_hook_policy
from hook_monitor.runtime.tool_outcome import ToolOutcome, classify_post_tool_outcome
from hook_monitor.runtime.workspace import WORKSPACE_ROOT_ENV

REPO_ROOT = Path(__file__).resolve().parents[2]


def run_hook(phase: str) -> int:
    raw_payload = sys.stdin.buffer.read()
    try:
        payload = parse_hook_payload(raw_payload)
    except HookPayloadError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    event = normalize_event(
        phase,
        payload,
        workspace_root=os.environ.get(WORKSPACE_ROOT_ENV),
    )
    artifacts = build_artifacts(event)
    fragments = build_fragments(artifacts)
    extraction = extract_tool_operations(event, artifacts, fragments)
    fragments.extend(extraction.fragments)

    store = EventStore(_resolve_db_path())
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
    enabled_pre_tool_adapters = _enabled_pre_tool_adapters()
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
    configured = os.environ.get("TOOLUSEPROXY_DB_PATH")
    if configured:
        return Path(configured).expanduser()
    # Hook の実行 cwd に依存すると DB の保存先がぶれるので、repo 基準で固定する。
    return REPO_ROOT / DEFAULT_DB_PATH


def _stop_policy_enabled() -> bool:
    configured = os.environ.get("TOOLUSEPROXY_STOP_POLICY", "1")
    return configured.lower() not in {"0", "false", "no", "off"}


def _pre_tool_policy_enabled() -> bool:
    configured = os.environ.get("TOOLUSEPROXY_PRE_TOOL_POLICY", "0")
    return configured.lower() in {"1", "true", "yes", "on"}


def _pre_tool_mcp_policy_enabled() -> bool:
    configured = os.environ.get("TOOLUSEPROXY_PRE_TOOL_MCP_POLICY", "0")
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


def _runtime_policy_workspace_enabled(event: NormalizedEvent) -> bool:
    return (
        event.workspace_status == "ready"
        and event.workspace_id is not None
        and event.workspace_root is not None
        and event.workspace_execution_cwd is not None
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
