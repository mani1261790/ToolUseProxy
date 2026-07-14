from __future__ import annotations

import json
import os
import re
import sys
from dataclasses import replace
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
    workspace_root_from_cwd,
)
from hook_monitor.runtime.stop_policy import evaluate_stop_hook_policy
from hook_monitor.runtime.tool_outcome import ToolOutcome, classify_post_tool_outcome

REPO_ROOT = Path(__file__).resolve().parents[2]


def run_hook(phase: str) -> int:
    raw_payload = sys.stdin.buffer.read()
    try:
        payload = parse_hook_payload(raw_payload)
    except HookPayloadError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    event = normalize_event(phase, payload)
    artifacts = build_artifacts(event)
    fragments = build_fragments(artifacts)
    extraction = extract_tool_operations(event, artifacts, fragments)
    fragments.extend(extraction.fragments)

    store = EventStore(_resolve_db_path())
    store.initialize()
    post_outcome: ToolOutcome | None = None
    post_snapshots: list[ResourceSnapshot] = []
    if phase == "post_tool_use":
        try:
            post_outcome, post_snapshots = _prepare_post_tool_evidence(store, event)
        except Exception as exc:  # pragma: no cover - defensive hook boundary
            _report_policy_failure("post-tool snapshot", exc)
    store.record(
        event,
        artifacts,
        fragments,
        list(extraction.operations),
        post_outcome=(
            None
            if post_outcome is None
            else (post_outcome.status, post_outcome.evidence)
        ),
        resource_snapshots=post_snapshots,
    )
    enabled_pre_tool_adapters = _enabled_pre_tool_adapters()
    if phase == "pre_tool_use" and pre_tool_adapter(
        event.tool_name
    ) in enabled_pre_tool_adapters:
        try:
            hook_output = evaluate_pre_tool_hook_policy(
                store,
                REPO_ROOT,
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
        try:
            hook_output = evaluate_stop_hook_policy(
                store,
                REPO_ROOT,
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


def _capture_post_tool_evidence(
    store: EventStore,
    event: NormalizedEvent,
) -> None:
    outcome, snapshots = _prepare_post_tool_evidence(store, event)
    if outcome is None:
        return
    store.update_tool_operation_outcome(
        event.session_id,
        event.tool_use_id,
        outcome=outcome.status,
        evidence=outcome.evidence,
        post_event_id=event.event_id,
    )
    store.upsert_resource_snapshots(snapshots)


def _prepare_post_tool_evidence(
    store: EventStore,
    event: NormalizedEvent,
) -> tuple[ToolOutcome | None, list[ResourceSnapshot]]:
    if event.session_id is None or event.tool_use_id is None:
        return None, []
    operations = store.list_tool_operations_for_tool_uses(
        event.session_id,
        {event.tool_use_id},
    )
    if not operations:
        return None, []
    outcome = classify_post_tool_outcome(event)
    owner_matches, owner_cwd = _validated_operation_owner_cwd(
        store,
        event,
        operations,
    )
    if not owner_matches:
        return ToolOutcome("unknown", "post_operation_owner_mismatch"), []
    if outcome.status != "succeeded":
        return outcome, []
    try:
        snapshots = capture_operation_snapshots(
            replace(event, cwd=owner_cwd),
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
    return outcome, snapshots


def _validated_operation_owner_cwd(
    store: EventStore,
    event: NormalizedEvent,
    operations: list[ToolOperation],
) -> tuple[bool, str | None]:
    owner_contexts = store.list_event_execution_contexts(
        {operation.event_id for operation in operations}
    )
    if len(owner_contexts) != len({operation.event_id for operation in operations}):
        return False, None
    identities = set(owner_contexts.values())
    if len(identities) != 1:
        return False, None
    phase, session_id, tool_use_id, tool_name, owner_cwd = identities.pop()
    if (
        phase != "pre_tool_use"
        or session_id != event.session_id
        or tool_use_id != event.tool_use_id
        or _normalized_tool_name(tool_name) != _normalized_tool_name(event.tool_name)
        or workspace_root_from_cwd(owner_cwd) != workspace_root_from_cwd(event.cwd)
    ):
        return False, None
    if any(
        operation.session_id != session_id
        or operation.tool_use_id != tool_use_id
        or _normalized_tool_name(operation.tool_name) != _normalized_tool_name(tool_name)
        for operation in operations
    ):
        return False, None
    return True, owner_cwd


def _normalized_tool_name(tool_name: str | None) -> str | None:
    if not tool_name:
        return None
    normalized = re.sub(r"[^a-z0-9]+", "_", tool_name.casefold()).strip("_")
    return normalized or None
