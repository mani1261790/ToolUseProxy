from __future__ import annotations

import json
import os
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
from hook_monitor.runtime.models import NormalizedEvent
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
from hook_monitor.runtime.tool_outcome import classify_post_tool_outcome

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
    store.record(event, artifacts, fragments, list(extraction.operations))
    if phase == "post_tool_use":
        try:
            _capture_post_tool_evidence(store, event)
        except Exception as exc:  # pragma: no cover - defensive hook boundary
            _report_policy_failure("post-tool snapshot", exc)
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
    if event.session_id is None or event.tool_use_id is None:
        return
    operations = store.list_tool_operations_for_tool_uses(
        event.session_id,
        {event.tool_use_id},
    )
    if not operations:
        return
    outcome = classify_post_tool_outcome(event)
    store.update_tool_operation_outcome(
        event.session_id,
        event.tool_use_id,
        outcome=outcome.status,
        evidence=outcome.evidence,
    )
    if outcome.status != "succeeded":
        return
    snapshots = capture_operation_snapshots(
        event,
        operations,
        limits=limits_from_environment(),
        store_plaintext=plaintext_snapshots_enabled(),
    )
    store.upsert_resource_snapshots(snapshots)
