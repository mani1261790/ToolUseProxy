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
from hook_monitor.runtime.storage import DEFAULT_DB_PATH, EventStore
from hook_monitor.runtime.stop_policy import evaluate_stop_hook_policy

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

    store = EventStore(_resolve_db_path())
    store.initialize()
    store.record(event, artifacts, fragments)
    if phase == "stop" and _stop_policy_enabled():
        try:
            hook_output = evaluate_stop_hook_policy(
                store,
                REPO_ROOT,
                current_event_id=event.event_id,
            )
        except Exception as exc:  # pragma: no cover - defensive hook boundary
            print(f"stop policy evaluation failed: {exc}", file=sys.stderr)
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
