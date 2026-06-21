from __future__ import annotations

import os
import sys
from pathlib import Path

from hook_monitor.runtime.parser import (
    HookPayloadError,
    build_artifacts,
    normalize_event,
    parse_hook_payload,
)
from hook_monitor.runtime.storage import DEFAULT_DB_PATH, EventStore

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

    store = EventStore(_resolve_db_path())
    store.initialize()
    store.record(event, artifacts)
    return 0


def _resolve_db_path() -> Path:
    configured = os.environ.get("TOOLUSEPROXY_DB_PATH")
    if configured:
        return Path(configured).expanduser()
    # Hook の実行 cwd に依存すると DB の保存先がぶれるので、repo 基準で固定する。
    return REPO_ROOT / DEFAULT_DB_PATH
