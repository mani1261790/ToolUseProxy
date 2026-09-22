from __future__ import annotations

import json
import sqlite3
import time
from contextlib import contextmanager
from dataclasses import asdict
from pathlib import Path

from hook_monitor.externality.providers import JudgeProviderError
from hook_monitor.runtime.parser import build_artifacts
from hook_monitor.semantic_flow.graph import GraphUnavailable, analyze, digest, initialize
from hook_monitor.semantic_flow.judge import PROMPT_VERSION, CodexSemanticJudge


def configuration(db_path: Path, workspace_id: str | None) -> dict | None:
    path = db_path.parent / "semantic-flow.json"
    if not path.exists():
        return None
    value = json.loads(path.read_text(encoding="utf-8"))
    config = value.get("workspaces", {}).get(workspace_id)
    if config is None:
        return None
    if (
        config.get("provider") != "codex_exec"
        or config.get("send_recorded_content") is not True
        or config.get("failure_policy") != "allow_with_warning"
        or config.get("mode") != "enforce"
    ):
        raise GraphUnavailable("invalid_semantic_configuration")
    return config


@contextmanager
def session_lock(db_path: Path, workspace: str, session: str):
    # Model requests must not hold the events.db writer lock. The process lock is
    # automatically released after a crash and serializes only this session.
    import fcntl

    lock_dir = db_path.parent / "semantic-flow-locks"
    lock_dir.mkdir(mode=0o700, exist_ok=True)
    with (lock_dir / digest([workspace, session])).open("a") as handle:
        until = time.monotonic() + 120
        while True:
            try:
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= until:
                    raise GraphUnavailable("session_analysis_busy")
                time.sleep(0.05)
        try:
            yield
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)


def hook_output(result: dict, phase: str) -> dict:
    if phase != "pre_tool_use":
        return {}
    if result["action"] == "block":
        return {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": "送信する内容から登録済みの秘密情報源へ依存経路が見つかったため、実行前に停止しました。",
            }
        }
    if result["action"] == "unavailable":
        return {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "additionalContext": "ToolUseProxyの情報流判定を完了できませんでした。流出検出ではありません。"
                "設定された障害時方針により、このHookは操作を遮断しません。安全確認は未完了です。"
                "（" + result["reason"] + "）",
            }
        }
    # Do not return permissionDecision=allow: retain the host's approval rules.
    return {}


def process_hook(store, event, *, judge=None) -> dict | None:
    try:
        config = configuration(store.db_path, event.workspace_id)
    except (ValueError, OSError, AttributeError):
        return hook_output(
            {"action": "unavailable", "reason": "invalid_semantic_configuration"}, event.phase
        )
    if config is None:
        return None
    if event.phase not in ("pre_tool_use", "post_tool_use"):
        # The old final-answer similarity policy is not part of this engine.
        return {}
    store.record(event, build_artifacts(event))
    result = {
        "action": "unavailable",
        "reason": "semantic_internal_error",
        "path": [],
        "node_id": None,
    }
    model = config.get("model") or "codex_default"
    try:
        if not event.workspace_id or not event.session_id or not event.tool_use_id:
            raise GraphUnavailable("semantic_identity_missing")
        sources = [
            dict(asdict(source), node_id="source:" + source.source_id)
            for source in store.list_protected_sources_for_workspace(event.workspace_id)
        ]
        with session_lock(store.db_path, event.workspace_id, event.session_id):
            started = time.monotonic()
            provider = judge or CodexSemanticJudge(config.get("model"), timeout=60)

            def bounded_judge(records):
                if time.monotonic() - started > 480:
                    raise GraphUnavailable("semantic_analysis_budget_exceeded")
                if len(json.dumps(records, ensure_ascii=False).encode()) > 512_000:
                    raise GraphUnavailable("semantic_prompt_budget_exceeded")
                return provider(records)

            result = analyze(
                store.db_path,
                event.workspace_id,
                event.session_id,
                event.event_id,
                sources,
                bounded_judge,
                model=model,
            )
    except (GraphUnavailable, JudgeProviderError) as exc:
        result["reason"] = str(exc)
    except Exception:
        # Never echo provider errors that may contain recorded/private content.
        pass
    if event.phase == "post_tool_use" and result["action"] != "unavailable":
        result["action"] = "observed"
    try:
        with sqlite3.connect(store.db_path, timeout=5) as conn:
            initialize(conn)
            conn.execute(
                "INSERT OR REPLACE INTO semantic_flow_decisions "
                "(event_id,workspace_id,session_id,node_id,action,reason,path_json,model,prompt_version) "
                "VALUES (?,?,?,?,?,?,?,?,?)",
                (
                    event.event_id,
                    event.workspace_id or "",
                    event.session_id or "",
                    result["node_id"],
                    result["action"],
                    result["reason"],
                    json.dumps(result["path"]),
                    model,
                    PROMPT_VERSION,
                ),
            )
    except sqlite3.Error:
        result = {"action": "unavailable", "reason": "semantic_audit_write_failed"}
    return hook_output(result, event.phase)
