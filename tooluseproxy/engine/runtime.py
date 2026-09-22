from __future__ import annotations

import json
import sqlite3
import time
from contextlib import contextmanager
from dataclasses import asdict
from pathlib import Path

from tooluseproxy.engine.codex import JudgeProviderError
from tooluseproxy.engine.graph import GraphUnavailable, digest, initialize
from tooluseproxy.engine.property_graph import analyze_properties
from tooluseproxy.engine.judge import PROMPT_VERSION, EXTERNALITY_VERSION, CodexSemanticJudge


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
def session_lock(db_path: Path, workspace: str, session: str, *, background=False):
    # Model requests must not hold the events.db writer lock. The process lock is
    # automatically released after a crash and serializes only this session.
    import fcntl

    lock_dir = db_path.parent / "semantic-flow-locks"
    lock_dir.mkdir(mode=0o700, exist_ok=True)
    from tooluseproxy.engine.jobs import priority_schema, PriorityYield
    import secrets
    owner=secrets.token_hex(16)
    if not background:
        with sqlite3.connect(db_path,timeout=5) as conn:
            priority_schema(conn)
            conn.execute("DELETE FROM flow_foreground_waiters WHERE until<?",(time.time(),))
            conn.execute("INSERT INTO flow_foreground_waiters VALUES (?,?,?,?)",(workspace,session,owner,time.time()+120))
    try:
        with (lock_dir / digest([workspace, session])).open("a") as handle:
            until = time.monotonic() + 120
            while True:
                try:
                    fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if background:
                        raise PriorityYield()
                    if time.monotonic() >= until:
                        raise GraphUnavailable("session_analysis_busy")
                    time.sleep(0.05)
            if not background:
                with sqlite3.connect(db_path,timeout=5) as conn:
                    conn.execute("DELETE FROM flow_foreground_waiters WHERE owner=?",(owner,))
            try:
                yield
            finally:
                fcntl.flock(handle, fcntl.LOCK_UN)
    finally:
        if not background:
            with sqlite3.connect(db_path,timeout=5) as conn:
                conn.execute("DELETE FROM flow_foreground_waiters WHERE owner=?",(owner,))


def hook_output(result: dict, phase: str) -> dict:
    if phase != "pre_tool_use":
        return {}
    if result["action"] == "block":
        return {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": (
                    "送信する内容に登録済みの秘密情報との一致が見つかったため、実行前に停止しました。"
                    if result.get("reason") == "protected_content_match" else
                    "送信する内容から登録済みの秘密情報源へ依存経路が見つかったため、実行前に停止しました。"
                ),
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


def screen_externality(db_path, event, model, provider):
    # Reuse only an identical delivery in the same workspace/session. Identical
    # command strings at a later time need not have the same environment/behavior.
    with sqlite3.connect(db_path) as conn:
        context = conn.execute("SELECT workspace_root,workspace_execution_cwd FROM events WHERE event_id=?",(event.event_id,)).fetchone()
    records = {"workspace_root": context[0] if context else None, "resolved_cwd": context[1] if context else None,
               "stage": "externality", "tool_name": event.raw_payload.get("tool_name"),
               "tool_input": event.raw_payload.get("tool_input"),
               "workspace": event.workspace_id}
    request_hash = digest([EXTERNALITY_VERSION, model, event.event_id, records])
    with sqlite3.connect(db_path) as conn:
        conn.execute("CREATE TABLE IF NOT EXISTS semantic_externality_checks (request_hash TEXT PRIMARY KEY, event_id TEXT NOT NULL, verdict_json TEXT NOT NULL, duration_ms INTEGER NOT NULL)")
        cached = conn.execute("SELECT verdict_json FROM semantic_externality_checks WHERE request_hash=?", (request_hash,)).fetchone()
    if cached:
        return json.loads(cached[0])
    started = time.monotonic()
    try:
        if len(json.dumps(records, ensure_ascii=False).encode()) > 64_000:
            raise GraphUnavailable("externality_input_large")
        verdict = provider(records)
        if (verdict.get("externality") not in ("local", "external")
                or type(verdict.get("complete")) is not bool
                or not isinstance(verdict.get("reason"), str)):
            raise GraphUnavailable("externality_invalid")
        resources = verdict.get("resources", [])
        transmission = verdict.get("transmission")
        verdict = {key: verdict[key] for key in ("externality", "complete", "reason")}
        verdict["resources"] = resources if isinstance(resources, list) else []
        if isinstance(transmission, dict):
            from tooluseproxy.engine.targets import validate_targets
            try:
                validate_targets(transmission)
                verdict["transmission"] = transmission
            except ValueError:
                pass
        if not verdict["complete"]:
            verdict = {"externality": "external", "complete": True, "reason": "screening_requires_inspection"}
    except Exception:
        # A screening failure is not permission to skip detailed analysis.
        return {"externality": "external", "complete": True, "reason": "screening_unavailable_requires_inspection"}
    with sqlite3.connect(db_path) as conn:
        conn.execute("INSERT OR REPLACE INTO semantic_externality_checks VALUES (?,?,?,?)", (request_hash, event.event_id, json.dumps(verdict), int((time.monotonic()-started)*1000)))
    return verdict


def process_hook(store, event, *, judge=None, screening_judge=None, target_judge=None) -> dict | None:
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
    store.record(event, [])
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
        with session_lock(store.db_path, event.workspace_id, event.session_id):
            node_id = "call:" + digest([event.workspace_id, event.session_id, event.tool_use_id])
            with sqlite3.connect(store.db_path) as conn:
                initialize(conn)
                conn.execute("INSERT OR IGNORE INTO semantic_flow_nodes (node_id,workspace_id,session_id,event_id,request_hash,verdict_json) VALUES (?,?,?,?,?,?)", (node_id,event.workspace_id,event.session_id,event.event_id,"","{}"))
            if event.phase == "post_tool_use":
                # Actual output is already in the journal. Analyze its provenance
                # on demand before a later possible external transmission.
                from tooluseproxy.engine.lineage import snapshot_resources
                snapshot_resources(store, event)
                if config.get("background_provenance") is True:
                    from tooluseproxy.engine.jobs import enqueue
                    enqueue(store.db_path,event,model)
                result = {"action": "observed", "reason": "provenance_deferred", "path": [], "node_id": node_id}
            else:
                screen = screen_externality(store.db_path, event, model,
                    screening_judge or judge or CodexSemanticJudge(config.get("model"), timeout=15))
                from tooluseproxy.engine.lineage import snapshot_resources
                snapshot_resources(store, event, screen.get("resources", []))
                if screen["externality"] == "local" and screen["complete"]:
                    result = {"action": "allow", "reason": "local_provenance_deferred", "path": [], "node_id": node_id}
                else:
                    sources = [
                        dict(asdict(source), node_id="source:" + source.source_id)
                        for source in store.list_protected_sources_for_workspace(event.workspace_id)
                    ]
                    started = time.monotonic()
                    provider = judge or CodexSemanticJudge(config.get("model"), timeout=60)

                    def bounded_judge(records):
                        if time.monotonic() - started > 480:
                            raise GraphUnavailable("semantic_analysis_budget_exceeded")
                        if len(json.dumps(records, ensure_ascii=False).encode()) > 512_000:
                            raise GraphUnavailable("semantic_prompt_budget_exceeded")
                        return provider(records)

                    def graph_decision():
                        return analyze_properties(
                            store.db_path,
                            event.workspace_id,
                            event.session_id,
                            event.event_id,
                            sources,
                            bounded_judge,
                            model=model,
                            sources_refresh=lambda: [dict(asdict(source), node_id="source:" + source.source_id) for source in store.list_protected_sources_for_workspace(event.workspace_id)],
                        )

                    if sources:
                        from tooluseproxy.engine.inspection import inspect_and_decide
                        def target_provider(records):
                            if time.monotonic() - started > 480:
                                raise GraphUnavailable("semantic_analysis_budget_exceeded")
                            if target_judge is None and not records.get("execution_definitions") and screen.get("transmission") is not None:
                                return screen["transmission"]
                            return (target_judge or provider)(records)
                        result = inspect_and_decide(store, event, sources, target_provider,
                                                    graph_decision, node_id, model)
                    else:
                        result = graph_decision()

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
