"""The v2 Hook entrypoint: lifecycle boundary, observation, semantic judgment."""

from __future__ import annotations

import json
import hashlib
import os
import sys
from pathlib import Path

from tooluseproxy import __version__
from tooluseproxy.engine.journal import Journal, event_from
from tooluseproxy.engine.runtime import hook_output, process_hook
from tooluseproxy.integrations.activation import enabled_workspace_root
from tooluseproxy.integrations.authority import workspace_authority_lease

PHASES = {
    "session-start": "session_start",
    "subagent-start": "subagent_start",
    "pre-tool-use": "pre_tool_use",
    "post-tool-use": "post_tool_use",
    "stop": "stop",
}
BOUNDARY = (
    "ToolUseProxyはToolCallの記録からモデルで依存関係を推定し、入力に明示された外部送信時に秘密情報源への"
    "経路を検査します。判定中は実行を保留し、判定完了後に実行可否を決めます。"
    "WebSearchなどHookに届かないhosted toolへ、保護情報や派生内容を入力しないでください。"
    "スクリプト内部やローカルサービスの転送など、入力に現れない通信は検査対象外です。"
)


def run(phase: str, db_path: Path) -> int:
    runtime_phase = PHASES[phase]
    result = {}
    try:
        raw = sys.stdin.buffer.read(1024 * 1024 + 1)
        if len(raw) > 1024 * 1024:
            raise ValueError("payload_budget_exceeded")
        payload = json.loads(raw)
        if not isinstance(payload, dict):
            raise ValueError("invalid_hook_payload")
        with workspace_authority_lease(db_path, payload.get("cwd")) as state:
            if state is not None and state.phase != "active":
                print("{}", flush=True)
                return 0
            root = enabled_workspace_root(db_path, payload.get("cwd"))
            if root is None:
                print("{}", flush=True)
                return 0
            journal = Journal(db_path)
            plugin = Path(os.environ.get("PLUGIN_ROOT", Path(__file__).resolve().parents[2]))
            manifest = (
                json.loads((plugin / ".codex-plugin/plugin.json").read_text())
                if (plugin / ".codex-plugin/plugin.json").is_file()
                else {}
            )
            definitions = plugin / "hooks/hooks.json"
            payload["_tooluseproxy_runtime"] = {
                "engine": "semantic-flow-v2",
                "runtime_version": __version__,
                "plugin_version": manifest.get("version", __version__),
                "hooks_sha256": hashlib.sha256(definitions.read_bytes()).hexdigest()
                if definitions.is_file()
                else "package-runtime-without-plugin-manifest",
            }
            from tooluseproxy.engine.requirements import observe_runtime_definitions, observe_managed_resources
            payload["_tooluseproxy_definitions"] = observe_runtime_definitions(payload.get("tool_input"))
            payload["_tooluseproxy_resource_catalog"] = observe_managed_resources(db_path.parent) if payload["_tooluseproxy_definitions"] else None
            event = event_from(runtime_phase, payload, root)
            # No whole-DB initialization, source-file read, cleanup, or legacy analysis here.
            journal.record(event)
            result = process_hook(journal, event)
            if result is None:
                result = hook_output(
                    {"action": "unavailable", "reason": "semantic_setup_required"}, runtime_phase
                )
            if runtime_phase in ("session_start", "subagent_start"):
                result = {
                    "hookSpecificOutput": {
                        "hookEventName": "SessionStart"
                        if runtime_phase == "session_start"
                        else "SubagentStart",
                        "additionalContext": BOUNDARY,
                    }
                }
    except Exception:
        result = hook_output(
            {"action": "unavailable", "reason": "semantic_runtime_unavailable"}, runtime_phase
        )
    print(json.dumps(result, ensure_ascii=False), flush=True)
    # The response is emitted before starting optional asynchronous work.
    if runtime_phase in ("pre_tool_use", "post_tool_use"):
        try:
            from tooluseproxy.engine.runtime import configuration
            config = configuration(db_path,event.workspace_id)
            if (config and config.get("background_provenance") is True
                    and journal.list_protected_sources_for_workspace(event.workspace_id)):
                from tooluseproxy.engine.worker import kick
                kick(db_path,event.workspace_id)
        except Exception:
            pass  # Durable work remains available to the next invocation/explicit drain.
    return 0
