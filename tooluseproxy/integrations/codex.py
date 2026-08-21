from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path

from hook_monitor.runtime.runner import inactive_hook_output, run_hook
from tooluseproxy.paths import (
    prepare_data_directory,
    resolve_runtime_paths,
    secure_database_permissions,
)


CODEX_HOOK_PHASES = {
    "session-start": "session_start",
    "subagent-start": "subagent_start",
    "pre-tool-use": "pre_tool_use",
    "post-tool-use": "post_tool_use",
    "stop": "stop",
}

HOSTED_TOOL_BOUNDARY_CONTEXT = (
    "ToolUseProxyの保護境界です。登録された保護対象と、そこから得た内容を、"
    "WebSearchなどのhosted toolへ入力しないでください。hosted toolはCodex Hookに"
    "届かないため、ToolUseProxyは実行前に検査・遮断できません。外部検索が必要な場合は、"
    "保護内容を含まない公開情報だけで問い合わせを作ってください。公開情報だけに分離できない"
    "場合はhosted toolを呼ばず、その理由を利用者へ説明してください。Hookから見えるローカル"
    "toolは、通常のToolUseProxy判定に従ってください。"
)


def codex_enforcement_coverage() -> dict[str, object]:
    """Describe the enforceable Codex boundary without claiming full coverage."""

    return {
        "scope": "partial",
        "hook_visible_local_tool_subscription": "all",
        "active_workspace_pre_execution_policy": (
            "adapter_or_conservative_unknown"
        ),
        "local_file_mutations": "observed_not_external_sink",
        "hosted_tools": "not_interceptable",
        "hosted_tool_mitigation": "session_and_subagent_developer_context",
        "hosted_tool_pre_execution_block": False,
        "write_stdin_continuations": "not_rechecked",
        "specialized_tool_paths": "unverified",
    }


def run_codex_hook(
    phase: str,
    *,
    db_path: str | Path | None = None,
    data_dir: str | Path | None = None,
) -> int:
    try:
        runtime_phase = CODEX_HOOK_PHASES[phase]
    except KeyError:
        raise ValueError(f"unsupported Codex hook phase: {phase}") from None
    if runtime_phase in {"session_start", "subagent_start"}:
        hook_event = (
            "SessionStart" if runtime_phase == "session_start" else "SubagentStart"
        )
        print(
            json.dumps(
                {
                    "hookSpecificOutput": {
                        "hookEventName": hook_event,
                        "additionalContext": HOSTED_TOOL_BOUNDARY_CONTEXT,
                    }
                },
                ensure_ascii=False,
            )
        )
        return 0

    captured = io.StringIO()
    try:
        paths = resolve_runtime_paths(db_path=db_path, data_dir=data_dir)
        prepare_data_directory(paths)
        try:
            with contextlib.redirect_stdout(captured):
                result = run_hook(
                    runtime_phase,
                    db_path=paths.db_path,
                    allow_schema_migration=False,
                )
        finally:
            secure_database_permissions(paths.db_path)
        output = _validated_hook_output(captured.getvalue(), runtime_phase)
        if captured.getvalue().strip() and output is None:
            raise ValueError("Hook runtime returned an invalid output")
        if output is not None:
            print(json.dumps(output, ensure_ascii=False))
        return result
    except Exception:  # Hook integrations must never block Codex on local failure.
        output = _validated_hook_output(captured.getvalue(), runtime_phase)
        if output is None:
            output = inactive_hook_output(
                runtime_phase,
                (
                    "ToolUseProxy inactive (runtime_error): "
                    "the local Hook runtime could not start"
                ),
            )
        print(
            json.dumps(output, ensure_ascii=False)
        )
        return 0


def _validated_hook_output(
    rendered: str,
    runtime_phase: str,
) -> dict[str, object] | None:
    if not rendered.strip():
        return None
    try:
        payload = json.loads(rendered)
    except json.JSONDecodeError:
        return None
    if not isinstance(payload, dict):
        return None
    if runtime_phase in {"pre_tool_use", "post_tool_use"}:
        expected_event = (
            "PreToolUse"
            if runtime_phase == "pre_tool_use"
            else "PostToolUse"
        )
        hook_output = payload.get("hookSpecificOutput")
        if (
            not isinstance(hook_output, dict)
            or hook_output.get("hookEventName") != expected_event
        ):
            return None
        return payload
    if runtime_phase in {"session_start", "subagent_start"}:
        expected_event = (
            "SessionStart" if runtime_phase == "session_start" else "SubagentStart"
        )
        hook_output = payload.get("hookSpecificOutput")
        if (
            isinstance(hook_output, dict)
            and hook_output.get("hookEventName") == expected_event
            and isinstance(hook_output.get("additionalContext"), str)
        ):
            return payload
    if runtime_phase == "stop" and (
        isinstance(payload.get("systemMessage"), str)
        or payload.get("decision") == "block"
    ):
        return payload
    return None
