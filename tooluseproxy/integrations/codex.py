from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import sys
from pathlib import Path
from types import SimpleNamespace

from hook_monitor.runtime.parser import inspect_top_level_json_strings
from hook_monitor.runtime.runner import (
    PRE_TOOL_RAW_JSON_MAX_BYTES, inactive_hook_output, run_hook,
)
from tooluseproxy.integrations.activation import (
    enabled_workspace_root, require_workspace_registration,
)
from tooluseproxy import __version__
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
        "programmatic_nested_tools": "unverified",
        "specialized_tool_paths": "unverified",
    }


def _runtime_attestation() -> dict[str, str]:
    """Bind Hook evidence to the exact installed runtime and definitions."""

    plugin_root = Path(
        os.environ.get("PLUGIN_ROOT", Path(__file__).resolve().parents[2])
    )
    manifest_path = plugin_root / ".codex-plugin" / "plugin.json"
    hooks_path = plugin_root / "hooks" / "hooks.json"
    if not manifest_path.is_file() or not hooks_path.is_file():
        return {
            "plugin_version": __version__,
            "runtime_version": __version__,
            "hooks_sha256": "package-runtime-without-plugin-manifest",
        }
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    plugin_version = manifest.get("version")
    if not isinstance(plugin_version, str) or not plugin_version:
        raise ValueError("Plugin manifest version is unavailable")
    hooks_bytes = hooks_path.read_bytes()
    return {
        "plugin_version": plugin_version,
        "runtime_version": __version__,
        "hooks_sha256": hashlib.sha256(hooks_bytes).hexdigest(),
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
    captured = io.StringIO()
    original_stdin = sys.stdin
    try:
        paths = resolve_runtime_paths(db_path=db_path, data_dir=data_dir)
        prefix = original_stdin.buffer.read(PRE_TOOL_RAW_JSON_MAX_BYTES + 1)
        envelope, _ = inspect_top_level_json_strings(prefix, frozenset({"cwd"}))
        workspace_root = enabled_workspace_root(paths.db_path, envelope.get("cwd"))
        if workspace_root is None:
            return 0
        # Replay exactly the original bytes. The runtime retains its own bounded
        # PreToolUse parser; PostToolUse/Stop may consume the remaining stream.
        sys.stdin = SimpleNamespace(buffer=_ReplayInput(prefix, original_stdin.buffer))
        if not paths.db_path.is_file():
            raise ValueError("enabled workspace database is missing")
        require_workspace_registration(paths.db_path, workspace_root)
        prepare_data_directory(paths)
        attestation = _runtime_attestation()
        try:
            with contextlib.redirect_stdout(captured):
                result = run_hook(
                    runtime_phase,
                    db_path=paths.db_path,
                    allow_schema_migration=False,
                    runtime_attestation=attestation,
                    activated_workspace_root=workspace_root,
                )
        finally:
            secure_database_permissions(paths.db_path)
        output = _validated_hook_output(captured.getvalue(), runtime_phase)
        if captured.getvalue().strip() and output is None:
            raise ValueError("Hook runtime returned an invalid output")
        if runtime_phase in {"session_start", "subagent_start"}:
            hook_event = (
                "SessionStart"
                if runtime_phase == "session_start"
                else "SubagentStart"
            )
            prior_context = ""
            if output is not None:
                hook_output = output.get("hookSpecificOutput")
                if isinstance(hook_output, dict):
                    candidate = hook_output.get("additionalContext")
                    if isinstance(candidate, str):
                        prior_context = candidate.strip()
            output = {
                "hookSpecificOutput": {
                    "hookEventName": hook_event,
                    "additionalContext": " ".join(
                        item
                        for item in (prior_context, HOSTED_TOOL_BOUNDARY_CONTEXT)
                        if item
                    ),
                }
            }
        if output is not None:
            print(json.dumps(output, ensure_ascii=False))
        return result
    except Exception:  # PreToolUse fails closed; later phases stay advisory.
        output = _validated_hook_output(captured.getvalue(), runtime_phase)
        if output is None:
            output = inactive_hook_output(
                runtime_phase,
                (
                    "ToolUseProxy inactive (runtime_error): "
                    "the local Hook runtime could not start"
                ),
                deny_pre_tool=runtime_phase == "pre_tool_use",
            )
        if runtime_phase in {"session_start", "subagent_start"}:
            hook_event = (
                "SessionStart"
                if runtime_phase == "session_start"
                else "SubagentStart"
            )
            output = {
                "hookSpecificOutput": {
                    "hookEventName": hook_event,
                    "additionalContext": (
                        "ToolUseProxyのHook実行状態を記録できませんでした。 "
                        + HOSTED_TOOL_BOUNDARY_CONTEXT
                    ),
                }
            }
        print(
            json.dumps(output, ensure_ascii=False)
        )
        return 0
    finally:
        sys.stdin = original_stdin


class _ReplayInput:
    def __init__(self, prefix: bytes, remainder: object) -> None:
        self.prefix = io.BytesIO(prefix)
        self.remainder = remainder

    def read(self, size: int = -1) -> bytes:
        first = self.prefix.read(size)
        if size < 0:
            return first + self.remainder.read()
        if len(first) == size:
            return first
        return first + self.remainder.read(size - len(first))


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
