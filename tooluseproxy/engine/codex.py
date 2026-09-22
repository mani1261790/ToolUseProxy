"""Isolated Codex inference transport. No ToolUseProxy analysis imports."""

from __future__ import annotations
import json
import os
import signal
import subprocess
from dataclasses import dataclass
from pathlib import Path


class JudgeProviderError(RuntimeError):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class ProcessResult:
    returncode: int
    stdout: bytes
    stderr: bytes


CODEX_DISABLED_FEATURES = (
    "apps",
    "browser_use",
    "browser_use_external",
    "browser_use_full_cdp_access",
    "code_mode_host",
    "computer_use",
    "hooks",
    "image_generation",
    "in_app_browser",
    "memories",
    "multi_agent",
    "multi_agent_v2",
    "plugins",
    "remote_plugin",
    "shell_tool",
    "standalone_web_search",
    "tool_suggest",
    "unified_exec",
    "unified_exec_zsh_fork",
    "workspace_dependencies",
)


def build_codex_exec_argv(
    *,
    executable: str,
    schema_path: Path,
    output_path: Path,
    model: str | None,
) -> list[str]:
    argv = [
        executable,
        "exec",
        "--ephemeral",
        "--ignore-user-config",
        "--ignore-rules",
        "--strict-config",
        "--skip-git-repo-check",
        "--sandbox",
        "read-only",
        "--json",
        "--color",
        "never",
        "--output-schema",
        str(schema_path),
        "--output-last-message",
        str(output_path),
    ]
    for feature in CODEX_DISABLED_FEATURES:
        argv.extend(("--disable", feature))
    if model is not None:
        argv.extend(("--model", model))
    argv.append("-")
    return argv


def codex_events_contain_tool_activity(events: bytes) -> bool:
    for raw_line in events.splitlines():
        if not raw_line.strip():
            continue
        try:
            event = json.loads(raw_line)
        except (UnicodeDecodeError, json.JSONDecodeError):
            return True
        if _contains_forbidden_event_value(event):
            return True
    return False


def _contains_forbidden_event_value(value: object) -> bool:
    forbidden = {
        "browser",
        "command_execution",
        "computer_use",
        "function_call",
        "mcp_tool_call",
        "shell",
        "tool_call",
        "web_search",
    }
    if isinstance(value, dict):
        for key, nested in value.items():
            if key in {"type", "item_type", "tool"} and isinstance(nested, str):
                normalized = nested.lower()
                if normalized in forbidden or any(token in normalized for token in forbidden):
                    return True
            if _contains_forbidden_event_value(nested):
                return True
    elif isinstance(value, list):
        return any(_contains_forbidden_event_value(item) for item in value)
    return False


def _loads_no_duplicate_keys(value: str | bytes) -> object:
    def closed_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, item in pairs:
            if key in result:
                raise JudgeProviderError("provider_response_duplicate_key")
            result[key] = item
        return result

    return json.loads(value, object_pairs_hook=closed_object)


def _minimal_codex_environment() -> dict[str, str]:
    allowed = (
        "CODEX_HOME",
        "HOME",
        "LANG",
        "LC_ALL",
        "PATH",
        "SSL_CERT_DIR",
        "SSL_CERT_FILE",
        "TMPDIR",
    )
    environment = {key: os.environ[key] for key in allowed if key in os.environ}
    environment["NO_COLOR"] = "1"
    environment["TOOLUSEPROXY_CODEX_JUDGE"] = "1"
    return environment


def _run_process(
    argv: list[str],
    stdin: bytes,
    cwd: Path,
    environment: dict[str, str],
    timeout_seconds: float,
) -> ProcessResult:
    try:
        process = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=cwd,
            env=environment,
            start_new_session=True,
        )
    except OSError as exc:
        raise JudgeProviderError("codex_exec_unavailable") from exc
    try:
        stdout, stderr = process.communicate(stdin, timeout=timeout_seconds)
    except subprocess.TimeoutExpired as exc:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.communicate()
        raise JudgeProviderError("codex_exec_timeout") from exc
    return ProcessResult(process.returncode, stdout, stderr)
