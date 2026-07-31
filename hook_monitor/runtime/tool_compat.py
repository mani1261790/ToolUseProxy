from __future__ import annotations

import re
from typing import Any


SHELL_OPERATION_TOOL_NAMES = frozenset(
    {
        "bash",
        "shell",
        "exec",
        "exec_command",
        "command",
        "terminal",
        "run_command",
    }
)
ENFORCED_SHELL_TOOL_NAMES = frozenset({"bash", "exec_command"})


def normalize_tool_name(tool_name: str | None) -> str:
    return re.sub(
        r"[^a-z0-9]+",
        "_",
        (tool_name or "").casefold(),
    ).strip("_")


def is_shell_operation_tool(tool_name: str | None) -> bool:
    return normalize_tool_name(tool_name) in SHELL_OPERATION_TOOL_NAMES


def is_enforced_shell_tool(tool_name: str | None) -> bool:
    return normalize_tool_name(tool_name) in ENFORCED_SHELL_TOOL_NAMES


def shell_command_from_input(
    tool_name: str | None,
    tool_input: object,
) -> str | None:
    """Return the exact shell command without rewriting the stored payload."""
    if not isinstance(tool_input, dict):
        return None
    normalized = normalize_tool_name(tool_name)
    field = "cmd" if normalized == "exec_command" else "command"
    value: Any = tool_input.get(field)
    return value if isinstance(value, str) and value else None
