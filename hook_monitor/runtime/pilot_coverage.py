"""Read local Codex task structure without retaining arguments or outputs."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path

from hook_monitor.runtime.pilot_models import ToolFamily

MAX_BYTES = 8 * 1024 * 1024
MAX_LINE = 128 * 1024
MAX_RECORDS = 20000


def unknown_coverage(reason: str = "unavailable") -> dict:
    if reason not in {"unavailable", "scope_mismatch", "limit", "invalid", "unsupported"}:
        raise ValueError("unknown coverage reason")
    return {"status": "unknown", "reason": reason, "observed_calls": None,
            "hook_matched": None, "hook_unmatched": None,
            "unmatched_by_family": {str(family): None for family in ToolFamily}}


def read_task_coverage(
    path: Path | None, *, session_id: str | None, workspace_root: Path,
    codex_home: Path, hook_call_hashes: set[str],
) -> dict:
    if path is None or session_id is None:
        return unknown_coverage()
    try:
        resolved = path.resolve(strict=True)
        roots = (codex_home.resolve() / "sessions", codex_home.resolve() / "archived_sessions")
        if path.is_symlink() or not any(resolved.is_relative_to(root) for root in roots):
            return unknown_coverage("scope_mismatch")
        descriptor = os.open(resolved, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode):
                return unknown_coverage("invalid")
            if info.st_size > MAX_BYTES:
                return unknown_coverage("limit")
            seen_meta = False
            calls: dict[str, ToolFamily] = {}
            consumed = 0
            for index in range(MAX_RECORDS + 1):
                line = stream.readline(MAX_LINE + 1)
                if not line:
                    break
                consumed += len(line)
                if len(line) > MAX_LINE or consumed > MAX_BYTES or index == MAX_RECORDS:
                    return unknown_coverage("limit")
                record = json.loads(line)
                payload = record.get("payload")
                if not isinstance(payload, dict):
                    return unknown_coverage("invalid")
                if record.get("type") == "session_meta":
                    if (seen_meta or payload.get("id") != session_id
                            or payload.get("cwd") != str(workspace_root)):
                        return unknown_coverage("scope_mismatch")
                    seen_meta = True
                    continue
                if not seen_meta:
                    return unknown_coverage("scope_mismatch")
                if record.get("type") != "response_item":
                    continue
                kind = payload.get("type")
                if kind in {"function_call", "custom_tool_call", "web_search_call"}:
                    call_id = payload.get("call_id", payload.get("id"))
                    if not isinstance(call_id, str) or not 1 <= len(call_id) <= 512:
                        return unknown_coverage("invalid")
                    name = payload.get("name", "")
                    if not isinstance(name, str):
                        return unknown_coverage("invalid")
                    name = name.rsplit(".", 1)[-1]
                    if kind == "web_search_call":
                        family = ToolFamily.HOSTED
                    elif name in {"write_stdin", "wait"}:
                        family = ToolFamily.CONTINUATION
                    elif name in {"exec_command", "shell", "shell_command", "Bash"}:
                        family = ToolFamily.SHELL
                    elif name.startswith("mcp__"):
                        family = ToolFamily.MCP
                    elif name == "exec":
                        # Nested JavaScript is not parsed or claimed as covered.
                        return unknown_coverage("unsupported")
                    else:
                        family = ToolFamily.FUNCTION
                    reference = hashlib.sha256(call_id.encode()).hexdigest()
                    if reference in calls and calls[reference] != family:
                        return unknown_coverage("invalid")
                    calls[reference] = family
                elif isinstance(kind, str) and kind.endswith("_call"):
                    return unknown_coverage("unsupported")
            if not seen_meta:
                return unknown_coverage("scope_mismatch")
    except (OSError, ValueError, TypeError, AttributeError, RecursionError):
        return unknown_coverage("invalid")
    missing = [family for reference, family in calls.items() if reference not in hook_call_hashes]
    return {
        "status": "known", "reason": None, "observed_calls": len(calls),
        "hook_matched": len(calls) - len(missing), "hook_unmatched": len(missing),
        "unmatched_by_family": {str(family): missing.count(family) for family in ToolFamily},
    }
