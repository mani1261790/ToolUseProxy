from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from hook_monitor.runtime.models import NormalizedEvent


@dataclass(frozen=True)
class ToolOutcome:
    status: str
    evidence: str


def classify_post_tool_outcome(event: NormalizedEvent) -> ToolOutcome:
    """PostToolUse payloadを本文非依存の三値outcomeへ正規化する。"""
    if event.phase != "post_tool_use":
        return ToolOutcome("unknown", "not_post_tool_use")
    if "tool_response" not in event.raw_payload:
        return ToolOutcome("unknown", "missing_tool_response")

    response = event.raw_payload.get("tool_response")
    exit_code = _find_exit_code(response)
    if exit_code is not None:
        return ToolOutcome(
            "succeeded" if exit_code == 0 else "failed",
            f"exit_code:{exit_code}",
        )

    text = _response_text(response).casefold()
    if any(
        marker in text
        for marker in (
            "command failed",
            "execution failed",
            "patch failed",
            "apply_patch failed",
        )
    ):
        return ToolOutcome("failed", "failure_marker")
    if (event.tool_name or "").casefold() == "apply_patch":
        if "done!" in text or "success" in text:
            return ToolOutcome("succeeded", "apply_patch_success_marker")
        return ToolOutcome("unknown", "apply_patch_success_unconfirmed")
    return ToolOutcome("succeeded", "post_tool_use_completed")


def _find_exit_code(value: Any) -> int | None:
    if isinstance(value, dict):
        for key in ("exit_code", "exitCode"):
            candidate = value.get(key)
            if isinstance(candidate, int):
                return candidate
        for child in value.values():
            candidate = _find_exit_code(child)
            if candidate is not None:
                return candidate
        return None
    if isinstance(value, list):
        for child in value:
            candidate = _find_exit_code(child)
            if candidate is not None:
                return candidate
        return None
    if not isinstance(value, str):
        return None
    match = re.search(
        r"(?:exit\s+code|process\s+exited\s+with\s+code)\s*[:=]?\s*(-?\d+)",
        value,
        flags=re.IGNORECASE,
    )
    return int(match.group(1)) if match is not None else None


def _response_text(value: Any) -> str:
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    except TypeError:
        return ""
