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
    exit_codes, invalid_exit_code = _collect_exit_codes(response)
    success_flags, invalid_success_flag = _collect_success_flags(response)
    nonzero_exit_codes = [code for code in exit_codes if code != 0]
    if nonzero_exit_codes:
        return ToolOutcome("failed", f"exit_code:{nonzero_exit_codes[0]}")
    if any(not flag for flag in success_flags):
        return ToolOutcome("failed", "explicit_failure_flag")
    if invalid_exit_code or invalid_success_flag:
        return ToolOutcome("unknown", "invalid_structured_outcome")
    if exit_codes:
        return ToolOutcome("succeeded", "exit_code:0")
    if success_flags:
        return ToolOutcome("succeeded", "explicit_success_flag")

    text = _response_text(response).casefold()
    if (event.tool_name or "").casefold() == "apply_patch":
        if any(
            marker in text
            for marker in ("patch failed", "apply_patch failed", "error:")
        ):
            return ToolOutcome("failed", "failure_marker")
        if "done!" in text or "success" in text:
            return ToolOutcome("succeeded", "apply_patch_success_marker")
        return ToolOutcome("unknown", "apply_patch_success_unconfirmed")
    # Bash stdoutはcommand自身が自由に生成できるため、本文中の
    # "exit code"や"command failed"を実行statusとして信用しない。
    # structured statusがないPostはsnapshot対象にしない。
    return ToolOutcome("unknown", "success_unconfirmed")


def _collect_exit_codes(value: Any) -> tuple[list[int], bool]:
    codes: list[int] = []
    invalid = False
    if isinstance(value, dict):
        for key in ("exit_code", "exitCode"):
            if key not in value:
                continue
            candidate = value[key]
            if isinstance(candidate, int) and not isinstance(candidate, bool):
                codes.append(candidate)
            elif isinstance(candidate, str) and re.fullmatch(r"-?\d+", candidate):
                codes.append(int(candidate))
            else:
                invalid = True
        for key, child in value.items():
            if key in {"exit_code", "exitCode"}:
                continue
            if isinstance(child, (dict, list)):
                child_codes, child_invalid = _collect_exit_codes(child)
                codes.extend(child_codes)
                invalid = invalid or child_invalid
        return codes, invalid
    if isinstance(value, list):
        for child in value:
            child_codes, child_invalid = _collect_exit_codes(child)
            codes.extend(child_codes)
            invalid = invalid or child_invalid
        return codes, invalid
    return codes, invalid


def _collect_success_flags(value: Any) -> tuple[list[bool], bool]:
    flags: list[bool] = []
    invalid = False
    if isinstance(value, dict):
        for key, child in value.items():
            if key in {"success", "succeeded", "ok"}:
                if isinstance(child, bool):
                    flags.append(child)
                else:
                    invalid = True
                continue
            if key in {"failed", "failure"}:
                if isinstance(child, bool):
                    flags.append(not child)
                else:
                    invalid = True
                continue
            child_flags, child_invalid = _collect_success_flags(child)
            flags.extend(child_flags)
            invalid = invalid or child_invalid
        return flags, invalid
    if isinstance(value, list):
        for child in value:
            child_flags, child_invalid = _collect_success_flags(child)
            flags.extend(child_flags)
            invalid = invalid or child_invalid
    return flags, invalid


def _response_text(value: Any) -> str:
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    except TypeError:
        return ""
