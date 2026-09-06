"""Closed literal-data contracts; never infer arbitrary function safety from text."""

from __future__ import annotations

from hook_monitor.analysis.adapters.mcp_profiles import inspect_mcp_input
from hook_monitor.analysis.mcp_payload_evidence import (
    McpPayloadVerification,
    verify_mcp_payload_against_sources,
)
from hook_monitor.runtime.models import SourceChunk


FUNCTION_PAYLOAD_CONTRACT_VERSION = "literal-question-payload-v2-rendered"


def verify_literal_function_payload(
    tool_name: str | None, payload: object, source_chunks: tuple[SourceChunk, ...],
) -> McpPayloadVerification:
    """Only the confirmed built-in question form has no indirect execution input.

    Names are exact, without suffix/prefix matching. Text and options are display
    values, not commands, file references, or tool-selection instructions. Unknown
    tools (including code execution), schema extensions and resource limits retain
    the conservative unresolved decision.
    """
    unsupported = McpPayloadVerification("unsupported", "unknown_function_contract", 0)
    if tool_name != "request_user_input_async" or not inspect_mcp_input(payload).accepted:
        return unsupported
    if not isinstance(payload, dict) or set(payload) != {"questions"}:
        return unsupported
    questions = payload["questions"]
    if not isinstance(questions, list) or not 1 <= len(questions) <= 16:
        return unsupported
    displayed: list[str] = []
    for question in questions:
        if (
            not isinstance(question, dict) or not {"title"} <= set(question) <= {"title", "options"}
            or not isinstance(question["title"], str) or not question["title"].strip()
        ):
            return unsupported
        displayed.append(question["title"])
        if "options" in question:
            options = question["options"]
            if (
                not isinstance(options, list) or not 1 <= len(options) <= 16
                or any(not isinstance(item, str) or not item.strip() for item in options)
            ):
                return unsupported
            displayed.extend(options)
    # Keep every original key and scalar, and also compare the complete display
    # in order. Per-scalar comparisons alone miss short fragments distributed
    # across titles/options. These additional views are comparison-only: they
    # never change the tool input and retain the same byte/field/time limits.
    # Preserve duplicates and question order; a set or sorted view is unsafe.
    comparison_payload = {
        "questions": [*questions, "".join(displayed), "\n".join(displayed)],
    }
    return verify_mcp_payload_against_sources(comparison_payload, source_chunks)
