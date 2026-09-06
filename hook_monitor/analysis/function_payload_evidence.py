"""Closed literal-data contracts; never infer arbitrary function safety from text."""

from __future__ import annotations

from hook_monitor.analysis.adapters.mcp_profiles import inspect_mcp_input
from hook_monitor.analysis.mcp_payload_evidence import (
    McpPayloadVerification,
    verify_mcp_payload_against_sources,
)
from hook_monitor.runtime.models import SourceChunk


FUNCTION_PAYLOAD_CONTRACT_VERSION = "literal-question-payload-v1"


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
    for question in questions:
        if (
            not isinstance(question, dict) or not {"title"} <= set(question) <= {"title", "options"}
            or not isinstance(question["title"], str) or not question["title"].strip()
        ):
            return unsupported
        if "options" in question:
            options = question["options"]
            if (
                not isinstance(options, list) or not 1 <= len(options) <= 16
                or any(not isinstance(item, str) or not item.strip() for item in options)
            ):
                return unsupported
    return verify_mcp_payload_against_sources(payload, source_chunks)
