from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from hook_monitor.analysis.adapters.mcp import parse_mcp_tool_name
from hook_monitor.analysis.adapters.mcp_profiles import (
    DEFAULT_MCP_INPUT_LIMITS,
    DEFAULT_MCP_PROFILE_REGISTRY,
    McpInputLimits,
    McpProfileRegistry,
    inspect_mcp_input,
)
from hook_monitor.runtime.redaction_integrity import (
    canonical_json_bytes,
    sha256_bytes,
    structure_sha256,
)


@dataclass(frozen=True)
class PostRedactionInputComparison:
    """Bounded observation of one rendered MCP input at PostToolUse."""

    disposition: Literal["confirmed", "mismatch", "unobserved"]
    diagnostic_code: str | None = None


@dataclass(frozen=True)
class RedactionPostConfirmationResult:
    """Storage outcome for one PostToolUse confirmation attempt."""

    disposition: Literal[
        "not_applicable",
        "confirmed",
        "mismatch",
        "unobserved",
        "conflict",
    ]
    plan_id: str | None = None
    diagnostic_code: str | None = None
    replayed: bool = False


def compare_mcp_post_input(
    *,
    tool_name: str,
    tool_input: object,
    profile_id: str,
    profile_version: str,
    profile_registry_version: str,
    rewritten_input_sha256: str,
    structure_sha256_after: str,
    profile_registry: McpProfileRegistry = DEFAULT_MCP_PROFILE_REGISTRY,
    input_limits: McpInputLimits = DEFAULT_MCP_INPUT_LIMITS,
) -> PostRedactionInputComparison:
    """Compare only bounded, full inputs whose profile promises Post stability.

    This function does not read storage, perform I/O, or retain the observed
    input. An unbounded or semantically stale observation stays unconfirmed
    instead of being mislabeled as an override.
    """
    parsed_name = parse_mcp_tool_name(tool_name)
    profile = (
        profile_registry.resolve(*parsed_name)
        if parsed_name is not None
        else None
    )
    if profile is None:
        return PostRedactionInputComparison("unobserved", "unknown_profile")
    if (
        profile.profile_id != profile_id
        or profile.profile_version != profile_version
        or profile_registry.registry_version != profile_registry_version
    ):
        return PostRedactionInputComparison(
            "unobserved",
            "profile_version_mismatch",
        )
    if not profile.post_input_stable or profile.file_input_pointers:
        return PostRedactionInputComparison(
            "unobserved",
            "post_input_unstable",
        )

    try:
        inspection = inspect_mcp_input(tool_input, input_limits)
    except (TypeError, ValueError, UnicodeEncodeError):
        return PostRedactionInputComparison(
            "unobserved",
            "unsupported_input_type",
        )
    if not inspection.accepted or not isinstance(tool_input, dict):
        return PostRedactionInputComparison(
            "unobserved",
            inspection.rejection_code or "unsupported_input_type",
        )
    if any(not isinstance(key, str) for key in tool_input):
        return PostRedactionInputComparison(
            "unobserved",
            "unsupported_input_type",
        )

    canonical_input = canonical_json_bytes(tool_input)
    actual_input_sha256 = sha256_bytes(canonical_input)
    actual_structure_sha256 = structure_sha256(tool_input)
    if actual_input_sha256 is None or actual_structure_sha256 is None:
        return PostRedactionInputComparison(
            "unobserved",
            "unsupported_input_type",
        )
    if actual_input_sha256 != rewritten_input_sha256:
        return PostRedactionInputComparison("mismatch")
    if actual_structure_sha256 != structure_sha256_after:
        return PostRedactionInputComparison(
            "unobserved",
            "plan_integrity_mismatch",
        )
    if not profile.validate(tool_input).accepted:
        return PostRedactionInputComparison(
            "unobserved",
            "plan_integrity_mismatch",
        )
    return PostRedactionInputComparison("confirmed")
