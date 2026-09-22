from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal

from hook_monitor.analysis.adapters.mcp import parse_mcp_tool_name
from hook_monitor.analysis.adapters.mcp_profiles import (
    DEFAULT_MCP_INPUT_LIMITS,
    DEFAULT_MCP_PROFILE_REGISTRY,
    MCP_TOOL_NAME_MAX_BYTES,
    McpInputLimits,
    McpProfileRegistry,
    inspect_mcp_input,
)
from hook_monitor.runtime.redaction_integrity import (
    canonical_json_bytes,
    sha256_bytes,
    structure_sha256,
)

_LOWER_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
REDACTION_POST_INPUT_OBSERVER_VERSION = "mcp-post-input-observer-v1"
REDACTION_POST_INPUT_DIAGNOSTIC_CODES = frozenset(
    {
        "field_count_exceeded",
        "input_bytes_exceeded",
        "input_not_object",
        "nesting_depth_exceeded",
        "post_input_unstable",
        "post_payload_bytes_exceeded",
        "unknown_profile",
        "unsupported_input_type",
    }
)


@dataclass(frozen=True)
class PostRedactionInputObservation:
    """Hash-only, bounded observation derived while a Post event is recorded."""

    status: Literal["not_applicable", "captured", "unobserved"]
    observer_version: str | None = None
    diagnostic_code: str | None = None
    profile_id: str | None = None
    profile_version: str | None = None
    profile_registry_version: str | None = None
    input_bytes: int | None = None
    input_sha256: str | None = None
    structure_sha256: str | None = None


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


def observe_mcp_post_input(
    *,
    tool_name: str,
    tool_input: object,
    profile_registry: McpProfileRegistry = DEFAULT_MCP_PROFILE_REGISTRY,
    input_limits: McpInputLimits = DEFAULT_MCP_INPUT_LIMITS,
) -> PostRedactionInputObservation:
    """Derive bounded confirmation hashes without retaining the observed input.

    The caller can persist this value beside the event in the same transaction.
    Inputs outside the exact stable-profile boundary retain only a fixed
    diagnostic code.
    """
    if not _is_bounded_identifier(tool_name):
        return _unobserved_post_input("unknown_profile")
    parsed_name = parse_mcp_tool_name(tool_name)
    profile = (
        profile_registry.resolve(*parsed_name)
        if parsed_name is not None
        else None
    )
    if profile is None:
        return _unobserved_post_input("unknown_profile")
    if not profile.post_input_stable or profile.file_input_pointers:
        return _unobserved_post_input("post_input_unstable")

    if not isinstance(tool_input, dict):
        return _unobserved_post_input("input_not_object")
    try:
        inspection = inspect_mcp_input(tool_input, input_limits)
    except (TypeError, ValueError, UnicodeEncodeError):
        return _unobserved_post_input("unsupported_input_type")
    if not inspection.accepted:
        return _unobserved_post_input(
            inspection.rejection_code or "unsupported_input_type"
        )
    if any(not isinstance(key, str) for key in tool_input):
        return _unobserved_post_input("unsupported_input_type")
    canonical_input = canonical_json_bytes(tool_input)
    actual_input_sha256 = sha256_bytes(canonical_input)
    actual_structure_sha256 = structure_sha256(tool_input)
    if actual_input_sha256 is None or actual_structure_sha256 is None:
        return _unobserved_post_input("unsupported_input_type")
    return PostRedactionInputObservation(
        "captured",
        observer_version=REDACTION_POST_INPUT_OBSERVER_VERSION,
        profile_id=profile.profile_id,
        profile_version=profile.profile_version,
        profile_registry_version=profile_registry.registry_version,
        input_bytes=inspection.input_bytes,
        input_sha256=actual_input_sha256,
        structure_sha256=actual_structure_sha256,
    )


def compare_mcp_post_observation(
    *,
    tool_name: str,
    observation: PostRedactionInputObservation,
    profile_id: str,
    profile_version: str,
    profile_registry_version: str,
    rewritten_input_sha256: str,
    structure_sha256_after: str,
    profile_registry: McpProfileRegistry = DEFAULT_MCP_PROFILE_REGISTRY,
    input_limits: McpInputLimits = DEFAULT_MCP_INPUT_LIMITS,
) -> PostRedactionInputComparison:
    """Compare one persisted hash-only observation with a rendered plan."""
    if not _is_bounded_identifier(tool_name):
        return PostRedactionInputComparison("unobserved", "unknown_profile")
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
    if observation.status == "unobserved":
        if (
            observation.observer_version
            != REDACTION_POST_INPUT_OBSERVER_VERSION
            or observation.diagnostic_code
            not in REDACTION_POST_INPUT_DIAGNOSTIC_CODES
            or any(
                value is not None
                for value in (
                    observation.profile_id,
                    observation.profile_version,
                    observation.profile_registry_version,
                    observation.input_bytes,
                    observation.input_sha256,
                    observation.structure_sha256,
                )
            )
        ):
            return PostRedactionInputComparison(
                "unobserved",
                "post_input_metadata_invalid",
            )
        return PostRedactionInputComparison(
            "unobserved",
            observation.diagnostic_code,
        )
    if observation.status != "captured" or observation.diagnostic_code is not None:
        return PostRedactionInputComparison(
            "unobserved",
            "post_input_metadata_unavailable",
        )
    if (
        observation.observer_version
        != REDACTION_POST_INPUT_OBSERVER_VERSION
        or not _is_bounded_identifier(observation.profile_id)
        or not _is_bounded_identifier(observation.profile_version)
        or not _is_bounded_identifier(observation.profile_registry_version)
    ):
        return PostRedactionInputComparison(
            "unobserved",
            "post_input_metadata_invalid",
        )
    if (
        observation.profile_id != profile.profile_id
        or observation.profile_version != profile.profile_version
        or observation.profile_registry_version
        != profile_registry.registry_version
    ):
        return PostRedactionInputComparison(
            "unobserved",
            "profile_version_mismatch",
        )
    if (
        type(observation.input_bytes) is not int
        or not 0 <= observation.input_bytes <= input_limits.max_input_bytes
        or not isinstance(observation.input_sha256, str)
        or _LOWER_SHA256_RE.fullmatch(observation.input_sha256) is None
        or not isinstance(observation.structure_sha256, str)
        or _LOWER_SHA256_RE.fullmatch(observation.structure_sha256) is None
    ):
        return PostRedactionInputComparison(
            "unobserved",
            "post_input_metadata_invalid",
        )
    if observation.input_sha256 != rewritten_input_sha256:
        return PostRedactionInputComparison("mismatch")
    if observation.structure_sha256 != structure_sha256_after:
        return PostRedactionInputComparison(
            "unobserved",
            "plan_integrity_mismatch",
        )
    return PostRedactionInputComparison("confirmed")


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
    """Compare a bounded in-memory Post input without retaining plaintext."""
    observation = observe_mcp_post_input(
        tool_name=tool_name,
        tool_input=tool_input,
        profile_registry=profile_registry,
        input_limits=input_limits,
    )
    return compare_mcp_post_observation(
        tool_name=tool_name,
        observation=observation,
        profile_id=profile_id,
        profile_version=profile_version,
        profile_registry_version=profile_registry_version,
        rewritten_input_sha256=rewritten_input_sha256,
        structure_sha256_after=structure_sha256_after,
        profile_registry=profile_registry,
        input_limits=input_limits,
    )


def _unobserved_post_input(
    diagnostic_code: str,
) -> PostRedactionInputObservation:
    if diagnostic_code not in REDACTION_POST_INPUT_DIAGNOSTIC_CODES:
        diagnostic_code = "unsupported_input_type"
    return PostRedactionInputObservation(
        "unobserved",
        observer_version=REDACTION_POST_INPUT_OBSERVER_VERSION,
        diagnostic_code=diagnostic_code,
    )


def _is_bounded_identifier(value: object) -> bool:
    if not isinstance(value, str) or not value:
        return False
    if len(value) > MCP_TOOL_NAME_MAX_BYTES:
        return False
    try:
        return len(value.encode("utf-8")) <= MCP_TOOL_NAME_MAX_BYTES
    except UnicodeEncodeError:
        return False
