from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass
from typing import Literal

from hook_monitor.analysis.adapters.mcp_profiles import inspect_mcp_input
from hook_monitor.analysis.similarity import (
    compare_source_binding_text,
)
from hook_monitor.analysis.sink_payload_evidence import (
    source_comparison_limit_reason,
)
from hook_monitor.runtime.models import SourceChunk
from hook_monitor.runtime.normalize import normalize_text


MCP_PAYLOAD_VERIFICATION_VERSION = "mcp-payload-verification-v1"
DEFAULT_MCP_PAYLOAD_VERIFICATION_TIME_BUDGET_MS = 200


@dataclass(frozen=True)
class McpPayloadVerification:
    status: Literal["safe", "matched", "unsupported"]
    reason: str | None
    compared_value_count: int


def verify_mcp_payload_against_sources(
    payload: object,
    source_chunks: tuple[SourceChunk, ...],
    *,
    time_budget_ms: int = DEFAULT_MCP_PAYLOAD_VERIFICATION_TIME_BUDGET_MS,
) -> McpPayloadVerification:
    """Compare every bounded MCP scalar and key with every bounded source chunk."""

    inspection = inspect_mcp_input(payload)
    if not inspection.accepted:
        return McpPayloadVerification(
            "unsupported",
            inspection.rejection_code or "input_rejected",
            0,
        )
    comparison_limit = source_comparison_limit_reason(source_chunks)
    if comparison_limit is not None:
        return McpPayloadVerification("unsupported", comparison_limit, 0)
    assert isinstance(payload, dict)
    values = _bounded_scalar_texts(payload)
    prepared_values = tuple(
        (
            value,
            normalize_text(value),
            hashlib.sha256(value.encode("utf-8")).hexdigest(),
        )
        for value in values
    )
    deadline = time.monotonic() + max(1, time_budget_ms) / 1000
    comparisons = 0
    for chunk in source_chunks:
        for value, normalized, value_hash in prepared_values:
            if time.monotonic() >= deadline:
                return McpPayloadVerification(
                    "unsupported",
                    "comparison_time_budget_exceeded",
                    comparisons,
                )
            comparisons += 1
            if chunk.text == value or chunk.text in value:
                return McpPayloadVerification("matched", None, comparisons)
            decision = compare_source_binding_text(
                source_binding_signal=chunk.source_binding_signal,
                left_text=chunk.text,
                left_normalized=chunk.normalized_text,
                left_hash=chunk.text_hash,
                right_text=value,
                right_normalized=normalized,
                right_hash=value_hash,
                embedding_backend=None,
                minimum_length=4,
            )
            if decision.matched:
                return McpPayloadVerification("matched", None, comparisons)
    return McpPayloadVerification("safe", None, comparisons)


def _bounded_scalar_texts(payload: dict[str, object]) -> tuple[str, ...]:
    values: set[str] = set()
    stack: list[object] = [payload]
    while stack:
        value = stack.pop()
        if isinstance(value, dict):
            for key, child in value.items():
                values.add(str(key))
                stack.append(child)
        elif isinstance(value, list):
            stack.extend(value)
        elif isinstance(value, str):
            values.add(value)
        elif isinstance(value, (bool, int, float)) or value is None:
            values.add(
                json.dumps(
                    value,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                    allow_nan=False,
                )
            )
        else:  # inspect_mcp_input rejects unsupported values first.
            raise TypeError("unsupported MCP scalar")
    return tuple(sorted(values))
