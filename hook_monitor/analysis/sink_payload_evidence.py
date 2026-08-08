from __future__ import annotations

import hashlib
import time
from collections.abc import Mapping
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Literal

from hook_monitor.analysis.bash_submission_resolution import (
    BASH_SUBMISSION_RESOLVER_VERSION,
    resolve_bash_http_submissions,
)
from hook_monitor.analysis.similarity import compare_source_binding_text
from hook_monitor.runtime.models import SourceChunk
from hook_monitor.runtime.normalize import normalize_text


SINK_PAYLOAD_EVIDENCE_VERSION = (
    "sink-payload-evidence-v2-exact-containment-ephemeral"
)
MAX_SINK_PAYLOAD_EVIDENCE_SOURCE_CHUNKS = 512
MAX_SINK_PAYLOAD_EVIDENCE_SOURCE_CHUNK_BYTES = 32 * 1024
MAX_SINK_PAYLOAD_EVIDENCE_SOURCE_BYTES = 512 * 1024


@dataclass(frozen=True)
class SinkPayloadSourceMatch:
    source_node_kind: Literal["source_chunk"]
    source_node_id: str
    evidence_level: Literal["content_exact", "content_lexical"]
    method: Literal[
        "resolved_payload_exact",
        "resolved_payload_exact_substring",
    ]
    score: float


@dataclass(frozen=True)
class BashSinkPayloadEvidence:
    workspace_id: str
    sink_node_id: str
    segment_index: int
    resolution_status: Literal["evaluated", "unsupported"]
    comparison_status: Literal["evaluated", "unsupported", "not_run"]
    extraction: Literal["static_values", "resolved_file", "coarse_fallback"]
    snapshot_semantics: Literal[
        "tool_input_literal",
        "pre_execution_file_snapshot",
        "unresolved",
    ]
    resolver_version: str
    evidence_version: str
    submitted_value_count: int
    submitted_bytes: int
    matches: tuple[SinkPayloadSourceMatch, ...]
    resolution_reason: str | None
    comparison_reason: str | None
    inspection_duration_ms: float


def inspect_bash_sink_payload_evidence(
    command: str,
    *,
    workspace_root: Path,
    execution_cwd: Path,
    workspace_id: str,
    sink_node_ids_by_segment: Mapping[int, str],
    source_chunks: tuple[SourceChunk, ...],
) -> tuple[BashSinkPayloadEvidence, ...]:
    """Compare resolved curl payloads without returning or storing their values.

    Resolved values exist only inside this call. The returned evidence is safe
    to render or persist because it contains source identifiers and aggregate
    metadata, never payload text or payload-derived hashes. Chunks from another
    workspace are ignored even if their values match.
    """
    if not workspace_id:
        raise ValueError("workspace_id must be non-empty")
    if (
        not isinstance(sink_node_ids_by_segment, Mapping)
        or any(
            type(segment_index) is not int
            or segment_index < 0
            or not isinstance(sink_node_id, str)
            or not sink_node_id
            or len(sink_node_id.encode("utf-8", errors="surrogatepass")) > 1024
            for segment_index, sink_node_id in sink_node_ids_by_segment.items()
        )
    ):
        raise ValueError("sink node mapping must contain bounded segment identities")
    started_at = time.monotonic()
    scoped_chunks = tuple(
        sorted(
            (
                chunk
                for chunk in source_chunks
                if chunk.workspace_id == workspace_id
            ),
            key=lambda item: item.chunk_id,
        )
    )
    comparison_limit_reason = _source_comparison_limit_reason(scoped_chunks)

    projections = resolve_bash_http_submissions(
        command,
        workspace_root=workspace_root,
        execution_cwd=execution_cwd,
    )
    evidence: list[BashSinkPayloadEvidence] = []
    for projection in projections:
        sink_node_id = sink_node_ids_by_segment.get(projection.segment_index)
        if sink_node_id is None:
            raise ValueError("resolved segment has no sink node identity")
        if projection.status == "unsupported":
            evidence.append(
                BashSinkPayloadEvidence(
                    workspace_id=workspace_id,
                    sink_node_id=sink_node_id,
                    segment_index=projection.segment_index,
                    resolution_status="unsupported",
                    comparison_status="not_run",
                    extraction="coarse_fallback",
                    snapshot_semantics="unresolved",
                    resolver_version=BASH_SUBMISSION_RESOLVER_VERSION,
                    evidence_version=SINK_PAYLOAD_EVIDENCE_VERSION,
                    submitted_value_count=0,
                    submitted_bytes=0,
                    matches=(),
                    resolution_reason=projection.unsupported_reason,
                    comparison_reason=None,
                    inspection_duration_ms=0.0,
                )
            )
            continue

        matches: dict[str, SinkPayloadSourceMatch] = {}
        submitted_bytes = 0
        for value in projection.submitted_values:
            encoded = value.encode("utf-8")
            submitted_bytes += len(encoded)
            if comparison_limit_reason is not None:
                continue
            value_hash = hashlib.sha256(encoded).hexdigest()
            value_normalized = normalize_text(value)
            for chunk in scoped_chunks:
                if chunk.text == value:
                    match = SinkPayloadSourceMatch(
                        source_node_kind="source_chunk",
                        source_node_id=chunk.chunk_id,
                        evidence_level="content_exact",
                        method="resolved_payload_exact",
                        score=1.0,
                    )
                elif chunk.text in value:
                    decision = compare_source_binding_text(
                        source_binding_signal=chunk.source_binding_signal,
                        left_text=chunk.text,
                        left_normalized=chunk.normalized_text,
                        left_hash=chunk.text_hash,
                        right_text=value,
                        right_normalized=value_normalized,
                        right_hash=value_hash,
                        embedding_backend=None,
                        minimum_length=4,
                    )
                    if not decision.matched or decision.method != "substring":
                        continue
                    match = SinkPayloadSourceMatch(
                        source_node_kind="source_chunk",
                        source_node_id=chunk.chunk_id,
                        evidence_level="content_lexical",
                        method="resolved_payload_exact_substring",
                        score=decision.score,
                    )
                else:
                    continue
                previous = matches.get(chunk.chunk_id)
                if previous is None or _match_sort_key(match) < _match_sort_key(
                    previous
                ):
                    matches[chunk.chunk_id] = match

        evidence.append(
            BashSinkPayloadEvidence(
                workspace_id=workspace_id,
                sink_node_id=sink_node_id,
                segment_index=projection.segment_index,
                resolution_status="evaluated",
                comparison_status=(
                    "unsupported"
                    if comparison_limit_reason is not None
                    else "evaluated"
                ),
                extraction=projection.extraction,
                snapshot_semantics=(
                    "pre_execution_file_snapshot"
                    if projection.extraction == "resolved_file"
                    else "tool_input_literal"
                ),
                resolver_version=BASH_SUBMISSION_RESOLVER_VERSION,
                evidence_version=SINK_PAYLOAD_EVIDENCE_VERSION,
                submitted_value_count=len(projection.submitted_values),
                submitted_bytes=submitted_bytes,
                matches=tuple(matches[key] for key in sorted(matches)),
                resolution_reason=None,
                comparison_reason=comparison_limit_reason,
                inspection_duration_ms=0.0,
            )
        )

    total_duration = _duration_ms(started_at)
    return tuple(
        replace(item, inspection_duration_ms=total_duration)
        for item in evidence
    )


def _duration_ms(started_at: float) -> float:
    return max(0.0, (time.monotonic() - started_at) * 1000)


def _source_comparison_limit_reason(
    chunks: tuple[SourceChunk, ...],
) -> str | None:
    if len(chunks) > MAX_SINK_PAYLOAD_EVIDENCE_SOURCE_CHUNKS:
        return "source_chunk_count_exceeded"
    total_bytes = 0
    for chunk in chunks:
        try:
            chunk_bytes = len(chunk.text.encode("utf-8"))
        except UnicodeEncodeError:
            return "source_chunk_invalid_unicode"
        if chunk_bytes > MAX_SINK_PAYLOAD_EVIDENCE_SOURCE_CHUNK_BYTES:
            return "source_chunk_bytes_exceeded"
        total_bytes += chunk_bytes
        if total_bytes > MAX_SINK_PAYLOAD_EVIDENCE_SOURCE_BYTES:
            return "source_total_bytes_exceeded"
    return None


def _match_sort_key(match: SinkPayloadSourceMatch) -> tuple[int, float]:
    return (
        0 if match.method == "resolved_payload_exact" else 1,
        -match.score,
    )
