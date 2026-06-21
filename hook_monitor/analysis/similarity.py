from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Protocol

from hook_monitor.runtime.models import ArtifactRecord, FlowEdge, SourceChunk


@dataclass(frozen=True)
class SimilarityDecision:
    method: str
    score: float
    reason: str
    matched: bool


class EmbeddingBackend(Protocol):
    def cosine_similarity(self, left_text: str, right_text: str) -> float:
        ...


def compare_source_chunk_to_artifact(
    source_chunk: SourceChunk,
    artifact: ArtifactRecord,
    embedding_backend: EmbeddingBackend | None = None,
) -> SimilarityDecision:
    # 速いものから順に当てるカスケード方式にしている。
    # exact / substring で拾えるものはそこで止め、重い比較は後段に回す。
    exact = _exact_match(source_chunk, artifact)
    if exact.matched:
        return exact

    substring = _substring_match(source_chunk, artifact)
    if substring.matched:
        return substring

    shingle = _shingle_match(source_chunk, artifact)
    if shingle.matched:
        return shingle

    if embedding_backend is not None:
        embedding = _embedding_match(source_chunk, artifact, embedding_backend)
        if embedding.matched:
            return embedding

    return SimilarityDecision(
        method="none",
        score=0.0,
        reason="no method exceeded threshold",
        matched=False,
    )


def build_flow_edge(
    source_chunk: SourceChunk,
    artifact: ArtifactRecord,
    decision: SimilarityDecision,
) -> FlowEdge:
    # 比較が通ったら source_chunk -> artifact の edge として保存する。
    return FlowEdge(
        edge_id=f"{source_chunk.chunk_id}->{artifact.artifact_id}:{decision.method}",
        src_node_kind="source_chunk",
        src_node_id=source_chunk.chunk_id,
        dst_artifact_id=artifact.artifact_id,
        method=decision.method,
        score=decision.score,
        reason=decision.reason,
    )


def _exact_match(source_chunk: SourceChunk, artifact: ArtifactRecord) -> SimilarityDecision:
    # .env の値や完全一致のコード断片はここで拾う。
    matched = source_chunk.text_hash == artifact.text_hash
    return SimilarityDecision(
        method="exact",
        score=1.0 if matched else 0.0,
        reason="identical text hash" if matched else "text hash mismatch",
        matched=matched,
    )


def _substring_match(source_chunk: SourceChunk, artifact: ArtifactRecord) -> SimilarityDecision:
    # source の一部がほぼそのまま後続 artifact に混ざったケースを拾う。
    if not source_chunk.normalized_text or not artifact.normalized_text:
        return SimilarityDecision("substring", 0.0, "empty normalized text", False)

    if source_chunk.normalized_text in artifact.normalized_text:
        coverage = len(source_chunk.normalized_text) / max(len(artifact.normalized_text), 1)
        return SimilarityDecision(
            method="substring",
            score=min(1.0, coverage),
            reason="source chunk appears as substring in artifact",
            matched=True,
        )
    return SimilarityDecision("substring", 0.0, "substring not found", False)


def _shingle_match(source_chunk: SourceChunk, artifact: ArtifactRecord) -> SimilarityDecision:
    # 少し崩れたコピーや近い再利用を 5-gram Jaccard で拾う。
    # exact や substring より遅いが、embedding よりは軽い。
    source_shingles = set(json.loads(source_chunk.shingle_fingerprint))
    artifact_shingles = _make_shingles(artifact.normalized_text, size=5)
    if not source_shingles or not artifact_shingles:
        return SimilarityDecision("shingle_jaccard", 0.0, "missing shingles", False)

    overlap = len(source_shingles & artifact_shingles)
    union = len(source_shingles | artifact_shingles)
    score = overlap / union if union else 0.0
    return SimilarityDecision(
        method="shingle_jaccard",
        score=score,
        reason="5-gram Jaccard similarity",
        matched=score >= 0.30,
    )


def _embedding_match(
    source_chunk: SourceChunk,
    artifact: ArtifactRecord,
    embedding_backend: EmbeddingBackend,
) -> SimilarityDecision:
    # 意味的な言い換えや要約を拾うための拡張ポイント。
    # 現状は backend を差し込んだ時だけ使う。
    score = embedding_backend.cosine_similarity(source_chunk.text, artifact.text)
    return SimilarityDecision(
        method="embedding_cosine",
        score=score,
        reason="embedding cosine similarity",
        matched=score >= 0.80,
    )


def _make_shingles(text: str, size: int) -> set[str]:
    # artifact 側の shingle は runtime では持たないので、その場で作る。
    if len(text) < size:
        return {text} if text else set()
    return {text[index : index + size] for index in range(len(text) - size + 1)}
