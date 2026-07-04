from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class SimilarityDecision:
    method: str
    score: float
    reason: str
    matched: bool


class EmbeddingBackend(Protocol):
    def cosine_similarity(self, left_text: str, right_text: str) -> float:
        ...


def compare_text(
    *,
    left_text: str,
    left_normalized: str,
    left_hash: str,
    right_text: str,
    right_normalized: str,
    right_hash: str,
    embedding_backend: EmbeddingBackend | None = None,
    minimum_length: int = 8,
) -> SimilarityDecision:
    """速い比較から順に適用し、最初に十分な証拠が得られた手法を返す。"""
    if not left_normalized or not right_normalized:
        return SimilarityDecision("none", 0.0, "empty normalized text", False)

    shorter_length = min(len(left_normalized), len(right_normalized))
    if shorter_length < minimum_length:
        return SimilarityDecision(
            "none",
            0.0,
            f"text shorter than minimum_length={minimum_length}",
            False,
        )

    if left_hash == right_hash:
        return SimilarityDecision("exact", 1.0, "identical text hash", True)

    substring = _substring_match(left_normalized, right_normalized)
    if substring.matched:
        return substring

    shingle = _shingle_match(left_normalized, right_normalized)
    if shingle.matched:
        return shingle

    if embedding_backend is not None:
        score = embedding_backend.cosine_similarity(left_text, right_text)
        return SimilarityDecision(
            method="embedding_cosine",
            score=score,
            reason="embedding cosine similarity",
            matched=score >= 0.80,
        )

    return SimilarityDecision(
        method="none",
        score=0.0,
        reason="no method exceeded threshold",
        matched=False,
    )


def make_shingles(text: str, size: int = 5) -> set[str]:
    if len(text) < size:
        return {text} if text else set()
    return {text[index : index + size] for index in range(len(text) - size + 1)}


def _substring_match(left: str, right: str) -> SimilarityDecision:
    shorter, longer = sorted((left, right), key=len)
    if shorter not in longer:
        return SimilarityDecision("substring", 0.0, "substring not found", False)

    # 一致部分が短い一般語だけの場合を避けるため、長い側に占める割合も残す。
    coverage = len(shorter) / len(longer)
    score = 0.75 + (0.25 * coverage)
    return SimilarityDecision(
        method="substring",
        score=min(1.0, score),
        reason=f"shorter text appears in longer text; coverage={coverage:.4f}",
        matched=True,
    )


def _shingle_match(left: str, right: str) -> SimilarityDecision:
    left_shingles = make_shingles(left)
    right_shingles = make_shingles(right)
    if not left_shingles or not right_shingles:
        return SimilarityDecision("shingle_jaccard", 0.0, "missing shingles", False)

    overlap = len(left_shingles & right_shingles)
    union = len(left_shingles | right_shingles)
    score = overlap / union if union else 0.0
    return SimilarityDecision(
        method="shingle_jaccard",
        score=score,
        reason=f"5-gram Jaccard similarity; overlap={overlap}; union={union}",
        matched=score >= 0.30,
    )
