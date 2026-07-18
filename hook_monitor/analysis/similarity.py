from __future__ import annotations

import hashlib
import unicodedata
from collections.abc import Iterable
from dataclasses import dataclass, field
from functools import cmp_to_key
from typing import Protocol


SIMILARITY_PROFILE_VERSION = "similarity-profile-v2"
SIMILARITY_SHINGLE_SIZE = 5
SIMILARITY_SHINGLE_THRESHOLD = 0.30
SIMILARITY_TOKEN_EQUIVALENT_SCORE = 0.85
SIMILARITY_PROSE_SUBSTRING_MIN_COVERAGE = 0.90
SIMILARITY_CANONICAL_MAX_CHARS = 16 * 1024
SIMILARITY_MAX_CANDIDATE_FEATURES = SIMILARITY_CANONICAL_MAX_CHARS

_FEATURE_NAMESPACE = f"c{SIMILARITY_SHINGLE_SIZE}:"
_EXACT_KEY_DOMAIN = f"{SIMILARITY_PROFILE_VERSION}:primary-exact\0".encode("ascii")
_RAW_EXACT_KEY_DOMAIN = f"{SIMILARITY_PROFILE_VERSION}:raw-exact\0".encode("ascii")
_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")
_IDENTIFIER_SEPARATORS = frozenset("._-/ ")
_NEGATION_TOKENS = frozenset(
    {
        "deny",
        "denied",
        "denies",
        "disable",
        "disabled",
        "disallow",
        "except",
        "false",
        "forbid",
        "forbidden",
        "never",
        "no",
        "not",
        "reject",
        "rejected",
        "rejects",
        "revoke",
        "revoked",
        "revokes",
        "revoking",
        "unless",
        "without",
    }
)
_NUMBER_ALIASES = {
    "zero": "0",
    "one": "1",
    "two": "2",
    "three": "3",
    "four": "4",
    "five": "5",
    "six": "6",
    "seven": "7",
    "eight": "8",
    "nine": "9",
    "ten": "10",
}
_EXPLICIT_TOKEN_ALIASES = {
    "sequence": "sequence",
    "sequences": "sequence",
}
_NUMERIC_SECRET_LABELS = (
    ("api", "key"),
    ("password",),
    ("access", "token"),
    ("client", "secret"),
)
_LOW_INFORMATION_NUMERIC_LABELS = frozenset({"invoice", "release", "status", "version"})
_EXPLICIT_SECURITY_VALUE_TOKENS = frozenset({"credential", "password", "secret", "token"})
_GENERIC_SECURITY_TOKENS = frozenset(
    {
        "access",
        "account",
        "api",
        "auth",
        "authentication",
        "authorization",
        "bearer",
        "client",
        "credential",
        "credentials",
        "database",
        "field",
        "header",
        "identifier",
        "key",
        "metadata",
        "password",
        "policy",
        "private",
        "production",
        "public",
        "secret",
        "service",
        "token",
        "value",
    }
)


@dataclass(frozen=True)
class SimilarityDecision:
    method: str
    score: float
    reason: str
    matched: bool


@dataclass(frozen=True)
class PreparedSimilarityText:
    """Value-bearing comparison material kept out of normal object repr output.

    Added canonical work is limited to ``SIMILARITY_CANONICAL_MAX_CHARS``.
    Longer inputs use a domain-separated raw-text exact key and emit no
    candidate features. Bounded comparison representations are aligned stages
    of one pipeline and are never compared across different decoding depths.
    Low-information security phrases intentionally have no candidate features
    and can only meet again through the exact index.
    """

    primary_exact_key: str
    candidate_features: frozenset[str] = field(repr=False)
    representations: tuple[str, ...] = field(repr=False)
    canonicalization_bounded: bool


@dataclass(frozen=True)
class SimilarityCandidateStats:
    candidate_id: str
    overlap_count: int
    candidate_feature_count: int
    candidate_normalized_length: int


class EmbeddingBackend(Protocol):
    def cosine_similarity(self, left_text: str, right_text: str) -> float: ...


def prepare_similarity_text(
    text: str,
    *,
    normalized_text: str | None = None,
) -> PreparedSimilarityText:
    """Prepare one exact key and a bounded, origin-independent feature set.

    The function is linear in the supplied text. Compatibility, percent, JSON,
    and identifier transformations are attempted only for bounded inputs and
    never repeatedly decoded. Candidate features come from the single final
    canonical form; the NFKC, one-pass percent, JSON slash, and identifier stages
    are retained in fixed order for same-stage pair comparison. Unbounded inputs
    use a raw-text exact key and no lexical features, so the candidate index
    cannot claim approximate eligibility that pair comparison rejects.
    Low-information security phrases also emit no lexical features. Feature
    count is capped independently from the Hook payload limit.
    """
    if not isinstance(text, str):
        raise TypeError("similarity text must be a string")
    if normalized_text is not None and not isinstance(normalized_text, str):
        raise TypeError("normalized similarity text must be a string")

    primary = _normalize_basic(text) if normalized_text is None else normalized_text
    bounded = (
        len(text) <= SIMILARITY_CANONICAL_MAX_CHARS
        and len(primary) <= SIMILARITY_CANONICAL_MAX_CHARS
    )
    canonical = primary
    representations: tuple[str, ...] = (primary,)
    if bounded:
        nfkc = _bounded_nfkc_normalize(text)
        if nfkc is None:
            bounded = False
        else:
            percent_stage = nfkc
            decoded = _decode_complete_percent_transport(text)
            if decoded is not None:
                decoded_nfkc = _bounded_nfkc_normalize(decoded)
                if decoded_nfkc is None:
                    bounded = False
                else:
                    percent_stage = decoded_nfkc

            if bounded:
                json_stage = percent_stage.replace("\\/", "/")
                identifier_signature = (
                    _canonicalize_identifier_comparison(json_stage)
                    if not _is_low_information_exact_only_text(json_stage)
                    else None
                )
                identifier_stage = identifier_signature or json_stage
                representations = (
                    nfkc,
                    percent_stage,
                    json_stage,
                    identifier_stage,
                )
                canonical = identifier_stage
                if any(
                    _is_low_information_exact_only_text(representation)
                    for representation in representations
                ):
                    canonical = primary

    if not bounded:
        canonical = primary
        representations = (primary,)

    exact_key_domain = _EXACT_KEY_DOMAIN if bounded else _RAW_EXACT_KEY_DOMAIN
    exact_key_text = canonical if bounded else text
    exact_key = hashlib.sha256(exact_key_domain + exact_key_text.encode("utf-8")).hexdigest()
    low_information = any(
        _is_low_information_exact_only_text(representation) for representation in representations
    )
    features = (
        frozenset()
        if not bounded or low_information
        else frozenset(
            f"{_FEATURE_NAMESPACE}{shingle}"
            for feature_text in _candidate_feature_windows(canonical)
            for shingle in make_shingles(feature_text, SIMILARITY_SHINGLE_SIZE)
        )
    )
    if len(features) > SIMILARITY_MAX_CANDIDATE_FEATURES:
        raise RuntimeError("similarity candidate feature bound exceeded")
    return PreparedSimilarityText(
        primary_exact_key=exact_key,
        candidate_features=features,
        representations=representations,
        canonicalization_bounded=bounded,
    )


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
    """Apply bounded deterministic evidence before optional semantic evidence."""
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

    left = prepare_similarity_text(left_text, normalized_text=left_normalized)
    right = prepare_similarity_text(right_text, normalized_text=right_normalized)
    if not left.canonicalization_bounded or not right.canonicalization_bounded:
        return SimilarityDecision(
            "none",
            0.0,
            "canonicalization limit exceeded; raw exact match required",
            False,
        )
    if _has_aligned_content_conflict(left.representations, right.representations):
        return SimilarityDecision(
            "none",
            0.0,
            "comparison rejected by aligned canonical content conflict",
            False,
        )
    if left.primary_exact_key == right.primary_exact_key:
        return SimilarityDecision(
            "exact",
            1.0,
            "identical canonical representation",
            True,
        )

    if _has_low_information_representation(left) or _has_low_information_representation(right):
        return SimilarityDecision(
            "none",
            0.0,
            "low-information security phrase requires exact match",
            False,
        )

    substring = _best_substring_match(left.representations, right.representations)
    if substring.matched:
        return substring
    if _has_rejected_low_signal_containment(
        left.representations,
        right.representations,
    ):
        return SimilarityDecision(
            "none",
            0.0,
            "low-signal prose containment rejected",
            False,
        )

    token_equivalent = _best_token_equivalent_match(
        left.representations,
        right.representations,
    )
    if token_equivalent.matched:
        return token_equivalent

    shingle, conflict = _best_shingle_match(
        left.representations,
        right.representations,
    )
    if conflict:
        return SimilarityDecision(
            "none",
            0.0,
            "lexical similarity rejected by deterministic content conflict",
            False,
        )
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


def rank_similarity_candidate_ids(
    *,
    query_feature_count: int,
    query_normalized_length: int,
    minimum_length: int,
    candidates: Iterable[SimilarityCandidateStats],
    limit: int,
) -> tuple[str, ...]:
    """Select deterministic coverage and raw-overlap retrieval objectives."""
    _require_nonnegative_int(query_feature_count, "query_feature_count")
    _require_nonnegative_int(query_normalized_length, "query_normalized_length")
    _require_positive_int(minimum_length, "minimum_length")
    _require_nonnegative_int(limit, "limit")
    if query_feature_count == 0 or query_normalized_length < minimum_length or limit == 0:
        return ()

    materialized = tuple(candidates)
    seen_ids: set[str] = set()
    for candidate in materialized:
        if not isinstance(candidate, SimilarityCandidateStats):
            raise TypeError("candidates must contain SimilarityCandidateStats")
        if not isinstance(candidate.candidate_id, str) or not candidate.candidate_id:
            raise ValueError("candidate_id must be a non-empty string")
        if candidate.candidate_id in seen_ids:
            raise ValueError("candidate_id values must be unique")
        seen_ids.add(candidate.candidate_id)
        _require_positive_int(candidate.overlap_count, "overlap_count")
        _require_positive_int(
            candidate.candidate_feature_count,
            "candidate_feature_count",
        )
        _require_nonnegative_int(
            candidate.candidate_normalized_length,
            "candidate_normalized_length",
        )
        denominator = min(query_feature_count, candidate.candidate_feature_count)
        if candidate.overlap_count > denominator:
            raise ValueError("overlap_count must not exceed the smaller feature count")

    eligible = tuple(
        candidate
        for candidate in materialized
        if candidate.candidate_normalized_length >= minimum_length
    )
    coverage_ranked = sorted(
        eligible,
        key=cmp_to_key(
            lambda left, right: _compare_candidate_stats(
                left,
                right,
                query_feature_count=query_feature_count,
            )
        ),
    )
    overlap_ranked = sorted(
        eligible,
        key=cmp_to_key(
            lambda left, right: _compare_candidate_stats_by_overlap(
                left,
                right,
                query_feature_count=query_feature_count,
            )
        ),
    )
    coverage_quota = (limit + 1) // 2
    overlap_quota = limit // 2
    selected: list[str] = []
    selected_ids: set[str] = set()

    def extend_unique(
        candidates_to_add: Iterable[SimilarityCandidateStats],
        *,
        maximum_additions: int | None = None,
    ) -> None:
        if maximum_additions == 0:
            return
        additions = 0
        for candidate in candidates_to_add:
            if candidate.candidate_id in selected_ids:
                continue
            selected.append(candidate.candidate_id)
            selected_ids.add(candidate.candidate_id)
            additions += 1
            if maximum_additions is not None and additions >= maximum_additions:
                break

    extend_unique(coverage_ranked, maximum_additions=coverage_quota)
    extend_unique(overlap_ranked, maximum_additions=overlap_quota)
    for candidate in coverage_ranked:
        if len(selected) >= limit:
            break
        extend_unique((candidate,))
    return tuple(selected)


def make_shingles(text: str, size: int = SIMILARITY_SHINGLE_SIZE) -> set[str]:
    if len(text) < size:
        return {text} if text else set()
    return {text[index : index + size] for index in range(len(text) - size + 1)}


def _best_substring_match(
    left_representations: tuple[str, ...],
    right_representations: tuple[str, ...],
) -> SimilarityDecision:
    best = SimilarityDecision("substring", 0.0, "substring not found", False)
    for left, right in zip(
        left_representations,
        right_representations,
        strict=True,
    ):
        decision = _substring_match(left, right)
        if decision.matched and decision.score > best.score:
            best = decision
    return best


def _best_token_equivalent_match(
    left_representations: tuple[str, ...],
    right_representations: tuple[str, ...],
) -> SimilarityDecision:
    for left, right in zip(
        left_representations,
        right_representations,
        strict=True,
    ):
        left_tokens = _tokenize(left)
        right_tokens = _tokenize(right)
        if (
            left_tokens is None
            or right_tokens is None
            or left_tokens == right_tokens
            or len(left_tokens) != len(right_tokens)
            or not all(
                _tokens_equivalent(left_token, right_token)
                for left_token, right_token in zip(left_tokens, right_tokens)
            )
        ):
            continue
        return SimilarityDecision(
            "token_equivalent",
            SIMILARITY_TOKEN_EQUIVALENT_SCORE,
            "ordered tokens differ only by bounded number or plural aliases",
            True,
        )
    return SimilarityDecision(
        "token_equivalent",
        0.0,
        "ordered tokens are not equivalent",
        False,
    )


def _has_rejected_low_signal_containment(
    left_representations: tuple[str, ...],
    right_representations: tuple[str, ...],
) -> bool:
    for left, right in zip(
        left_representations,
        right_representations,
        strict=True,
    ):
        shorter, longer = sorted((left, right), key=len)
        if shorter not in longer:
            continue
        coverage = len(shorter) / len(longer)
        if (
            coverage < SIMILARITY_PROSE_SUBSTRING_MIN_COVERAGE
            and not _has_distinctive_substring_signal(shorter)
        ):
            return True
    return False


def _substring_match(left: str, right: str) -> SimilarityDecision:
    shorter, longer = sorted((left, right), key=len)
    if shorter not in longer:
        return SimilarityDecision("substring", 0.0, "substring not found", False)

    coverage = len(shorter) / len(longer)
    if _has_negation_conflict(shorter, longer):
        return SimilarityDecision(
            "substring",
            0.0,
            "substring rejected by negation conflict",
            False,
        )
    if _has_identifier_containment_boundary_conflict(shorter, longer):
        return SimilarityDecision(
            "substring",
            0.0,
            "identifier containment rejected at an alphanumeric boundary",
            False,
        )
    distinctive = _has_distinctive_substring_signal(shorter)
    if not distinctive and (
        coverage < SIMILARITY_PROSE_SUBSTRING_MIN_COVERAGE or _is_low_information_substring(shorter)
    ):
        return SimilarityDecision(
            "substring",
            0.0,
            f"low-information substring rejected; coverage={coverage:.4f}",
            False,
        )
    score = 1.0 if distinctive else 0.75 + (0.25 * coverage)
    return SimilarityDecision(
        method="substring",
        score=min(1.0, score),
        reason=(
            "distinctive text appears completely in longer text; score=1.0000"
            if distinctive
            else f"shorter text appears in longer text; coverage={coverage:.4f}"
        ),
        matched=True,
    )


def _best_shingle_match(
    left_representations: tuple[str, ...],
    right_representations: tuple[str, ...],
) -> tuple[SimilarityDecision, bool]:
    best = SimilarityDecision("shingle_jaccard", 0.0, "missing shingles", False)
    best_pair = ("", "")
    for left, right in zip(
        left_representations,
        right_representations,
        strict=True,
    ):
        decision = _shingle_match_from_sets(
            make_shingles(left),
            make_shingles(right),
        )
        if decision.score > best.score:
            best = decision
            best_pair = (left, right)
    return best, bool(best_pair[0]) and _has_content_conflict(*best_pair)


def _shingle_match(left: str, right: str) -> SimilarityDecision:
    return _shingle_match_from_sets(make_shingles(left), make_shingles(right))


def _shingle_match_from_sets(
    left_shingles: set[str],
    right_shingles: set[str],
) -> SimilarityDecision:
    if not left_shingles or not right_shingles:
        return SimilarityDecision("shingle_jaccard", 0.0, "missing shingles", False)

    overlap = len(left_shingles & right_shingles)
    union = len(left_shingles | right_shingles)
    score = overlap / union if union else 0.0
    return SimilarityDecision(
        method="shingle_jaccard",
        score=score,
        reason=f"5-gram Jaccard similarity; overlap={overlap}; union={union}",
        matched=score >= SIMILARITY_SHINGLE_THRESHOLD,
    )


def _normalize_basic(text: str) -> str:
    return " ".join(text.casefold().split())


def _bounded_nfkc_normalize(text: str) -> str | None:
    normalized = _normalize_basic(unicodedata.normalize("NFKC", text))
    return normalized if len(normalized) <= SIMILARITY_CANONICAL_MAX_CHARS else None


def _decode_complete_percent_transport(text: str) -> str | None:
    encoded = text.strip()
    if "%" not in encoded:
        return None
    raw = bytearray()
    index = 0
    try:
        while index < len(encoded):
            character = encoded[index]
            if character != "%":
                raw.extend(character.encode("utf-8"))
                index += 1
                continue
            if (
                index + 2 >= len(encoded)
                or encoded[index + 1] not in _HEX_DIGITS
                or encoded[index + 2] not in _HEX_DIGITS
            ):
                return None
            raw.append(int(encoded[index + 1 : index + 3], 16))
            index += 3
        decoded = bytes(raw).decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return None
    if not decoded or any(
        unicodedata.category(character) == "Cc" and character not in "\t\r\n"
        for character in decoded
    ):
        return None
    return decoded


def _canonicalize_identifier_separators(text: str) -> str | None:
    if not text or any(
        not character.isalnum() and character not in _IDENTIFIER_SEPARATORS for character in text
    ):
        return None
    separators = {character for character in text if character in _IDENTIFIER_SEPARATORS}
    if (
        not separators
        or sum(character.isdigit() for character in text) < 4
        or sum(character.isalpha() for character in text) < 2
    ):
        return None

    segments: list[str] = []
    current: list[str] = []
    for character in text:
        if character.isalnum():
            current.append(character)
        elif current:
            segments.append("".join(current))
            current = []
    if current:
        segments.append("".join(current))
    if len(segments) < 2:
        return None

    has_non_space_separator = any(separator != " " for separator in separators)
    if not has_non_space_separator and not _space_separated_identifier_shape(segments):
        return None
    signature = "/".join(segments)
    return signature if signature != text else None


def _canonicalize_identifier_comparison(text: str) -> str | None:
    standalone = _canonicalize_identifier_separators(text)
    if standalone is not None:
        return standalone
    if not _has_wrapper_identifier_signal(text):
        return None

    normalized: list[str] = []
    in_separator_run = False
    for character in text:
        if character in _IDENTIFIER_SEPARATORS:
            if not in_separator_run:
                normalized.append("/")
            in_separator_run = True
            continue
        normalized.append(character)
        in_separator_run = False
    comparison = "".join(normalized)
    return comparison if comparison != text else None


def _has_wrapper_identifier_signal(text: str) -> bool:
    tokens = _tokenize(text)
    if tokens is None:
        return False
    if _has_mixed_identifier_token(tokens):
        return True
    case_specific_numbers = tuple(
        token
        for token in tokens
        if token.isdigit() and len(token) >= 4 and not _is_low_information_digit_token(token)
    )
    return len(case_specific_numbers) >= 2


def _space_separated_identifier_shape(segments: list[str]) -> bool:
    return len(segments) >= 3


def _candidate_feature_windows(text: str) -> tuple[str, ...]:
    if len(text) <= SIMILARITY_CANONICAL_MAX_CHARS:
        return (text,)
    half = SIMILARITY_CANONICAL_MAX_CHARS // 2
    return (text[:half], text[-half:])


def _has_distinctive_substring_signal(text: str) -> bool:
    tokens = _tokenize(text)
    if tokens is None:
        return False
    if _has_long_diverse_alpha_secret_shape(tokens):
        return True
    if _has_mixed_identifier_token(tokens):
        return True
    if _has_non_space_separator_identifier(text, tokens):
        return True
    if _has_long_numeric_secret_shape(tokens):
        return True
    return _has_explicit_security_value_signal(tokens)


def _has_long_diverse_alpha_secret_shape(tokens: tuple[str, ...]) -> bool:
    if len(tokens) == 1:
        return _is_long_diverse_alpha_value(tokens[0])
    return any(
        len(tokens) == len(label) + 1
        and tokens[:-1] == label
        and _is_long_diverse_alpha_value(tokens[-1])
        for label in _NUMERIC_SECRET_LABELS
    )


def _is_long_diverse_alpha_value(token: str) -> bool:
    return token.isalpha() and len(token) >= 20 and len(set(token)) >= 10


def _has_mixed_identifier_token(tokens: tuple[str, ...]) -> bool:
    return any(
        len(token) >= 8
        and sum(character.isalpha() for character in token) >= 2
        and sum(character.isdigit() for character in token) >= 2
        for token in tokens
    )


def _has_non_space_separator_identifier(
    text: str,
    tokens: tuple[str, ...],
) -> bool:
    digit_tokens = tuple(token for token in tokens if token.isdigit())
    return (
        len(tokens) >= 2
        and any(separator in text for separator in "._-/")
        and all(
            character.isalnum() or character.isspace() or character in _IDENTIFIER_SEPARATORS
            for character in text
        )
        and sum(character.isalpha() for character in text) >= 2
        and sum(character.isdigit() for character in text) >= 4
        and (
            not digit_tokens
            or any(not _is_low_information_digit_token(token) for token in digit_tokens)
        )
    )


def _has_long_numeric_secret_shape(tokens: tuple[str, ...]) -> bool:
    if not any(token.isdigit() and len(token) >= 8 for token in tokens):
        return False
    return any(_contains_token_sequence(tokens, label) for label in _NUMERIC_SECRET_LABELS)


def _has_explicit_security_value_signal(tokens: tuple[str, ...]) -> bool:
    return (
        any(token in _EXPLICIT_SECURITY_VALUE_TOKENS for token in tokens)
        and any(any(character.isdigit() for character in token) for token in tokens)
        and any(token not in _GENERIC_SECURITY_TOKENS and not token.isdigit() for token in tokens)
    )


def _has_identifier_containment_boundary_conflict(shorter: str, longer: str) -> bool:
    tokens = _tokenize(shorter)
    mixed_identifier = (
        len(shorter) >= 10
        and any(character.isalpha() for character in shorter)
        and any(character.isdigit() for character in shorter)
    )
    if tokens is None or not (mixed_identifier or _has_long_diverse_alpha_secret_shape(tokens)):
        return False

    start = longer.find(shorter)
    while start >= 0:
        end = start + len(shorter)
        starts_at_boundary = start == 0 or not longer[start - 1].isalnum()
        ends_at_boundary = end == len(longer) or not longer[end].isalnum()
        if starts_at_boundary and ends_at_boundary:
            return False
        start = longer.find(shorter, start + 1)
    return True


def _is_low_information_substring(text: str) -> bool:
    tokens = _tokenize(text)
    return tokens is not None and (
        _is_low_information_exact_only_text(text)
        or (1 <= len(tokens) <= 2 and len(text) < 16 and all(token.isalpha() for token in tokens))
    )


def _is_low_information_exact_only_text(text: str) -> bool:
    tokens = _tokenize(text)
    return tokens is not None and (
        _is_low_information_security_phrase(text) or _is_short_numeric_label_phrase(tokens)
    )


def _is_low_information_security_phrase(text: str) -> bool:
    tokens = _tokenize(text)
    return (
        tokens is not None
        and 1 <= len(tokens) <= 6
        and any(token in _GENERIC_SECURITY_TOKENS for token in tokens)
        and all(
            token in _GENERIC_SECURITY_TOKENS or _is_low_information_digit_token(token)
            for token in tokens
        )
    )


def _is_low_information_digit_token(token: str) -> bool:
    if not token.isdigit():
        return False
    if len(token) <= 3:
        return True
    return len(token) == 4 and 1900 <= int(token) <= 2199


def _is_short_numeric_label_phrase(tokens: tuple[str, ...]) -> bool:
    return (
        len(tokens) == 2
        and tokens[0].isalpha()
        and tokens[1].isdigit()
        and (
            _is_low_information_digit_token(tokens[1])
            or tokens[0] in _LOW_INFORMATION_NUMERIC_LABELS
        )
    )


def _has_low_information_representation(prepared: PreparedSimilarityText) -> bool:
    return any(
        _is_low_information_exact_only_text(representation)
        for representation in prepared.representations
    )


def _has_aligned_content_conflict(
    left_representations: tuple[str, ...],
    right_representations: tuple[str, ...],
) -> bool:
    aligned = tuple(zip(left_representations, right_representations, strict=True))
    semantic_stages = aligned[1:] if len(aligned) > 1 else aligned
    return any(_has_content_conflict(left, right) for left, right in semantic_stages)


def _has_content_conflict(left: str, right: str) -> bool:
    left_tokens = _tokenize(left)
    right_tokens = _tokenize(right)
    if left_tokens is None or right_tokens is None:
        return False
    if _negation_presence(left_tokens) != _negation_presence(right_tokens):
        return True
    if left_tokens == right_tokens:
        return False
    if _tokens_contained(left_tokens, right_tokens):
        shorter, longer = sorted((left, right), key=len)
        return shorter in longer and _is_low_information_substring(shorter)
    if len(left_tokens) == len(right_tokens):
        return any(
            not _tokens_equivalent(left_token, right_token)
            for left_token, right_token in zip(left_tokens, right_tokens)
        )
    if _has_bidirectional_non_equivalent_tokens(left_tokens, right_tokens):
        return True

    common_prefix = 0
    for left_token, right_token in zip(left_tokens, right_tokens):
        if left_token != right_token:
            break
        common_prefix += 1
    common_suffix = 0
    for left_token, right_token in zip(reversed(left_tokens), reversed(right_tokens)):
        if left_token != right_token:
            break
        common_suffix += 1
    shared = min(len(left_tokens), common_prefix + common_suffix)
    return shared >= 2 and shared * 2 >= min(len(left_tokens), len(right_tokens))


def _has_negation_conflict(left: str, right: str) -> bool:
    left_tokens = _tokenize(left)
    right_tokens = _tokenize(right)
    if left_tokens is None or right_tokens is None:
        return False
    return _negation_presence(left_tokens) != _negation_presence(right_tokens)


def _negation_presence(tokens: tuple[str, ...]) -> bool:
    return any(token in _NEGATION_TOKENS for token in tokens)


def _tokenize(text: str) -> tuple[str, ...] | None:
    if len(text) > SIMILARITY_CANONICAL_MAX_CHARS:
        return None
    tokens: list[str] = []
    current: list[str] = []
    for character in text:
        if character.isalnum():
            current.append(character)
        elif current:
            tokens.append("".join(current))
            current = []
    if current:
        tokens.append("".join(current))
    return tuple(tokens)


def _tokens_contained(left: tuple[str, ...], right: tuple[str, ...]) -> bool:
    shorter, longer = sorted((left, right), key=len)
    if not shorter:
        return False
    prefix_lengths = [0] * len(shorter)
    prefix_length = 0
    for index in range(1, len(shorter)):
        while prefix_length and shorter[index] != shorter[prefix_length]:
            prefix_length = prefix_lengths[prefix_length - 1]
        if shorter[index] == shorter[prefix_length]:
            prefix_length += 1
            prefix_lengths[index] = prefix_length

    matched = 0
    for token in longer:
        while matched and token != shorter[matched]:
            matched = prefix_lengths[matched - 1]
        if token == shorter[matched]:
            matched += 1
            if matched == len(shorter):
                return True
    return False


def _tokens_equivalent(left: str, right: str) -> bool:
    return _token_equivalence_key(left) == _token_equivalence_key(right)


def _has_bidirectional_non_equivalent_tokens(
    left: tuple[str, ...],
    right: tuple[str, ...],
) -> bool:
    left_keys = [_token_equivalence_keys(token) for token in left]
    right_keys = [_token_equivalence_keys(token) for token in right]
    all_left_keys = set().union(*left_keys)
    all_right_keys = set().union(*right_keys)
    return any(not keys & all_right_keys for keys in left_keys) and any(
        not keys & all_left_keys for keys in right_keys
    )


def _token_equivalence_keys(token: str) -> frozenset[str]:
    return frozenset({_token_equivalence_key(token)})


def _token_equivalence_key(token: str) -> str:
    numbered = _NUMBER_ALIASES.get(token, token)
    return _EXPLICIT_TOKEN_ALIASES.get(numbered, numbered)


def _contains_token_sequence(
    tokens: tuple[str, ...],
    candidate: tuple[str, ...],
) -> bool:
    if len(candidate) > len(tokens):
        return False
    return any(
        tokens[index : index + len(candidate)] == candidate
        for index in range(len(tokens) - len(candidate) + 1)
    )


def _compare_candidate_stats(
    left: SimilarityCandidateStats,
    right: SimilarityCandidateStats,
    *,
    query_feature_count: int,
) -> int:
    left_denominator = min(query_feature_count, left.candidate_feature_count)
    right_denominator = min(query_feature_count, right.candidate_feature_count)
    left_cross = left.overlap_count * right_denominator
    right_cross = right.overlap_count * left_denominator
    if left_cross != right_cross:
        return -1 if left_cross > right_cross else 1
    if left.overlap_count != right.overlap_count:
        return -1 if left.overlap_count > right.overlap_count else 1
    return (left.candidate_id > right.candidate_id) - (left.candidate_id < right.candidate_id)


def _compare_candidate_stats_by_overlap(
    left: SimilarityCandidateStats,
    right: SimilarityCandidateStats,
    *,
    query_feature_count: int,
) -> int:
    if left.overlap_count != right.overlap_count:
        return -1 if left.overlap_count > right.overlap_count else 1
    return _compare_candidate_stats(
        left,
        right,
        query_feature_count=query_feature_count,
    )


def _require_nonnegative_int(value: int, name: str) -> None:
    if type(value) is not int or value < 0:
        raise ValueError(f"{name} must be a non-negative integer")


def _require_positive_int(value: int, name: str) -> None:
    if type(value) is not int or value <= 0:
        raise ValueError(f"{name} must be a positive integer")
