"""Closed, content-free records shared by runtime storage and evaluation."""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum


PILOT_OBSERVATION_SCHEMA_VERSION = "pilot-observation-v1"
PILOT_COMPARISON_SCHEMA_VERSION = "pilot-comparison-v1"
PILOT_COMPARISON_THRESHOLD = 20
MAX_DECISION_MS = 60_000.0

_OPAQUE_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_VERSION_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$")
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_WORKSPACE_ID_PATTERN = re.compile(r"^ws_v1_[0-9a-f]{64}$")


class StudyCohort(StrEnum):
    LEGACY = "legacy"
    PILOT = "pilot"


class ToolFamily(StrEnum):
    SHELL = "shell"
    MCP = "mcp"
    FUNCTION = "function"
    HOSTED = "hosted"
    CONTINUATION = "continuation"
    OTHER = "other"


class Externality(StrEnum):
    LOCAL = "local"
    EXTERNAL = "external"
    UNKNOWN = "unknown"
    NOT_VISIBLE = "not_visible"


class PayloadResolution(StrEnum):
    DIRECT = "direct"
    FILE = "file"
    LINEAGE = "lineage"
    UNRESOLVED = "unresolved"
    NOT_APPLICABLE = "not_applicable"


class EvidenceSource(StrEnum):
    ADAPTER = "adapter"
    STATIC = "static"
    DIRECT = "direct"
    RESOLVED = "resolved"
    LINEAGE = "lineage"
    FALLBACK = "fallback"
    NOT_VISIBLE = "not_visible"


class PolicyAction(StrEnum):
    ALLOW = "allow"
    BLOCK = "block"


class ReasonCode(StrEnum):
    PUBLIC_FLOW_ABSENT = "public_flow_absent"
    PROTECTED_EXACT_MATCH = "protected_exact_match"
    PROTECTED_UNKNOWN_EXTERNALITY = "protected_unknown_externality"
    PROTECTED_PAYLOAD_UNRESOLVED = "protected_payload_unresolved"
    PROTECTED_LINEAGE = "protected_lineage"
    POLICY_SAFETY_FAILURE = "policy_safety_failure"
    TOOL_NOT_VISIBLE = "tool_not_visible"
    UNMAPPED = "unmapped"


class ReviewState(StrEnum):
    NOT_NEEDED = "not_needed"
    PENDING = "pending"
    CORRECT_BLOCK = "correct_block"
    UNNECESSARY_BLOCK = "unnecessary_block"
    UNABLE_TO_JUDGE = "unable_to_judge"


class CauseCategory(StrEnum):
    EXTERNALITY = "externality"
    PAYLOAD_RESOLUTION = "payload_resolution"
    PROTECTED_MATCH = "protected_match"
    LINEAGE = "lineage"
    COVERAGE_BOUNDARY = "coverage_boundary"
    EXPLANATION = "explanation"
    UNIDENTIFIED = "unidentified"


class RecordState(StrEnum):
    COMPLETE = "complete"
    RECONSTRUCTED = "reconstructed"
    INCOMPLETE = "incomplete"


class ProblemSymptom(StrEnum):
    UNNECESSARY_BLOCK = "unnecessary_block"
    MISS_CANDIDATE = "miss_candidate"
    REPRODUCED_MISS = "reproduced_miss"
    UNABLE_TO_JUDGE = "unable_to_judge"
    NOT_VISIBLE = "not_visible"
    RECORD_FAILURE = "record_failure"


class ClassifiedBy(StrEnum):
    AUTOMATIC = "automatic"
    HUMAN = "human"


@dataclass(frozen=True)
class PilotObservation:
    observation_id: str
    observed_at: str
    workspace_id: str
    event_ref_sha256: str
    product_version: str
    detector_version: str
    settings_revision: str
    tool_family: ToolFamily
    externality: Externality
    payload_resolution: PayloadResolution
    evidence_source: EvidenceSource
    policy_action: PolicyAction
    reason_code: ReasonCode
    decision_ms: float
    review_state: ReviewState
    cause_candidate: CauseCategory | None
    record_state: RecordState
    study_cohort: StudyCohort

    def __post_init__(self) -> None:
        _require_enum(self.tool_family, ToolFamily, "tool_family")
        _require_enum(self.externality, Externality, "externality")
        _require_enum(
            self.payload_resolution,
            PayloadResolution,
            "payload_resolution",
        )
        _require_enum(self.evidence_source, EvidenceSource, "evidence_source")
        _require_enum(self.policy_action, PolicyAction, "policy_action")
        _require_enum(self.reason_code, ReasonCode, "reason_code")
        _require_enum(self.review_state, ReviewState, "review_state")
        if self.cause_candidate is not None:
            _require_enum(
                self.cause_candidate,
                CauseCategory,
                "cause_candidate",
            )
        _require_enum(self.record_state, RecordState, "record_state")
        _require_enum(self.study_cohort, StudyCohort, "study_cohort")
        _require_opaque_id(self.observation_id, "observation_id")
        _require_utc_timestamp(self.observed_at, "observed_at")
        if not _WORKSPACE_ID_PATTERN.fullmatch(self.workspace_id):
            raise ValueError("workspace_id must be a ToolUseProxy opaque workspace ID")
        _require_sha256(self.event_ref_sha256, "event_ref_sha256")
        _require_version(self.product_version, "product_version")
        _require_version(self.detector_version, "detector_version")
        _require_sha256(self.settings_revision, "settings_revision")
        if (
            not isinstance(self.decision_ms, (int, float))
            or isinstance(self.decision_ms, bool)
            or not math.isfinite(float(self.decision_ms))
            or not 0 <= float(self.decision_ms) <= MAX_DECISION_MS
        ):
            raise ValueError("decision_ms must be finite and between 0 and 60000")
        if self.policy_action == PolicyAction.ALLOW and self.review_state != ReviewState.NOT_NEEDED:
            raise ValueError("allowed observations must not carry a block review")
        if self.policy_action == PolicyAction.BLOCK and self.review_state == ReviewState.NOT_NEEDED:
            raise ValueError("blocked observations must carry a block review state")


@dataclass(frozen=True)
class PilotProblemEvent:
    problem_event_id: str
    observation_id: str | None
    workspace_id: str
    detector_version: str
    symptom: ProblemSymptom
    cause: CauseCategory
    classified_by: ClassifiedBy
    previous_problem_event_id: str | None
    comparable_count_at_record: int
    recorded_at: str

    def __post_init__(self) -> None:
        _require_enum(self.symptom, ProblemSymptom, "symptom")
        _require_enum(self.cause, CauseCategory, "cause")
        _require_enum(self.classified_by, ClassifiedBy, "classified_by")
        _require_opaque_id(self.problem_event_id, "problem_event_id")
        if self.observation_id is not None:
            _require_opaque_id(self.observation_id, "observation_id")
        if not _WORKSPACE_ID_PATTERN.fullmatch(self.workspace_id):
            raise ValueError("workspace_id must be a ToolUseProxy opaque workspace ID")
        _require_version(self.detector_version, "detector_version")
        if self.previous_problem_event_id is not None:
            _require_opaque_id(
                self.previous_problem_event_id,
                "previous_problem_event_id",
            )
            if self.previous_problem_event_id == self.problem_event_id:
                raise ValueError("a problem event cannot replace itself")
        if (
            isinstance(self.comparable_count_at_record, bool)
            or not isinstance(self.comparable_count_at_record, int)
            or self.comparable_count_at_record < 0
        ):
            raise ValueError("comparable_count_at_record must be a non-negative integer")
        _require_utc_timestamp(self.recorded_at, "recorded_at")


def parse_utc_timestamp(value: str) -> datetime:
    _require_utc_timestamp(value, "timestamp")
    return datetime.fromisoformat(value.removesuffix("Z") + "+00:00")


def _require_opaque_id(value: str, field: str) -> None:
    if not isinstance(value, str) or not _OPAQUE_ID_PATTERN.fullmatch(value):
        raise ValueError(f"{field} must be a bounded opaque identifier")


def _require_version(value: str, field: str) -> None:
    if not isinstance(value, str) or not _VERSION_PATTERN.fullmatch(value):
        raise ValueError(f"{field} must be a bounded version identifier")


def _require_sha256(value: str, field: str) -> None:
    if not isinstance(value, str) or not _SHA256_PATTERN.fullmatch(value):
        raise ValueError(f"{field} must be a lowercase SHA-256 digest")


def _require_enum(value: object, enum_type: type[StrEnum], field: str) -> None:
    if not isinstance(value, enum_type):
        raise ValueError(f"{field} must use a closed {enum_type.__name__} value")


def _require_utc_timestamp(value: str, field: str) -> None:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValueError(f"{field} must be an ISO 8601 UTC timestamp ending in Z")
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError as error:
        raise ValueError(f"{field} must be a valid ISO 8601 timestamp") from error
    if parsed.tzinfo != UTC:
        raise ValueError(f"{field} must use UTC")
