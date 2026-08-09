from __future__ import annotations

import hashlib
import sqlite3
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from hook_monitor.analysis.sink_payload_evidence import BashSinkPayloadEvidence


SINK_PAYLOAD_SHADOW_SCHEMA_VERSION = "sink-payload-shadow-v1"
SINK_PAYLOAD_SHADOW_BUSY_TIMEOUT_MS = 10

_RESOLUTION_STATUSES = frozenset({"evaluated", "unsupported"})
_COMPARISON_STATUSES = frozenset({"evaluated", "unsupported", "not_run"})
_EXTRACTIONS = frozenset({"resolved_file", "coarse_fallback"})
_SNAPSHOT_SEMANTICS = frozenset(
    {"pre_execution_file_snapshot", "unresolved"}
)
_MATCH_KINDS = frozenset(
    {"none", "resolved_payload_exact", "resolved_payload_exact_substring"}
)
_ACTIONS = frozenset({"allow", "block", "continue_review", "redact", "warn"})
_SHADOW_ACTIONS = frozenset({"would_allow", "would_block", "unknown"})
_BYTE_BUCKETS = frozenset(
    {"0", "1-1024", "1025-4096", "4097-32768", "32769+"}
)
_VALUE_COUNT_BUCKETS = frozenset({"0", "1", "2-4", "5-16", "17+"})


@dataclass(frozen=True)
class SinkPayloadShadowObservation:
    observation_id: str
    pre_event_id: str
    analysis_run_id: str
    workspace_id: str
    session_id: str
    tool_use_id: str | None
    sink_node_id: str
    segment_index: int
    resolver_version: str
    evidence_version: str
    resolution_status: Literal["evaluated", "unsupported"]
    comparison_status: Literal["evaluated", "unsupported", "not_run"]
    extraction: Literal["resolved_file", "coarse_fallback"]
    snapshot_semantics: Literal[
        "pre_execution_file_snapshot",
        "unresolved",
    ]
    resolution_reason: str | None
    comparison_reason: str | None
    value_count_bucket: str
    payload_bytes_bucket: str
    match_kind: Literal[
        "none",
        "resolved_payload_exact",
        "resolved_payload_exact_substring",
    ]
    match_count: int
    inspection_duration_ms: float
    baseline_action: str
    shadow_action: Literal["would_allow", "would_block", "unknown"]


def build_sink_payload_shadow_observation(
    evidence: BashSinkPayloadEvidence,
    *,
    pre_event_id: str,
    analysis_run_id: str,
    session_id: str,
    tool_use_id: str | None,
    baseline_action: str,
) -> SinkPayloadShadowObservation | None:
    """Reduce ephemeral evidence to aggregate, value-free shadow metadata."""
    if evidence.extraction == "static_values":
        return None
    match_kind = _strongest_match_kind(evidence)
    shadow_action = _shadow_action(evidence, match_kind)
    observation_id = _observation_id(
        pre_event_id,
        evidence.sink_node_id,
        evidence.segment_index,
        evidence.evidence_version,
    )
    observation = SinkPayloadShadowObservation(
        observation_id=observation_id,
        pre_event_id=pre_event_id,
        analysis_run_id=analysis_run_id,
        workspace_id=evidence.workspace_id,
        session_id=session_id,
        tool_use_id=tool_use_id,
        sink_node_id=evidence.sink_node_id,
        segment_index=evidence.segment_index,
        resolver_version=evidence.resolver_version,
        evidence_version=evidence.evidence_version,
        resolution_status=evidence.resolution_status,
        comparison_status=evidence.comparison_status,
        extraction=evidence.extraction,
        snapshot_semantics=evidence.snapshot_semantics,
        resolution_reason=evidence.resolution_reason,
        comparison_reason=evidence.comparison_reason,
        value_count_bucket=_count_bucket(evidence.submitted_value_count),
        payload_bytes_bucket=_bytes_bucket(evidence.submitted_bytes),
        match_kind=match_kind,
        match_count=len(evidence.matches),
        inspection_duration_ms=round(evidence.inspection_duration_ms, 3),
        baseline_action=baseline_action,
        shadow_action=shadow_action,
    )
    _validate_observation(observation)
    return observation


def store_sink_payload_shadow_observations(
    db_path: Path,
    observations: tuple[SinkPayloadShadowObservation, ...],
) -> None:
    """Persist first observations without putting shadow on the core DB path."""
    if not observations:
        return
    with _connect(db_path) as conn:
        _initialize_schema(conn)
        conn.execute("BEGIN IMMEDIATE")
        try:
            for observation in observations:
                _validate_observation(observation)
                _insert_immutable_observation(conn, observation)
        except Exception:
            conn.rollback()
            raise
        else:
            conn.commit()


def list_sink_payload_shadow_observations(
    db_path: Path,
) -> tuple[SinkPayloadShadowObservation, ...]:
    with _connect(db_path) as conn:
        _initialize_schema(conn)
        rows = conn.execute(
            """
            SELECT
                observation_id,
                pre_event_id,
                analysis_run_id,
                workspace_id,
                session_id,
                tool_use_id,
                sink_node_id,
                segment_index,
                resolver_version,
                evidence_version,
                resolution_status,
                comparison_status,
                extraction,
                snapshot_semantics,
                resolution_reason,
                comparison_reason,
                value_count_bucket,
                payload_bytes_bucket,
                match_kind,
                match_count,
                inspection_duration_ms,
                baseline_action,
                shadow_action
            FROM sink_payload_shadow_observations
            ORDER BY created_at, observation_id
            """
        ).fetchall()
    return tuple(_observation_from_row(row) for row in rows)


def build_sink_payload_shadow_report(
    observations: tuple[SinkPayloadShadowObservation, ...],
) -> dict[str, object]:
    """Return aggregate-only dogfood metrics without durable identities."""
    durations = sorted(item.inspection_duration_ms for item in observations)
    return {
        "schema_version": SINK_PAYLOAD_SHADOW_SCHEMA_VERSION,
        "observation_count": len(observations),
        "resolution_status": _counts(
            item.resolution_status for item in observations
        ),
        "comparison_status": _counts(
            item.comparison_status for item in observations
        ),
        "match_kind": _counts(item.match_kind for item in observations),
        "baseline_action": _counts(
            item.baseline_action for item in observations
        ),
        "shadow_action": _counts(item.shadow_action for item in observations),
        "decision_diff": _counts(
            f"{item.baseline_action}->{item.shadow_action}"
            for item in observations
        ),
        "payload_bytes_bucket": _counts(
            item.payload_bytes_bucket for item in observations
        ),
        "latency_ms": {
            "p50": _percentile(durations, 0.50),
            "p95": _percentile(durations, 0.95),
            "p99": _percentile(durations, 0.99),
            "max": None if not durations else durations[-1],
        },
    }


def _insert_immutable_observation(
    conn: sqlite3.Connection,
    observation: SinkPayloadShadowObservation,
) -> None:
    values = _observation_values(observation)
    conn.execute(
        """
        INSERT INTO sink_payload_shadow_observations (
            observation_id,
            pre_event_id,
            analysis_run_id,
            workspace_id,
            session_id,
            tool_use_id,
            sink_node_id,
            segment_index,
            resolver_version,
            evidence_version,
            resolution_status,
            comparison_status,
            extraction,
            snapshot_semantics,
            resolution_reason,
            comparison_reason,
            value_count_bucket,
            payload_bytes_bucket,
            match_kind,
            match_count,
            inspection_duration_ms,
            baseline_action,
            shadow_action
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(observation_id) DO NOTHING
        """,
        values,
    )
    stored = conn.execute(
        """
        SELECT
            observation_id,
            pre_event_id,
            analysis_run_id,
            workspace_id,
            session_id,
            tool_use_id,
            sink_node_id,
            segment_index,
            resolver_version,
            evidence_version,
            resolution_status,
            comparison_status,
            extraction,
            snapshot_semantics,
            resolution_reason,
            comparison_reason,
            value_count_bucket,
            payload_bytes_bucket,
            match_kind,
            match_count,
            inspection_duration_ms,
            baseline_action,
            shadow_action
        FROM sink_payload_shadow_observations
        WHERE observation_id = ?
        """,
        (observation.observation_id,),
    ).fetchone()
    if stored is None:
        raise sqlite3.IntegrityError("sink payload shadow observation was not stored")
    existing = _observation_from_row(stored)
    if _immutable_signature(existing) != _immutable_signature(observation):
        raise sqlite3.IntegrityError("sink payload shadow replay mismatch")


def _initialize_schema(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS sink_payload_shadow_observations (
            observation_id TEXT PRIMARY KEY,
            pre_event_id TEXT NOT NULL,
            analysis_run_id TEXT NOT NULL,
            workspace_id TEXT NOT NULL,
            session_id TEXT NOT NULL,
            tool_use_id TEXT,
            sink_node_id TEXT NOT NULL,
            segment_index INTEGER NOT NULL CHECK (segment_index >= 0),
            resolver_version TEXT NOT NULL,
            evidence_version TEXT NOT NULL,
            resolution_status TEXT NOT NULL
                CHECK (resolution_status IN ('evaluated', 'unsupported')),
            comparison_status TEXT NOT NULL
                CHECK (comparison_status IN ('evaluated', 'unsupported', 'not_run')),
            extraction TEXT NOT NULL
                CHECK (extraction IN ('resolved_file', 'coarse_fallback')),
            snapshot_semantics TEXT NOT NULL
                CHECK (
                    snapshot_semantics IN (
                        'pre_execution_file_snapshot',
                        'unresolved'
                    )
                ),
            resolution_reason TEXT,
            comparison_reason TEXT,
            value_count_bucket TEXT NOT NULL,
            payload_bytes_bucket TEXT NOT NULL,
            match_kind TEXT NOT NULL,
            match_count INTEGER NOT NULL CHECK (match_count >= 0),
            inspection_duration_ms REAL NOT NULL
                CHECK (inspection_duration_ms >= 0),
            baseline_action TEXT NOT NULL,
            shadow_action TEXT NOT NULL,
            schema_version TEXT NOT NULL DEFAULT 'sink-payload-shadow-v1',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    columns = tuple(
        row[1]
        for row in conn.execute(
            "PRAGMA table_info(sink_payload_shadow_observations)"
        ).fetchall()
    )
    expected = (
        "observation_id",
        "pre_event_id",
        "analysis_run_id",
        "workspace_id",
        "session_id",
        "tool_use_id",
        "sink_node_id",
        "segment_index",
        "resolver_version",
        "evidence_version",
        "resolution_status",
        "comparison_status",
        "extraction",
        "snapshot_semantics",
        "resolution_reason",
        "comparison_reason",
        "value_count_bucket",
        "payload_bytes_bucket",
        "match_kind",
        "match_count",
        "inspection_duration_ms",
        "baseline_action",
        "shadow_action",
        "schema_version",
        "created_at",
    )
    if columns != expected:
        raise RuntimeError("sink payload shadow schema mismatch")


def _connect(db_path: Path) -> sqlite3.Connection:
    timeout_seconds = SINK_PAYLOAD_SHADOW_BUSY_TIMEOUT_MS / 1000
    conn = sqlite3.connect(db_path, timeout=timeout_seconds)
    conn.execute(
        f"PRAGMA busy_timeout = {SINK_PAYLOAD_SHADOW_BUSY_TIMEOUT_MS}"
    )
    return conn


def _validate_observation(observation: SinkPayloadShadowObservation) -> None:
    bounded_text = (
        observation.observation_id,
        observation.pre_event_id,
        observation.analysis_run_id,
        observation.workspace_id,
        observation.session_id,
        observation.sink_node_id,
        observation.resolver_version,
        observation.evidence_version,
    )
    if any(
        not value
        or len(value.encode("utf-8", errors="surrogatepass")) > 4096
        for value in bounded_text
    ):
        raise ValueError("sink payload shadow identity is invalid")
    if (
        observation.tool_use_id is not None
        and (
            not observation.tool_use_id
            or len(
                observation.tool_use_id.encode(
                    "utf-8",
                    errors="surrogatepass",
                )
            )
            > 4096
        )
    ):
        raise ValueError("sink payload shadow tool use id is invalid")
    if type(observation.segment_index) is not int or observation.segment_index < 0:
        raise ValueError("sink payload shadow segment index is invalid")
    if observation.observation_id != _observation_id(
        observation.pre_event_id,
        observation.sink_node_id,
        observation.segment_index,
        observation.evidence_version,
    ):
        raise ValueError("sink payload shadow observation id is invalid")
    if observation.resolution_status not in _RESOLUTION_STATUSES:
        raise ValueError("sink payload shadow resolution status is invalid")
    if observation.comparison_status not in _COMPARISON_STATUSES:
        raise ValueError("sink payload shadow comparison status is invalid")
    if observation.extraction not in _EXTRACTIONS:
        raise ValueError("sink payload shadow extraction is invalid")
    if observation.snapshot_semantics not in _SNAPSHOT_SEMANTICS:
        raise ValueError("sink payload shadow snapshot semantics is invalid")
    for reason in (observation.resolution_reason, observation.comparison_reason):
        if reason is not None and (
            not reason
            or len(reason.encode("ascii", errors="ignore")) != len(reason)
            or len(reason) > 128
            or not all(character.islower() or character == "_" for character in reason)
        ):
            raise ValueError("sink payload shadow reason is invalid")
    if observation.value_count_bucket not in _VALUE_COUNT_BUCKETS:
        raise ValueError("sink payload shadow value count bucket is invalid")
    if observation.payload_bytes_bucket not in _BYTE_BUCKETS:
        raise ValueError("sink payload shadow byte bucket is invalid")
    if observation.match_kind not in _MATCH_KINDS:
        raise ValueError("sink payload shadow match kind is invalid")
    if type(observation.match_count) is not int or observation.match_count < 0:
        raise ValueError("sink payload shadow match count is invalid")
    if (
        not isinstance(observation.inspection_duration_ms, float)
        or not 0 <= observation.inspection_duration_ms <= 1000
    ):
        raise ValueError("sink payload shadow duration is invalid")
    if observation.baseline_action not in _ACTIONS:
        raise ValueError("sink payload shadow baseline action is invalid")
    if observation.shadow_action not in _SHADOW_ACTIONS:
        raise ValueError("sink payload shadow action is invalid")
    if observation.extraction == "resolved_file":
        if (
            observation.resolution_status != "evaluated"
            or observation.snapshot_semantics != "pre_execution_file_snapshot"
            or observation.resolution_reason is not None
        ):
            raise ValueError("sink payload shadow resolved state is inconsistent")
    elif (
        observation.resolution_status != "unsupported"
        or observation.snapshot_semantics != "unresolved"
        or observation.resolution_reason is None
        or observation.comparison_status != "not_run"
    ):
        raise ValueError("sink payload shadow unsupported state is inconsistent")
    if (
        observation.comparison_status == "evaluated"
        and observation.comparison_reason is not None
    ) or (
        observation.comparison_status == "unsupported"
        and observation.comparison_reason is None
    ):
        raise ValueError("sink payload shadow comparison state is inconsistent")
    if (observation.match_kind == "none") != (observation.match_count == 0):
        raise ValueError("sink payload shadow match state is inconsistent")
    expected_shadow_action = (
        "unknown"
        if (
            observation.resolution_status != "evaluated"
            or observation.comparison_status != "evaluated"
        )
        else (
            "would_allow"
            if observation.match_kind == "none"
            else "would_block"
        )
    )
    if observation.shadow_action != expected_shadow_action:
        raise ValueError("sink payload shadow action is inconsistent")


def _strongest_match_kind(evidence: BashSinkPayloadEvidence) -> str:
    methods = {match.method for match in evidence.matches}
    if "resolved_payload_exact" in methods:
        return "resolved_payload_exact"
    if "resolved_payload_exact_substring" in methods:
        return "resolved_payload_exact_substring"
    return "none"


def _shadow_action(
    evidence: BashSinkPayloadEvidence,
    match_kind: str,
) -> Literal["would_allow", "would_block", "unknown"]:
    if (
        evidence.resolution_status != "evaluated"
        or evidence.comparison_status != "evaluated"
    ):
        return "unknown"
    if match_kind in {
        "resolved_payload_exact",
        "resolved_payload_exact_substring",
    }:
        return "would_block"
    return "would_allow"


def _bytes_bucket(value: int) -> str:
    if value == 0:
        return "0"
    if value <= 1024:
        return "1-1024"
    if value <= 4096:
        return "1025-4096"
    if value <= 32768:
        return "4097-32768"
    return "32769+"


def _count_bucket(value: int) -> str:
    if value == 0:
        return "0"
    if value == 1:
        return "1"
    if value <= 4:
        return "2-4"
    if value <= 16:
        return "5-16"
    return "17+"


def _observation_id(
    pre_event_id: str,
    sink_node_id: str,
    segment_index: int,
    evidence_version: str,
) -> str:
    identity = "\0".join(
        (pre_event_id, sink_node_id, str(segment_index), evidence_version)
    )
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()


def _observation_values(
    observation: SinkPayloadShadowObservation,
) -> tuple[object, ...]:
    return (
        observation.observation_id,
        observation.pre_event_id,
        observation.analysis_run_id,
        observation.workspace_id,
        observation.session_id,
        observation.tool_use_id,
        observation.sink_node_id,
        observation.segment_index,
        observation.resolver_version,
        observation.evidence_version,
        observation.resolution_status,
        observation.comparison_status,
        observation.extraction,
        observation.snapshot_semantics,
        observation.resolution_reason,
        observation.comparison_reason,
        observation.value_count_bucket,
        observation.payload_bytes_bucket,
        observation.match_kind,
        observation.match_count,
        observation.inspection_duration_ms,
        observation.baseline_action,
        observation.shadow_action,
    )


def _observation_from_row(
    row: tuple[object, ...],
) -> SinkPayloadShadowObservation:
    return SinkPayloadShadowObservation(
        observation_id=str(row[0]),
        pre_event_id=str(row[1]),
        analysis_run_id=str(row[2]),
        workspace_id=str(row[3]),
        session_id=str(row[4]),
        tool_use_id=None if row[5] is None else str(row[5]),
        sink_node_id=str(row[6]),
        segment_index=int(row[7]),
        resolver_version=str(row[8]),
        evidence_version=str(row[9]),
        resolution_status=str(row[10]),  # type: ignore[arg-type]
        comparison_status=str(row[11]),  # type: ignore[arg-type]
        extraction=str(row[12]),  # type: ignore[arg-type]
        snapshot_semantics=str(row[13]),  # type: ignore[arg-type]
        resolution_reason=None if row[14] is None else str(row[14]),
        comparison_reason=None if row[15] is None else str(row[15]),
        value_count_bucket=str(row[16]),
        payload_bytes_bucket=str(row[17]),
        match_kind=str(row[18]),  # type: ignore[arg-type]
        match_count=int(row[19]),
        inspection_duration_ms=float(row[20]),
        baseline_action=str(row[21]),
        shadow_action=str(row[22]),  # type: ignore[arg-type]
    )


def _immutable_signature(
    observation: SinkPayloadShadowObservation,
) -> tuple[object, ...]:
    values = _observation_values(observation)
    return values[:20] + values[21:]


def _counts(values: Iterable[str]) -> dict[str, int]:
    return dict(sorted(Counter(values).items()))


def _percentile(
    sorted_values: list[float],
    fraction: float,
) -> float | None:
    if not sorted_values:
        return None
    index = max(0, int(len(sorted_values) * fraction + 0.999999999) - 1)
    return sorted_values[min(index, len(sorted_values) - 1)]
