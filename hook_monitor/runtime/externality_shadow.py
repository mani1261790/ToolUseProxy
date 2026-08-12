from __future__ import annotations

import hashlib
import math
import re
import sqlite3
import time
from collections import Counter
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator, Literal, Mapping

from hook_monitor.analysis.adapters.bash import classify_bash_sink_type
from hook_monitor.analysis.adapters.mcp import classify_mcp_sink_type
from hook_monitor.externality.configuration import resolve_judge_configuration
from hook_monitor.externality.envelope import (
    StaticExternalityResult,
    analyze_bash_externality,
    analyze_mcp_externality,
)
from hook_monitor.externality.providers import JudgeChainResult, JudgeObservation
from hook_monitor.runtime.models import NormalizedEvent
from hook_monitor.runtime.tool_compat import (
    is_enforced_shell_tool,
    shell_command_from_input,
)


EXTERNALITY_SHADOW_SCHEMA_VERSION = "externality-shadow-v1"
EXTERNALITY_SHADOW_BUSY_TIMEOUT_MS = 10
MAX_SHADOW_DURATION_MS = 60_000.0

_ADAPTER_VERDICTS = frozenset({"external", "unknown"})
_STATIC_VERDICTS = frozenset({"external", "local", "unknown"})
_JUDGE_VERDICTS = frozenset(
    {"external", "possibly_external", "local", "unknown", "not_run", "failed"}
)
_SHADOW_VERDICTS = frozenset({"external", "possibly_external", "local", "unknown"})
_JUDGE_STATUSES = frozenset(
    {"not_needed", "not_configured", "completed", "failed"}
)
_ANALYSIS_COVERAGE = frozenset({"complete", "partial", "opaque"})
_JUDGE_PROVIDERS = frozenset({"none", "codex_exec"})
_MODEL_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
MAX_SHADOW_COUNT = 1024


@dataclass(frozen=True)
class ExternalityShadowObservation:
    observation_id: str
    pre_event_id: str
    workspace_id: str
    session_id: str
    tool_use_id: str | None
    tool_family: str
    envelope_sha256: str
    adapter_verdict: Literal["external", "unknown"]
    static_verdict: Literal["external", "local", "unknown"]
    judge_status: Literal["not_needed", "not_configured", "completed", "failed"]
    judge_verdict: str
    shadow_verdict: Literal["external", "possibly_external", "local", "unknown"]
    provider: str
    model_sha256: str
    failure_code: str | None
    analysis_coverage: str
    capability_count: int
    risk_signal_count: int
    static_duration_ms: float
    judge_duration_ms: float


def observe_externality_shadow(
    event: NormalizedEvent,
    *,
    workspace_root: Path,
    environ: Mapping[str, str],
) -> ExternalityShadowObservation | None:
    if (
        event.phase != "pre_tool_use"
        or event.workspace_status != "ready"
        or event.workspace_id is None
        or event.session_id is None
    ):
        return None
    started = time.monotonic()
    static, adapter_verdict = _static_result(event, workspace_root=workspace_root)
    if static is None:
        return None
    static_duration = _bounded_duration(started)
    judge_started = time.monotonic()
    judge_result: JudgeChainResult | None = None
    judge_status = "not_needed"
    judge_verdict = "not_run"
    provider = "none"
    model_sha256 = _sha256_text("none")
    failure_code: str | None = None

    if adapter_verdict == "unknown" and static.verdict == "unknown":
        configuration = resolve_judge_configuration(environ)
        if configuration.status == "ready" and configuration.chain is not None:
            judge_result = configuration.chain.judge(static.envelope)
            if judge_result.observation is None:
                judge_status = "failed"
                judge_verdict = "failed"
                failure_code = _failure_code(judge_result.failure_codes)
            else:
                judge_observation = judge_result.observation
                if not _valid_judge_observation(
                    judge_observation,
                    envelope_sha256=static.envelope.digest_sha256(),
                ):
                    judge_status = "failed"
                    judge_verdict = "failed"
                    failure_code = "provider_observation_invalid"
                else:
                    judge_status = "completed"
                    judge_verdict = judge_observation.verdict.verdict
                    provider = judge_observation.provider
                    model_sha256 = _sha256_text(judge_observation.model)
                    failure_code = _failure_code(judge_result.failure_codes)
        elif configuration.status == "not_configured":
            judge_status = "not_configured"
            judge_verdict = "not_run"
        else:
            judge_status = "failed"
            judge_verdict = "failed"
            failure_code = configuration.failure_code or "configuration_invalid"
    judge_duration = (
        _bounded_duration(judge_started)
        if judge_status in {"completed", "failed"}
        else 0.0
    )
    shadow_verdict = combine_externality_verdicts(
        adapter_verdict,
        static.verdict,
        judge_verdict,
    )
    observation = ExternalityShadowObservation(
        observation_id=_observation_id(event.event_id, static.envelope.digest_sha256()),
        pre_event_id=event.event_id,
        workspace_id=event.workspace_id,
        session_id=event.session_id,
        tool_use_id=event.tool_use_id,
        tool_family=static.envelope.tool_family,
        envelope_sha256=static.envelope.digest_sha256(),
        adapter_verdict=adapter_verdict,
        static_verdict=static.verdict,
        judge_status=judge_status,  # type: ignore[arg-type]
        judge_verdict=judge_verdict,
        shadow_verdict=shadow_verdict,
        provider=provider,
        model_sha256=model_sha256,
        failure_code=failure_code,
        analysis_coverage=static.envelope.analysis_coverage,
        capability_count=len(static.envelope.capabilities),
        risk_signal_count=len(static.envelope.risk_signals),
        static_duration_ms=static_duration,
        judge_duration_ms=judge_duration,
    )
    _validate_observation(observation)
    return observation


def store_externality_shadow_observation(
    db_path: Path,
    observation: ExternalityShadowObservation,
) -> None:
    _validate_observation(observation)
    with _connect(db_path) as conn:
        _require_schema(conn)
        conn.execute(
            """
            INSERT INTO externality_shadow_observations (
                observation_id, pre_event_id, workspace_id, session_id,
                tool_use_id, tool_family, envelope_sha256, adapter_verdict,
                static_verdict, judge_status, judge_verdict, shadow_verdict,
                provider, model_sha256, failure_code, analysis_coverage,
                capability_count, risk_signal_count, static_duration_ms,
                judge_duration_ms
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(observation_id) DO NOTHING
            """,
            _observation_values(observation),
        )
        _verify_stored(conn, observation)


def list_externality_shadow_observations(
    db_path: Path,
) -> list[ExternalityShadowObservation]:
    with _connect(db_path) as conn:
        _require_schema(conn)
        rows = conn.execute(
            """
            SELECT observation_id, pre_event_id, workspace_id, session_id,
                   tool_use_id, tool_family, envelope_sha256, adapter_verdict,
                   static_verdict, judge_status, judge_verdict, shadow_verdict,
                   provider, model_sha256, failure_code, analysis_coverage,
                   capability_count, risk_signal_count, static_duration_ms,
                   judge_duration_ms
            FROM externality_shadow_observations
            ORDER BY created_at, observation_id
            """
        ).fetchall()
    return [_observation_from_row(row) for row in rows]


def build_externality_shadow_report(
    observations: Iterable[ExternalityShadowObservation],
) -> dict[str, object]:
    items = tuple(observations)
    judge_latencies = sorted(
        item.judge_duration_ms for item in items if item.judge_status == "completed"
    )
    adapter_external = sum(item.adapter_verdict == "external" for item in items)
    added_risk = sum(
        item.adapter_verdict != "external"
        and item.shadow_verdict in {"external", "possibly_external", "unknown"}
        for item in items
    )
    return {
        "schema_version": EXTERNALITY_SHADOW_SCHEMA_VERSION,
        "observation_count": len(items),
        "adapter_verdict": _counts(item.adapter_verdict for item in items),
        "static_verdict": _counts(item.static_verdict for item in items),
        "judge_status": _counts(item.judge_status for item in items),
        "judge_verdict": _counts(item.judge_verdict for item in items),
        "shadow_verdict": _counts(item.shadow_verdict for item in items),
        "adapter_external_count": adapter_external,
        "shadow_added_risk_count": added_risk,
        "judge_latency_ms": {
            "p50": _percentile(judge_latencies, 0.50),
            "p95": _percentile(judge_latencies, 0.95),
            "p99": _percentile(judge_latencies, 0.99),
            "max": max(judge_latencies) if judge_latencies else None,
        },
        "privacy": {
            "raw_value_fields": 0,
            "source_identity_fields": 0,
        },
        "production_behavior_changed": False,
    }


def _static_result(
    event: NormalizedEvent,
    *,
    workspace_root: Path,
) -> tuple[StaticExternalityResult | None, Literal["external", "unknown"]]:
    tool_input = event.raw_payload.get("tool_input")
    if is_enforced_shell_tool(event.tool_name):
        command = shell_command_from_input(event.tool_name, tool_input)
        if command is None:
            return None, "unknown"
        static = analyze_bash_externality(
            command,
            workspace_root=workspace_root,
            cwd=Path(event.workspace_execution_cwd or workspace_root),
        )
        return static, (
            "external" if classify_bash_sink_type(command) is not None else "unknown"
        )
    if isinstance(tool_input, dict) and event.tool_name and event.tool_name.startswith("mcp__"):
        static = analyze_mcp_externality(event.tool_name, tool_input)
        return static, (
            "external"
            if classify_mcp_sink_type(event.tool_name, tool_input) is not None
            else "unknown"
        )
    return None, "unknown"


def combine_externality_verdicts(
    adapter_verdict: str,
    static_verdict: str,
    judge_verdict: str,
) -> Literal["external", "possibly_external", "local", "unknown"]:
    if adapter_verdict == "external" or static_verdict == "external":
        return "external"
    if judge_verdict in {"external", "possibly_external"}:
        return judge_verdict  # type: ignore[return-value]
    if static_verdict == "local":
        return "local"
    return "unknown"


def initialize_externality_shadow_schema(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS externality_shadow_observations (
            observation_id TEXT PRIMARY KEY,
            pre_event_id TEXT NOT NULL,
            workspace_id TEXT NOT NULL,
            session_id TEXT NOT NULL,
            tool_use_id TEXT,
            tool_family TEXT NOT NULL CHECK (tool_family IN ('bash', 'mcp')),
            envelope_sha256 TEXT NOT NULL,
            adapter_verdict TEXT NOT NULL CHECK (adapter_verdict IN ('external', 'unknown')),
            static_verdict TEXT NOT NULL CHECK (static_verdict IN ('external', 'local', 'unknown')),
            judge_status TEXT NOT NULL CHECK (judge_status IN ('not_needed', 'not_configured', 'completed', 'failed')),
            judge_verdict TEXT NOT NULL CHECK (judge_verdict IN ('external', 'possibly_external', 'local', 'unknown', 'not_run', 'failed')),
            shadow_verdict TEXT NOT NULL CHECK (shadow_verdict IN ('external', 'possibly_external', 'local', 'unknown')),
            provider TEXT NOT NULL,
            model_sha256 TEXT NOT NULL,
            failure_code TEXT,
            analysis_coverage TEXT NOT NULL CHECK (analysis_coverage IN ('complete', 'partial', 'opaque')),
            capability_count INTEGER NOT NULL CHECK (capability_count >= 0),
            risk_signal_count INTEGER NOT NULL CHECK (risk_signal_count >= 0),
            static_duration_ms REAL NOT NULL CHECK (static_duration_ms >= 0),
            judge_duration_ms REAL NOT NULL CHECK (judge_duration_ms >= 0),
            schema_version TEXT NOT NULL DEFAULT 'externality-shadow-v1',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    conn.execute(
        """
        CREATE TRIGGER IF NOT EXISTS externality_shadow_observations_no_update
        BEFORE UPDATE ON externality_shadow_observations
        BEGIN
            SELECT RAISE(ABORT, 'externality shadow observation is immutable');
        END
        """
    )
    conn.execute(
        """
        CREATE TRIGGER IF NOT EXISTS externality_shadow_observations_no_delete
        BEFORE DELETE ON externality_shadow_observations
        BEGIN
            SELECT RAISE(ABORT, 'externality shadow observation is immutable');
        END
        """
    )
    _require_schema(conn)


def _require_schema(conn: sqlite3.Connection) -> None:
    columns = tuple(
        row[1]
        for row in conn.execute(
            "PRAGMA table_info(externality_shadow_observations)"
        ).fetchall()
    )
    expected = (
        "observation_id", "pre_event_id", "workspace_id", "session_id",
        "tool_use_id", "tool_family", "envelope_sha256", "adapter_verdict",
        "static_verdict", "judge_status", "judge_verdict", "shadow_verdict",
        "provider", "model_sha256", "failure_code", "analysis_coverage",
        "capability_count", "risk_signal_count", "static_duration_ms",
        "judge_duration_ms", "schema_version", "created_at",
    )
    if columns != expected:
        raise RuntimeError("externality shadow schema mismatch")
    triggers = {
        str(row[0])
        for row in conn.execute(
            "SELECT name FROM sqlite_master "
            "WHERE type = 'trigger' AND tbl_name = ?",
            ("externality_shadow_observations",),
        ).fetchall()
    }
    if not {
        "externality_shadow_observations_no_update",
        "externality_shadow_observations_no_delete",
    }.issubset(triggers):
        raise RuntimeError("externality shadow schema mismatch")


@contextmanager
def _connect(db_path: Path) -> Iterator[sqlite3.Connection]:
    timeout_seconds = EXTERNALITY_SHADOW_BUSY_TIMEOUT_MS / 1000
    conn = sqlite3.connect(db_path, timeout=timeout_seconds)
    try:
        conn.execute(f"PRAGMA busy_timeout = {EXTERNALITY_SHADOW_BUSY_TIMEOUT_MS}")
        with conn:
            yield conn
    finally:
        conn.close()


def _validate_observation(observation: ExternalityShadowObservation) -> None:
    for value in (
        observation.observation_id,
        observation.pre_event_id,
        observation.workspace_id,
        observation.session_id,
        observation.envelope_sha256,
        observation.provider,
        observation.model_sha256,
    ):
        if not value or len(value.encode("utf-8", errors="surrogatepass")) > 4096:
            raise ValueError("externality shadow identity is invalid")
    if observation.tool_family not in {"bash", "mcp"}:
        raise ValueError("externality shadow tool family is invalid")
    if observation.adapter_verdict not in _ADAPTER_VERDICTS:
        raise ValueError("externality shadow adapter verdict is invalid")
    if observation.static_verdict not in _STATIC_VERDICTS:
        raise ValueError("externality shadow static verdict is invalid")
    if observation.judge_status not in _JUDGE_STATUSES:
        raise ValueError("externality shadow judge status is invalid")
    if observation.judge_verdict not in _JUDGE_VERDICTS:
        raise ValueError("externality shadow judge verdict is invalid")
    if observation.shadow_verdict not in _SHADOW_VERDICTS:
        raise ValueError("externality shadow verdict is invalid")
    if observation.analysis_coverage not in _ANALYSIS_COVERAGE:
        raise ValueError("externality shadow analysis coverage is invalid")
    if observation.provider not in _JUDGE_PROVIDERS:
        raise ValueError("externality shadow provider is invalid")
    for digest in (observation.envelope_sha256, observation.model_sha256):
        if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
            raise ValueError("externality shadow digest is invalid")
    if observation.failure_code is not None and (
        not observation.failure_code
        or len(observation.failure_code) > 128
        or not all(character.islower() or character == "_" for character in observation.failure_code)
    ):
        raise ValueError("externality shadow failure code is invalid")
    for count in (observation.capability_count, observation.risk_signal_count):
        if isinstance(count, bool) or not isinstance(count, int) or not 0 <= count <= MAX_SHADOW_COUNT:
            raise ValueError("externality shadow count is invalid")
    for duration in (observation.static_duration_ms, observation.judge_duration_ms):
        if not isinstance(duration, float) or not math.isfinite(duration) or not 0 <= duration <= MAX_SHADOW_DURATION_MS:
            raise ValueError("externality shadow duration is invalid")
    expected_observation_id = _observation_id(
        observation.pre_event_id,
        observation.envelope_sha256,
    )
    if observation.observation_id != expected_observation_id:
        raise ValueError("externality shadow observation id is inconsistent")
    if observation.tool_use_id is not None and (
        not observation.tool_use_id
        or len(observation.tool_use_id.encode("utf-8", errors="surrogatepass")) > 4096
    ):
        raise ValueError("externality shadow tool use id is invalid")
    _validate_judge_state(observation)
    expected = combine_externality_verdicts(
        observation.adapter_verdict,
        observation.static_verdict,
        observation.judge_verdict,
    )
    if observation.shadow_verdict != expected:
        raise ValueError("externality shadow verdict is inconsistent")


def _validate_judge_state(observation: ExternalityShadowObservation) -> None:
    if observation.judge_status in {"not_needed", "not_configured"}:
        if (
            observation.judge_verdict != "not_run"
            or observation.provider != "none"
            or observation.model_sha256 != _sha256_text("none")
            or observation.failure_code is not None
            or observation.judge_duration_ms != 0.0
        ):
            raise ValueError("externality shadow judge state is inconsistent")
        return
    if observation.judge_status == "failed":
        if (
            observation.judge_verdict != "failed"
            or observation.provider != "none"
            or observation.model_sha256 != _sha256_text("none")
            or observation.failure_code is None
        ):
            raise ValueError("externality shadow judge state is inconsistent")
        return
    if (
        observation.judge_verdict not in {"external", "possibly_external", "local", "unknown"}
        or observation.provider == "none"
        or observation.model_sha256 == _sha256_text("none")
    ):
        raise ValueError("externality shadow judge state is inconsistent")


def _observation_values(observation: ExternalityShadowObservation) -> tuple[object, ...]:
    return (
        observation.observation_id, observation.pre_event_id, observation.workspace_id,
        observation.session_id, observation.tool_use_id, observation.tool_family,
        observation.envelope_sha256, observation.adapter_verdict,
        observation.static_verdict, observation.judge_status,
        observation.judge_verdict, observation.shadow_verdict,
        observation.provider, observation.model_sha256, observation.failure_code,
        observation.analysis_coverage, observation.capability_count,
        observation.risk_signal_count, observation.static_duration_ms,
        observation.judge_duration_ms,
    )


def _observation_from_row(row: tuple[object, ...]) -> ExternalityShadowObservation:
    return ExternalityShadowObservation(
        observation_id=str(row[0]), pre_event_id=str(row[1]),
        workspace_id=str(row[2]), session_id=str(row[3]),
        tool_use_id=None if row[4] is None else str(row[4]), tool_family=str(row[5]),
        envelope_sha256=str(row[6]), adapter_verdict=str(row[7]),  # type: ignore[arg-type]
        static_verdict=str(row[8]), judge_status=str(row[9]),  # type: ignore[arg-type]
        judge_verdict=str(row[10]), shadow_verdict=str(row[11]),  # type: ignore[arg-type]
        provider=str(row[12]), model_sha256=str(row[13]),
        failure_code=None if row[14] is None else str(row[14]),
        analysis_coverage=str(row[15]), capability_count=int(row[16]),
        risk_signal_count=int(row[17]), static_duration_ms=float(row[18]),
        judge_duration_ms=float(row[19]),
    )


def _verify_stored(conn: sqlite3.Connection, observation: ExternalityShadowObservation) -> None:
    row = conn.execute(
        """
        SELECT observation_id, pre_event_id, workspace_id, session_id,
               tool_use_id, tool_family, envelope_sha256, adapter_verdict,
               static_verdict, judge_status, judge_verdict, shadow_verdict,
               provider, model_sha256, failure_code, analysis_coverage,
               capability_count, risk_signal_count, static_duration_ms,
               judge_duration_ms
        FROM externality_shadow_observations WHERE observation_id = ?
        """,
        (observation.observation_id,),
    ).fetchone()
    if row is None:
        raise sqlite3.IntegrityError("externality shadow observation was not stored")
    existing = _observation_from_row(row)
    # Runtime duration is intentionally first-write-wins; every decision field is immutable.
    if _immutable_signature(existing) != _immutable_signature(observation):
        raise sqlite3.IntegrityError("externality shadow replay mismatch")


def _immutable_signature(observation: ExternalityShadowObservation) -> tuple[object, ...]:
    return (
        observation.observation_id,
        observation.pre_event_id,
        observation.workspace_id,
        observation.session_id,
        observation.tool_use_id,
        observation.tool_family,
        observation.envelope_sha256,
        observation.adapter_verdict,
        observation.static_verdict,
        observation.judge_status,
        observation.judge_verdict,
        observation.shadow_verdict,
        observation.provider,
        observation.model_sha256,
        observation.failure_code,
        observation.analysis_coverage,
        observation.capability_count,
        observation.risk_signal_count,
    )


def _observation_id(event_id: str, envelope_sha256: str) -> str:
    return _sha256_text("\0".join((EXTERNALITY_SHADOW_SCHEMA_VERSION, event_id, envelope_sha256)))


def _failure_code(codes: tuple[str, ...]) -> str | None:
    if not codes:
        return None
    if len(codes) == 1:
        return codes[0]
    return "provider_chain_failed"


def _valid_judge_observation(
    observation: object,
    *,
    envelope_sha256: str,
) -> bool:
    if not isinstance(observation, JudgeObservation):
        return False
    return (
        observation.provider in _JUDGE_PROVIDERS - {"none"}
        and bool(_MODEL_PATTERN.fullmatch(observation.model))
        and observation.envelope_sha256 == envelope_sha256
        and isinstance(observation.latency_ms, int)
        and not isinstance(observation.latency_ms, bool)
        and 0 <= observation.latency_ms <= MAX_SHADOW_DURATION_MS
    )


def _bounded_duration(started: float) -> float:
    return min(MAX_SHADOW_DURATION_MS, max(0.0, (time.monotonic() - started) * 1000))


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _counts(values: Iterable[str]) -> dict[str, int]:
    return dict(sorted(Counter(values).items()))


def _percentile(sorted_values: list[float], fraction: float) -> float | None:
    if not sorted_values:
        return None
    index = max(0, int(len(sorted_values) * fraction + 0.999999999) - 1)
    return sorted_values[min(index, len(sorted_values) - 1)]
