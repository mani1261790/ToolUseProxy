from __future__ import annotations

import hashlib
import json
import re
import shlex
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Literal, Mapping

from hook_monitor.analysis.adapters.bash import classify_bash_sink_type
from hook_monitor.analysis.adapters.mcp import classify_mcp_sink_type
from hook_monitor.externality.configuration import resolve_judge_configuration
from hook_monitor.externality.envelope import (
    analyze_bash_externality,
    analyze_mcp_externality,
)
from hook_monitor.externality.models import ExternalityEnvelope, ExternalityVerdict
from hook_monitor.externality.providers import JudgeObservation
from hook_monitor.runtime.models import NormalizedEvent
from hook_monitor.runtime.tool_compat import (
    is_enforced_shell_tool,
    shell_command_from_input,
)


EXTERNALITY_RULE_CONTRACT_VERSION = "externality-rule-v1"
EXTERNALITY_RULE_CONTRACT_SHA256 = hashlib.sha256(
    EXTERNALITY_RULE_CONTRACT_VERSION.encode("utf-8")
).hexdigest()
EXTERNALITY_RULE_BUSY_TIMEOUT_MS = 10
GENERIC_FUNCTION_EXTERNALITY_CONTRACT = b"generic-function-externality-v1"
TRUSTED_SETUP_PROFILE_CONTRACT = b"trusted-tooluseproxy-setup-profile-v1"
_REVISION_PATTERN = re.compile(r"[0-9a-f]{64}")
_RECONCILIATION_REVISION_PATTERN = re.compile(r"r1_[0-9a-f]{64}")


@dataclass(frozen=True)
class ExternalityRuleMatch:
    envelope_sha256: str
    verdict: Literal["external", "possibly_external", "local"]
    review_revision: str

    @property
    def adds_external_sink(self) -> bool:
        return self.verdict in {"external", "possibly_external"}


@dataclass(frozen=True)
class ExternalityReviewItem:
    job_id: str
    envelope: ExternalityEnvelope
    verdict: ExternalityVerdict
    provider: str
    model_sha256: str
    review_revision: str

    def to_payload(self) -> dict[str, object]:
        return {
            "job_id": self.job_id,
            "envelope_sha256": self.envelope.digest_sha256(),
            "summary": self.envelope.to_dict(),
            "verdict": self.verdict.to_dict(),
            "provider": self.provider,
            "model_sha256": self.model_sha256,
            "review_revision": self.review_revision,
            "privacy": {"raw_value_fields": 0, "source_identity_fields": 0},
        }


@dataclass(frozen=True)
class ExternalityHookDecision:
    envelope_sha256: str
    state: Literal[
        "known_external",
        "known_local",
        "queued",
        "cache_hit",
        "analysis_failed",
    ]
    rule: ExternalityRuleMatch | None = None


def failed_externality_hook_decision() -> ExternalityHookDecision:
    return ExternalityHookDecision(
        hashlib.sha256(b"externality-analysis-failed-v1").hexdigest(),
        "analysis_failed",
    )


def conservative_function_tool_decision(tool_name: str | None) -> ExternalityHookDecision:
    """Treat an unclassified Hook-visible function tool as a potential sink."""

    encoded_name = (tool_name or "unknown").encode("utf-8", errors="replace")
    digest = hashlib.sha256(
        GENERIC_FUNCTION_EXTERNALITY_CONTRACT
        + b"\0"
        + hashlib.sha256(encoded_name).digest()
    ).hexdigest()
    return ExternalityHookDecision(digest, "analysis_failed")


def classify_static_externality_hook_decision(
    event: NormalizedEvent,
    *,
    workspace_root: Path,
    trusted_plugin_root: Path | None = None,
    plugin_data: Path | None = None,
) -> ExternalityHookDecision | None:
    """Classify without queue, cache, provider, or network activity."""

    if event.phase != "pre_tool_use" or event.workspace_status != "ready":
        return None
    tool_input = event.raw_payload.get("tool_input")
    if is_enforced_shell_tool(event.tool_name):
        command = shell_command_from_input(event.tool_name, tool_input)
        if command is None:
            return None
        if plugin_data is not None:
            trusted_setup_operation = _trusted_local_recovery_operation(
                command,
                plugin_root=trusted_plugin_root,
                workspace_root=workspace_root,
                plugin_data=plugin_data,
            )
            if trusted_setup_operation is not None:
                digest = hashlib.sha256(
                    TRUSTED_SETUP_PROFILE_CONTRACT
                    + b"\0"
                    + trusted_setup_operation.encode("ascii")
                ).hexdigest()
                return ExternalityHookDecision(digest, "known_local")
        static = analyze_bash_externality(
            command,
            workspace_root=workspace_root,
            cwd=Path(event.workspace_execution_cwd or workspace_root),
        )
        adapter_external = classify_bash_sink_type(command) is not None
    elif (
        isinstance(tool_input, dict)
        and event.tool_name
        and event.tool_name.startswith("mcp__")
    ):
        static = analyze_mcp_externality(event.tool_name, tool_input)
        adapter_external = classify_mcp_sink_type(event.tool_name, tool_input) is not None
    else:
        return None
    digest = static.envelope.digest_sha256()
    if adapter_external or static.verdict == "external":
        return ExternalityHookDecision(digest, "known_external")
    if static.verdict == "local":
        return ExternalityHookDecision(digest, "known_local")
    return ExternalityHookDecision(digest, "analysis_failed")


def prepare_externality_hook_decision(
    db_path: Path,
    event: NormalizedEvent,
    *,
    workspace_root: Path,
    trusted_plugin_root: Path | None = None,
) -> ExternalityHookDecision | None:
    """Perform only bounded static analysis and local SQLite work in the Hook."""
    static_decision = classify_static_externality_hook_decision(
        event,
        workspace_root=workspace_root,
        trusted_plugin_root=trusted_plugin_root,
        plugin_data=db_path.parent,
    )
    if static_decision is None or static_decision.state != "analysis_failed":
        return static_decision
    digest = static_decision.envelope_sha256
    if event.workspace_id is None:
        return None
    rule = lookup_externality_rule(db_path, event.workspace_id, digest)
    if rule is not None:
        return ExternalityHookDecision(digest, "cache_hit", rule)
    tool_input = event.raw_payload.get("tool_input")
    if is_enforced_shell_tool(event.tool_name):
        command = shell_command_from_input(event.tool_name, tool_input)
        if command is None:
            return None
        static = analyze_bash_externality(
            command,
            workspace_root=workspace_root,
            cwd=Path(event.workspace_execution_cwd or workspace_root),
        )
    elif (
        isinstance(tool_input, dict)
        and event.tool_name
        and event.tool_name.startswith("mcp__")
    ):
        static = analyze_mcp_externality(event.tool_name, tool_input)
    else:
        return None
    queue_externality_envelope(db_path, event.workspace_id, static.envelope)
    return ExternalityHookDecision(digest, "queued")


def _trusted_local_recovery_operation(
    command: str,
    *,
    plugin_root: Path | None,
    workspace_root: Path,
    plugin_data: Path,
) -> Literal["apply", "verify", "reconcile_plan", "reconcile_apply"] | None:
    """Recognize only fixed, revision-bound local recovery commands."""

    if plugin_root is None:
        return None
    try:
        tokens = shlex.split(command, posix=True)
    except ValueError:
        return None
    launcher = str(plugin_root / "hooks" / "run_cli.sh")
    common = ["sh", launcher, "setup"]
    workspace = str(workspace_root)
    data_dir = str(plugin_data)
    if tokens == [
        "sh",
        launcher,
        "protect",
        "reconcile",
        "plan",
        "--workspace",
        workspace,
        "--json",
    ]:
        return "reconcile_plan"
    reconciliation_prefix = [
        "sh",
        launcher,
        "protect",
        "reconcile",
        "apply",
        "--reconciliation-revision",
    ]
    reconciliation_suffix = [
        "--expected-manifest-sha256",
        None,
        "--workspace",
        workspace,
        "--json",
    ]
    if (
        len(tokens)
        == len(reconciliation_prefix) + 1 + len(reconciliation_suffix)
        and tokens[: len(reconciliation_prefix)] == reconciliation_prefix
        and _RECONCILIATION_REVISION_PATTERN.fullmatch(
            tokens[len(reconciliation_prefix)]
        )
        and tokens[-len(reconciliation_suffix) :][0]
        == reconciliation_suffix[0]
        and _REVISION_PATTERN.fullmatch(tokens[-len(reconciliation_suffix) :][1])
        and tokens[-len(reconciliation_suffix) :][2:]
        == reconciliation_suffix[2:]
    ):
        return "reconcile_apply"
    if tokens in (
        [
            *common,
            "verify",
            "file-payload-exact",
            "--workspace",
            workspace,
            "--data-dir",
            data_dir,
            "--json",
        ],
        [
            *common,
            "verify",
            "file-payload-exact",
            "--workspace",
            workspace,
            "--json",
        ],
    ):
        return "verify"
    if tokens in (
        [
            *common,
            "apply",
            "file-payload-exact",
            "--codex",
            "--expect-empty-settings",
            "--workspace",
            workspace,
            "--json",
        ],
        [
            *common,
            "apply",
            "file-payload-exact",
            "--codex",
            "--expect-compatible-settings",
            "--workspace",
            workspace,
            "--json",
        ],
    ):
        return "apply"
    prefix = [
        *common,
        "apply",
        "file-payload-exact",
        "--codex",
        "--expected-revision",
    ]
    suffix = [
        "--workspace",
        workspace,
        "--data-dir",
        data_dir,
        "--json",
    ]
    if (
        len(tokens) == len(prefix) + 1 + len(suffix)
        and tokens[: len(prefix)] == prefix
        and _REVISION_PATTERN.fullmatch(tokens[len(prefix)])
        and tokens[-len(suffix) :] == suffix
    ):
        return "apply"
    return None


def initialize_externality_rule_schema(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS externality_classification_jobs (
            job_id TEXT PRIMARY KEY,
            workspace_id TEXT NOT NULL,
            envelope_sha256 TEXT NOT NULL,
            contract_sha256 TEXT NOT NULL,
            envelope_json TEXT NOT NULL,
            status TEXT NOT NULL CHECK (
                status IN ('pending', 'processing', 'review_pending',
                           'failed', 'approved', 'rejected')
            ),
            provider TEXT,
            model_sha256 TEXT,
            verdict_json TEXT,
            failure_code TEXT,
            attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE (workspace_id, envelope_sha256, contract_sha256)
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS externality_approved_rules (
            rule_id TEXT PRIMARY KEY,
            workspace_id TEXT NOT NULL,
            envelope_sha256 TEXT NOT NULL,
            contract_sha256 TEXT NOT NULL,
            verdict TEXT NOT NULL CHECK (
                verdict IN ('external', 'possibly_external', 'local')
            ),
            review_revision TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE (workspace_id, envelope_sha256, contract_sha256)
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS externality_rule_reviews (
            review_id TEXT PRIMARY KEY,
            job_id TEXT NOT NULL,
            decision TEXT NOT NULL CHECK (decision IN ('approve', 'reject')),
            expected_revision TEXT NOT NULL,
            verdict TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    for table in ("externality_approved_rules", "externality_rule_reviews"):
        conn.execute(
            f"""
            CREATE TRIGGER IF NOT EXISTS {table}_no_update
            BEFORE UPDATE ON {table}
            BEGIN SELECT RAISE(ABORT, '{table} is immutable'); END
            """
        )
        conn.execute(
            f"""
            CREATE TRIGGER IF NOT EXISTS {table}_no_delete
            BEFORE DELETE ON {table}
            BEGIN SELECT RAISE(ABORT, '{table} is immutable'); END
            """
        )


def queue_externality_envelope(
    db_path: Path,
    workspace_id: str,
    envelope: ExternalityEnvelope,
) -> str:
    envelope_sha256 = envelope.digest_sha256()
    job_id = _job_id(workspace_id, envelope_sha256)
    with _connect(db_path) as conn:
        conn.execute(
            """
            INSERT INTO externality_classification_jobs (
                job_id, workspace_id, envelope_sha256, contract_sha256,
                envelope_json, status
            ) VALUES (?, ?, ?, ?, ?, 'pending')
            ON CONFLICT(workspace_id, envelope_sha256, contract_sha256) DO NOTHING
            """,
            (
                job_id,
                workspace_id,
                envelope_sha256,
                EXTERNALITY_RULE_CONTRACT_SHA256,
                envelope.canonical_json(),
            ),
        )
    return job_id


def lookup_externality_rule(
    db_path: Path,
    workspace_id: str,
    envelope_sha256: str,
) -> ExternalityRuleMatch | None:
    with _connect(db_path) as conn:
        row = conn.execute(
            """
            SELECT verdict, review_revision
            FROM externality_approved_rules
            WHERE workspace_id = ? AND envelope_sha256 = ? AND contract_sha256 = ?
            """,
            (workspace_id, envelope_sha256, EXTERNALITY_RULE_CONTRACT_SHA256),
        ).fetchone()
    if row is None:
        return None
    return ExternalityRuleMatch(envelope_sha256, str(row[0]), str(row[1]))  # type: ignore[arg-type]


def process_externality_jobs(
    db_path: Path,
    *,
    environ: Mapping[str, str],
    limit: int = 10,
    retry_failed: bool = False,
) -> dict[str, object]:
    if not 1 <= limit <= 100:
        raise ValueError("limit must be within [1, 100]")
    configuration = resolve_judge_configuration(environ)
    if configuration.status != "ready" or configuration.chain is None:
        raise ValueError(configuration.failure_code or "judge_not_configured")
    processed = 0
    review_pending = 0
    failed = 0
    while processed < limit:
        claimed = _claim_job(db_path, retry_failed=retry_failed)
        if claimed is None:
            break
        job_id, envelope = claimed
        processed += 1
        try:
            result = configuration.chain.judge(envelope)
        except Exception:
            _finish_failed(db_path, job_id, "provider_call_failed")
            failed += 1
            continue
        observation = result.observation
        if observation is None or not _observation_matches(observation, envelope):
            _finish_failed(
                db_path,
                job_id,
                _failure_code(result.failure_codes, observation is not None),
            )
            failed += 1
            continue
        _finish_classified(db_path, job_id, observation)
        review_pending += 1
    return {
        "processed": processed,
        "review_pending": review_pending,
        "failed": failed,
        "network_used": processed > 0,
        "privacy": {"raw_value_fields": 0, "source_identity_fields": 0},
    }


def list_externality_reviews(db_path: Path) -> list[ExternalityReviewItem]:
    with _connect(db_path) as conn:
        rows = conn.execute(
            """
            SELECT job_id, envelope_json, verdict_json, provider, model_sha256
            FROM externality_classification_jobs
            WHERE status = 'review_pending'
            ORDER BY created_at, job_id
            """
        ).fetchall()
    items: list[ExternalityReviewItem] = []
    for row in rows:
        envelope = ExternalityEnvelope.from_mapping(json.loads(str(row[1])))
        verdict = ExternalityVerdict.from_mapping(json.loads(str(row[2])))
        revision = _review_revision(
            str(row[0]), envelope.digest_sha256(), str(row[3]), str(row[4]), verdict
        )
        items.append(
            ExternalityReviewItem(
                str(row[0]), envelope, verdict, str(row[3]), str(row[4]), revision
            )
        )
    return items


def review_externality_job(
    db_path: Path,
    *,
    job_id: str,
    expected_revision: str,
    decision: Literal["approve", "reject"],
) -> ExternalityRuleMatch | None:
    with _connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            """
            SELECT workspace_id, envelope_sha256, verdict_json, provider,
                   model_sha256, status
            FROM externality_classification_jobs WHERE job_id = ?
            """,
            (job_id,),
        ).fetchone()
        if row is None or str(row[5]) != "review_pending":
            raise ValueError("externality review is not pending")
        verdict = ExternalityVerdict.from_mapping(json.loads(str(row[2])))
        revision = _review_revision(
            job_id, str(row[1]), str(row[3]), str(row[4]), verdict
        )
        if revision != expected_revision:
            raise ValueError("externality review revision changed")
        if decision == "approve" and verdict.verdict == "unknown":
            raise ValueError("unknown verdict cannot be approved")
        review_id = _sha256("\0".join(("review", job_id, decision, revision)))
        conn.execute(
            """
            INSERT INTO externality_rule_reviews (
                review_id, job_id, decision, expected_revision, verdict
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (review_id, job_id, decision, revision, verdict.verdict),
        )
        match: ExternalityRuleMatch | None = None
        if decision == "approve":
            rule_id = _sha256("\0".join(("rule", str(row[0]), str(row[1]), EXTERNALITY_RULE_CONTRACT_SHA256)))
            conn.execute(
                """
                INSERT INTO externality_approved_rules (
                    rule_id, workspace_id, envelope_sha256, contract_sha256,
                    verdict, review_revision
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (rule_id, str(row[0]), str(row[1]), EXTERNALITY_RULE_CONTRACT_SHA256, verdict.verdict, revision),
            )
            match = ExternalityRuleMatch(str(row[1]), verdict.verdict, revision)  # type: ignore[arg-type]
        conn.execute(
            """
            UPDATE externality_classification_jobs
            SET status = ?, updated_at = CURRENT_TIMESTAMP
            WHERE job_id = ? AND status = 'review_pending'
            """,
            ("approved" if decision == "approve" else "rejected", job_id),
        )
    return match


def _claim_job(
    db_path: Path,
    *,
    retry_failed: bool,
) -> tuple[str, ExternalityEnvelope] | None:
    statuses = ("pending", "failed") if retry_failed else ("pending",)
    placeholders = ",".join("?" for _ in statuses)
    with _connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            f"""
            SELECT job_id, envelope_json FROM externality_classification_jobs
            WHERE status IN ({placeholders}) ORDER BY created_at, job_id LIMIT 1
            """,
            statuses,
        ).fetchone()
        if row is None:
            return None
        updated = conn.execute(
            """
            UPDATE externality_classification_jobs
            SET status = 'processing', attempt_count = attempt_count + 1,
                failure_code = NULL, updated_at = CURRENT_TIMESTAMP
            WHERE job_id = ? AND status IN ('pending', 'failed')
            """,
            (str(row[0]),),
        ).rowcount
        if updated != 1:
            return None
    return str(row[0]), ExternalityEnvelope.from_mapping(json.loads(str(row[1])))


def _finish_classified(
    db_path: Path,
    job_id: str,
    observation: JudgeObservation,
) -> None:
    with _connect(db_path) as conn:
        updated = conn.execute(
            """
            UPDATE externality_classification_jobs
            SET status = 'review_pending', provider = ?, model_sha256 = ?,
                verdict_json = ?, failure_code = NULL,
                updated_at = CURRENT_TIMESTAMP
            WHERE job_id = ? AND status = 'processing'
            """,
            (
                observation.provider,
                _sha256(observation.model),
                json.dumps(observation.verdict.to_dict(), sort_keys=True, separators=(",", ":")),
                job_id,
            ),
        ).rowcount
        if updated != 1:
            raise sqlite3.IntegrityError("externality job state changed")


def _finish_failed(db_path: Path, job_id: str, failure_code: str) -> None:
    with _connect(db_path) as conn:
        updated = conn.execute(
            """
            UPDATE externality_classification_jobs
            SET status = 'failed', provider = NULL, model_sha256 = NULL,
                verdict_json = NULL, failure_code = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE job_id = ? AND status = 'processing'
            """,
            (failure_code, job_id),
        ).rowcount
        if updated != 1:
            raise sqlite3.IntegrityError("externality job state changed")


def _observation_matches(
    observation: JudgeObservation,
    envelope: ExternalityEnvelope,
) -> bool:
    return observation.envelope_sha256 == envelope.digest_sha256()


def _failure_code(codes: tuple[str, ...], invalid_observation: bool) -> str:
    if invalid_observation:
        return "provider_observation_invalid"
    if len(codes) == 1:
        return codes[0]
    return "provider_chain_failed"


def _review_revision(
    job_id: str,
    envelope_sha256: str,
    provider: str,
    model_sha256: str,
    verdict: ExternalityVerdict,
) -> str:
    return _sha256(
        "\0".join(
            (
                "review-revision-v1",
                job_id,
                envelope_sha256,
                provider,
                model_sha256,
                json.dumps(verdict.to_dict(), sort_keys=True, separators=(",", ":")),
            )
        )
    )


def _job_id(workspace_id: str, envelope_sha256: str) -> str:
    return _sha256(
        "\0".join(
            ("job-v1", workspace_id, envelope_sha256, EXTERNALITY_RULE_CONTRACT_SHA256)
        )
    )


@contextmanager
def _connect(db_path: Path) -> Iterator[sqlite3.Connection]:
    conn = sqlite3.connect(
        db_path,
        timeout=EXTERNALITY_RULE_BUSY_TIMEOUT_MS / 1000,
    )
    try:
        conn.execute(f"PRAGMA busy_timeout = {EXTERNALITY_RULE_BUSY_TIMEOUT_MS}")
        with conn:
            yield conn
    finally:
        conn.close()


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()
