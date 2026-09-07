from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import sqlite3
from contextlib import closing
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Callable

from hook_monitor.runtime.storage import CURRENT_SCHEMA_VERSION
from tooluseproxy.migration_backups import (
    MigrationBackupError,
    MigrationBackupInventory,
    delete_verified_migration_backups,
    inventory_migration_backups,
)


STORAGE_CLEANUP_PLAN_SCHEMA_VERSION = 4
STORAGE_RETENTION_DAYS = 30
STORAGE_CLEANUP_DEFAULT_BATCH_SIZE = 20
STORAGE_CLEANUP_MAX_BATCH_SIZE = 100
STORAGE_CLEANUP_REVIEW_WINDOW = timedelta(minutes=5)
STORAGE_WARNING_BYTES = 2 * 1024 * 1024 * 1024
STORAGE_ACTION_BYTES = 4 * 1024 * 1024 * 1024
_TEMPORARY_SPACE_MARGIN_BYTES = 16 * 1024 * 1024
_IMPROVEMENT_FEEDBACK_TABLES = frozenset(
    {
        "externality_approved_rules",
        "externality_classification_jobs",
        "externality_rule_reviews",
        "externality_shadow_observations",
        "pilot_comparisons",
        "pilot_coverage_snapshots",
        "pilot_issue_bindings",
        "pilot_issue_config",
        "pilot_issue_outbox",
        "pilot_issue_preparations",
        "pilot_miss_events",
        "pilot_observations",
        "pilot_project_aliases",
        "pilot_reviews",
        "sink_payload_shadow_observations",
    }
)
_DURABLE_CONFIGURATION_TABLES = frozenset(
    {
        "analysis_state",
        "protected_source_candidate_reviews",
        "protected_source_candidates",
        "protected_sources",
        "source_chunks",
        "workspace_analysis_state",
        "workspace_runtime_setting_changes",
        "workspace_runtime_settings",
        "workspaces",
    }
)
_REBUILDABLE_DETECTION_TABLES = frozenset(
    {
        "analysis_cursors",
        "content_similarity_features",
        "fragment_exact_index",
        "fragment_shingles",
        "runtime_lineage_state",
        "runtime_source_binding_edges",
    }
)
_CORE_RETENTION_TABLES = (
    "analysis_cursors",
    "analysis_run_flow_edges",
    "analysis_run_graphs",
    "analysis_run_nodes",
    "analysis_runs",
    "analysis_node_snapshots",
    "artifact_contents",
    "events",
    "event_payload_metadata",
    "artifacts",
    "artifact_fragments",
    "content_similarity_features",
    "flow_edges",
    "fragment_exact_index",
    "information_flow_edges",
    "lineage_assignments",
    "policy_decisions",
    "redaction_decision_links",
    "redaction_plans",
    "redaction_targets",
    "resource_versions",
    "runtime_lineage_state",
    "runtime_source_binding_edges",
    "source_binding_edges",
    "tool_operations",
    "tool_operation_outcomes",
    "resource_snapshots",
    "sink_candidates",
    "information_flow_edge_scopes",
)

_SESSION_ACTIVITY_CTE = """
    fragment_origins(fragment_id, workspace_id, session_id) AS (
        SELECT fragment.fragment_id, event.workspace_id, event.session_id
        FROM artifact_fragments fragment
        JOIN artifacts artifact ON artifact.artifact_id = fragment.artifact_id
        JOIN events event ON event.event_id = artifact.event_id
        WHERE event.session_id IS NOT NULL
    ),
    event_session_latest(workspace_id, session_id, activity_at) AS (
        SELECT workspace_id, session_id, MAX(recorded_at)
        FROM events
        WHERE session_id IS NOT NULL
        GROUP BY workspace_id, session_id
    ),
    session_activity(workspace_id, session_id, activity_at) AS (
        SELECT workspace_id, session_id, recorded_at
        FROM events WHERE session_id IS NOT NULL
        UNION ALL
        SELECT e.workspace_id, e.session_id, a.recorded_at
        FROM artifacts a JOIN events e ON e.event_id = a.event_id
        WHERE e.session_id IS NOT NULL
        UNION ALL
        SELECT e.workspace_id, e.session_id, f.recorded_at
        FROM artifact_fragments f
        JOIN artifacts a ON a.artifact_id = f.artifact_id
        JOIN events e ON e.event_id = a.event_id
        WHERE e.session_id IS NOT NULL
        UNION ALL
        SELECT e.workspace_id, e.session_id, edge.recorded_at
        FROM flow_edges edge
        JOIN artifacts a ON a.artifact_id = edge.dst_artifact_id
        JOIN events e ON e.event_id = a.event_id
        WHERE e.session_id IS NOT NULL
        UNION ALL
        SELECT e.workspace_id, e.session_id, o.recorded_at
        FROM tool_operations o JOIN events e ON e.event_id = o.event_id
        WHERE e.session_id IS NOT NULL
        UNION ALL
        SELECT e.workspace_id, e.session_id, o.recorded_at
        FROM tool_operation_outcomes o JOIN events e ON e.event_id = o.post_event_id
        WHERE e.session_id IS NOT NULL
        UNION ALL
        SELECT origin.workspace_id, origin.session_id, outcome.recorded_at
        FROM tool_operation_outcomes outcome
        JOIN tool_operations operation
          ON operation.operation_id = outcome.operation_id
        JOIN events origin ON origin.event_id = operation.event_id
        WHERE origin.session_id IS NOT NULL
        UNION ALL
        SELECT e.workspace_id, e.session_id, r.recorded_at
        FROM resource_snapshots r JOIN events e ON e.event_id = r.post_event_id
        WHERE e.session_id IS NOT NULL
        UNION ALL
        SELECT origin.workspace_id, origin.session_id, snapshot.recorded_at
        FROM resource_snapshots snapshot
        JOIN tool_operations operation
          ON operation.operation_id = snapshot.operation_id
        JOIN events origin ON origin.event_id = operation.event_id
        WHERE origin.session_id IS NOT NULL
        UNION ALL
        SELECT workspace_id, session_id, started_at
        FROM analysis_runs WHERE session_id IS NOT NULL
        UNION ALL
        SELECT workspace_id, session_id, completed_at
        FROM analysis_runs
        WHERE session_id IS NOT NULL AND completed_at IS NOT NULL
        UNION ALL
        SELECT run.workspace_id, run.session_id, graph.recorded_at
        FROM analysis_run_graphs graph
        JOIN analysis_runs run ON run.analysis_run_id = graph.analysis_run_id
        WHERE run.session_id IS NOT NULL
        UNION ALL
        SELECT run.workspace_id, run.session_id, edge.recorded_at
        FROM analysis_run_flow_edges edge
        JOIN analysis_runs run ON run.analysis_run_id = edge.analysis_run_id
        WHERE run.session_id IS NOT NULL
        UNION ALL
        SELECT run.workspace_id, run.session_id, snapshot.recorded_at
        FROM analysis_run_nodes node
        JOIN analysis_runs run ON run.analysis_run_id = node.analysis_run_id
        JOIN analysis_node_snapshots snapshot
          ON snapshot.workspace_id = node.workspace_id
         AND snapshot.snapshot_hash = node.snapshot_hash
        WHERE run.session_id IS NOT NULL
        UNION ALL
        SELECT run.workspace_id, run.session_id, edge.recorded_at
        FROM source_binding_edges edge
        JOIN analysis_runs run ON run.analysis_run_id = edge.analysis_run_id
        WHERE run.session_id IS NOT NULL
        UNION ALL
        SELECT run.workspace_id, run.session_id, assignment.recorded_at
        FROM lineage_assignments assignment
        JOIN analysis_runs run ON run.analysis_run_id = assignment.analysis_run_id
        WHERE run.session_id IS NOT NULL
        UNION ALL
        SELECT run.workspace_id, run.session_id, decision.created_at
        FROM policy_decisions decision
        JOIN analysis_runs run ON run.analysis_run_id = decision.analysis_run_id
        WHERE run.session_id IS NOT NULL
        UNION ALL
        SELECT workspace_id, session_id, created_at
        FROM redaction_plans
        UNION ALL
        SELECT workspace_id, session_id, rendered_at
        FROM redaction_plans WHERE rendered_at IS NOT NULL
        UNION ALL
        SELECT workspace_id, session_id, confirmed_at
        FROM redaction_plans WHERE confirmed_at IS NOT NULL
        UNION ALL
        SELECT run.workspace_id, run.session_id, plan.created_at
        FROM redaction_plans plan
        JOIN analysis_runs run ON run.analysis_run_id = plan.analysis_run_id
        WHERE run.session_id IS NOT NULL
        UNION ALL
        SELECT run.workspace_id, run.session_id, plan.rendered_at
        FROM redaction_plans plan
        JOIN analysis_runs run ON run.analysis_run_id = plan.analysis_run_id
        WHERE run.session_id IS NOT NULL AND plan.rendered_at IS NOT NULL
        UNION ALL
        SELECT run.workspace_id, run.session_id, plan.confirmed_at
        FROM redaction_plans plan
        JOIN analysis_runs run ON run.analysis_run_id = plan.analysis_run_id
        WHERE run.session_id IS NOT NULL AND plan.confirmed_at IS NOT NULL
        UNION ALL
        SELECT event.workspace_id, event.session_id, plan.created_at
        FROM redaction_plans plan
        JOIN events event
          ON event.event_id = plan.pre_event_id
          OR event.event_id = plan.post_event_id
        WHERE event.session_id IS NOT NULL
        UNION ALL
        SELECT event.workspace_id, event.session_id, plan.rendered_at
        FROM redaction_plans plan
        JOIN events event
          ON event.event_id = plan.pre_event_id
          OR event.event_id = plan.post_event_id
        WHERE event.session_id IS NOT NULL AND plan.rendered_at IS NOT NULL
        UNION ALL
        SELECT event.workspace_id, event.session_id, plan.confirmed_at
        FROM redaction_plans plan
        JOIN events event
          ON event.event_id = plan.pre_event_id
          OR event.event_id = plan.post_event_id
        WHERE event.session_id IS NOT NULL AND plan.confirmed_at IS NOT NULL
        UNION ALL
        SELECT workspace_id, session_id, recorded_at
        FROM resource_versions WHERE session_id IS NOT NULL
        UNION ALL
        SELECT workspace_id, session_id, recorded_at
        FROM sink_candidates WHERE session_id IS NOT NULL
        UNION ALL
        SELECT scope.workspace_id, scope.session_id, edge.recorded_at
        FROM information_flow_edge_scopes scope
        JOIN information_flow_edges edge
          ON edge.workspace_id = scope.workspace_id
         AND edge.edge_id = scope.edge_id
        UNION ALL
        SELECT origin.workspace_id, origin.session_id, edge.recorded_at
        FROM information_flow_edges edge
        JOIN fragment_origins origin
          ON (edge.src_node_kind = 'artifact_fragment'
              AND edge.src_node_id = origin.fragment_id)
          OR (edge.dst_node_kind = 'artifact_fragment'
              AND edge.dst_node_id = origin.fragment_id)
        UNION ALL
        SELECT origin.workspace_id, origin.session_id, snapshot.recorded_at
        FROM analysis_run_nodes node
        JOIN analysis_node_snapshots snapshot
          ON snapshot.workspace_id = node.workspace_id
         AND snapshot.snapshot_hash = node.snapshot_hash
        JOIN fragment_origins origin
          ON node.node_kind = 'artifact_fragment'
         AND node.node_id = origin.fragment_id
        UNION ALL
        SELECT origin.workspace_id, origin.session_id, edge.recorded_at
        FROM analysis_run_flow_edges edge
        JOIN fragment_origins origin
          ON (edge.src_node_kind = 'artifact_fragment'
              AND edge.src_node_id = origin.fragment_id)
          OR (edge.dst_node_kind = 'artifact_fragment'
              AND edge.dst_node_id = origin.fragment_id)
        UNION ALL
        SELECT origin.workspace_id, origin.session_id, edge.recorded_at
        FROM source_binding_edges edge
        JOIN fragment_origins origin
          ON (edge.src_node_kind = 'artifact_fragment'
              AND edge.src_node_id = origin.fragment_id)
          OR (edge.dst_node_kind = 'artifact_fragment'
              AND edge.dst_node_id = origin.fragment_id)
        UNION ALL
        SELECT origin.workspace_id, origin.session_id, assignment.recorded_at
        FROM lineage_assignments assignment
        JOIN fragment_origins origin
          ON (assignment.source_node_kind = 'artifact_fragment'
              AND assignment.source_node_id = origin.fragment_id)
          OR (assignment.node_kind = 'artifact_fragment'
              AND assignment.node_id = origin.fragment_id)
        UNION ALL
        SELECT origin.workspace_id, origin.session_id, decision.created_at
        FROM policy_decisions decision
        JOIN fragment_origins origin
          ON decision.source_node_kind = 'artifact_fragment'
         AND decision.source_node_id = origin.fragment_id
        UNION ALL
        SELECT origin.workspace_id, origin.session_id, plan.created_at
        FROM redaction_targets target
        JOIN redaction_plans plan ON plan.plan_id = target.plan_id
        JOIN fragment_origins origin
          ON target.source_node_kind = 'artifact_fragment'
         AND target.source_node_id = origin.fragment_id
        UNION ALL
        SELECT origin.workspace_id, origin.session_id, latest.activity_at
        FROM runtime_lineage_state state
        JOIN event_session_latest latest
          ON latest.workspace_id = state.workspace_id
         AND latest.session_id = state.session_id
        JOIN fragment_origins origin
          ON (state.source_node_kind = 'artifact_fragment'
              AND state.source_node_id = origin.fragment_id)
          OR (state.node_kind = 'artifact_fragment'
              AND state.node_id = origin.fragment_id)
        UNION ALL
        SELECT origin.workspace_id, origin.session_id, latest.activity_at
        FROM runtime_source_binding_edges edge
        JOIN event_session_latest latest
          ON latest.workspace_id = edge.workspace_id
         AND latest.session_id = edge.session_id
        JOIN fragment_origins origin
          ON (edge.src_node_kind = 'artifact_fragment'
              AND edge.src_node_id = origin.fragment_id)
          OR (edge.dst_node_kind = 'artifact_fragment'
              AND edge.dst_node_id = origin.fragment_id)
        UNION ALL
        SELECT origin.workspace_id, origin.session_id, latest.activity_at
        FROM fragment_exact_index exact_entry
        JOIN event_session_latest latest
          ON latest.workspace_id = exact_entry.workspace_id
         AND latest.session_id = exact_entry.session_id
        JOIN fragment_origins origin
          ON origin.fragment_id = exact_entry.fragment_id
    ),
    session_summary AS (
        SELECT workspace_id, session_id,
               SUM(CASE WHEN phase = 'stop' THEN 1 ELSE 0 END) AS stop_count
        FROM events
        WHERE session_id IS NOT NULL
        GROUP BY workspace_id, session_id
    ),
    pending_sessions AS (
        SELECT workspace_id, session_id
        FROM analysis_runs
        WHERE session_id IS NOT NULL AND completed_at IS NULL
        UNION
        SELECT workspace_id, session_id
        FROM redaction_plans
        WHERE status IN ('eligible', 'rendered')
    ),
    eligible AS (
        SELECT summary.workspace_id, summary.session_id, summary.stop_count,
               MAX(julianday(activity.activity_at)) AS last_activity_jd
        FROM session_summary summary
        JOIN session_activity activity
          ON activity.session_id = summary.session_id
         AND activity.workspace_id IS summary.workspace_id
        WHERE NOT EXISTS (
            SELECT 1 FROM pending_sessions pending
            WHERE pending.session_id = summary.session_id
              AND pending.workspace_id IS summary.workspace_id
        )
        GROUP BY summary.workspace_id, summary.session_id
        HAVING MIN(julianday(activity.activity_at) IS NOT NULL) = 1
           AND MAX(julianday(activity.activity_at)) < julianday(:cutoff)
    ),
    pending_expired AS (
        SELECT summary.workspace_id, summary.session_id
        FROM session_summary summary
        WHERE EXISTS (
            SELECT 1 FROM pending_sessions pending
            WHERE pending.session_id = summary.session_id
              AND pending.workspace_id IS summary.workspace_id
        )
          AND NOT EXISTS (
            SELECT 1 FROM session_activity activity
            WHERE activity.session_id = summary.session_id
              AND activity.workspace_id IS summary.workspace_id
              AND (
                  julianday(activity.activity_at) IS NULL
                  OR julianday(activity.activity_at) >= julianday(:cutoff)
              )
        )
    )
"""

_UNSCOPED_ACTIVITY_CTE = """
    unscoped_activity(event_id, activity_at) AS (
        SELECT event_id, recorded_at FROM events WHERE session_id IS NULL
        UNION ALL
        SELECT e.event_id, a.recorded_at
        FROM artifacts a JOIN events e ON e.event_id = a.event_id
        WHERE e.session_id IS NULL
        UNION ALL
        SELECT e.event_id, f.recorded_at
        FROM artifact_fragments f
        JOIN artifacts a ON a.artifact_id = f.artifact_id
        JOIN events e ON e.event_id = a.event_id
        WHERE e.session_id IS NULL
        UNION ALL
        SELECT e.event_id, edge.recorded_at
        FROM flow_edges edge
        JOIN artifacts a ON a.artifact_id = edge.dst_artifact_id
        JOIN events e ON e.event_id = a.event_id
        WHERE e.session_id IS NULL
        UNION ALL
        SELECT e.event_id, o.recorded_at
        FROM tool_operations o JOIN events e ON e.event_id = o.event_id
        WHERE e.session_id IS NULL
        UNION ALL
        SELECT e.event_id, o.recorded_at
        FROM tool_operation_outcomes o JOIN events e ON e.event_id = o.post_event_id
        WHERE e.session_id IS NULL
        UNION ALL
        SELECT e.event_id, r.recorded_at
        FROM resource_snapshots r JOIN events e ON e.event_id = r.post_event_id
        WHERE e.session_id IS NULL
        UNION ALL
        SELECT e.event_id, plan.created_at
        FROM redaction_plans plan
        JOIN events e
          ON e.event_id = plan.pre_event_id OR e.event_id = plan.post_event_id
        WHERE e.session_id IS NULL
        UNION ALL
        SELECT e.event_id, plan.rendered_at
        FROM redaction_plans plan
        JOIN events e
          ON e.event_id = plan.pre_event_id OR e.event_id = plan.post_event_id
        WHERE e.session_id IS NULL AND plan.rendered_at IS NOT NULL
        UNION ALL
        SELECT e.event_id, plan.confirmed_at
        FROM redaction_plans plan
        JOIN events e
          ON e.event_id = plan.pre_event_id OR e.event_id = plan.post_event_id
        WHERE e.session_id IS NULL AND plan.confirmed_at IS NOT NULL
    ),
    eligible_unscoped AS (
        SELECT event.event_id,
               MAX(julianday(activity.activity_at)) AS last_activity_jd
        FROM events event
        JOIN unscoped_activity activity ON activity.event_id = event.event_id
        WHERE event.session_id IS NULL
          AND NOT EXISTS (
              SELECT 1 FROM redaction_plans plan
              LEFT JOIN analysis_runs run
                ON run.analysis_run_id = plan.analysis_run_id
              WHERE (plan.pre_event_id = event.event_id
                     OR plan.post_event_id = event.event_id)
                AND (
                    plan.status IN ('eligible', 'rendered')
                    OR run.completed_at IS NULL
                )
          )
        GROUP BY event.event_id
        HAVING MIN(julianday(activity.activity_at) IS NOT NULL) = 1
           AND MAX(julianday(activity.activity_at)) < julianday(:cutoff)
    )
"""


class StorageCleanupPlanError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class _RetentionInventory:
    eligible_sessions: tuple[tuple[str | None, str], ...]
    eligible_incomplete_session_count: int
    pending_session_count: int
    eligible_unscoped_event_ids: tuple[str, ...]
    candidate_rows: dict[str, int]
    eligibility_digest: str


@dataclass(frozen=True)
class StorageCategoryUsage:
    allocated_bytes: int | None
    row_count: int

    def to_payload(self) -> dict[str, int | None]:
        return {
            "allocated_bytes": self.allocated_bytes,
            "row_count": self.row_count,
        }


@dataclass(frozen=True)
class StorageCleanupPlan:
    cutoff_at: str
    reviewed_at: str
    database_logical_bytes: int
    database_allocated_bytes: int
    database_free_page_bytes: int
    database_wal_bytes: int
    migration_backup_count: int
    migration_backup_bytes: int
    migration_backup_eligible_count: int
    migration_backup_eligible_bytes: int
    migration_backup_recent_count: int
    migration_backup_awaiting_verification_count: int
    migration_backup_identity_mismatch_count: int
    migration_backup_verification_current: bool
    migration_backup_current_database_integrity_ok: bool
    migration_backup_cleanup_blocked: bool
    categories: dict[str, StorageCategoryUsage]
    eligible_session_count: int
    eligible_incomplete_session_count: int
    pending_session_count: int
    eligible_unscoped_event_count: int
    candidate_rows: dict[str, int]
    estimated_expired_reclaimable_bytes: int | None
    temporary_space_required_bytes: int
    temporary_space_available_bytes: int
    plan_revision: str

    def to_payload(self) -> dict[str, Any]:
        total_managed_bytes = (
            self.database_allocated_bytes
            + self.database_wal_bytes
            + self.migration_backup_bytes
        )
        return {
            "schema_version": STORAGE_CLEANUP_PLAN_SCHEMA_VERSION,
            "status": "review_required",
            "action": "storage_cleanup",
            "retention_days": STORAGE_RETENTION_DAYS,
            "cutoff_at": self.cutoff_at,
            "reviewed_at": self.reviewed_at,
            "thresholds": {
                "warning_bytes": STORAGE_WARNING_BYTES,
                "action_bytes": STORAGE_ACTION_BYTES,
                "recent_records_deleted_for_capacity": False,
            },
            "storage": {
                "total_managed_bytes": total_managed_bytes,
                "database_logical_bytes": self.database_logical_bytes,
                "database_allocated_bytes": self.database_allocated_bytes,
                "database_wal_bytes": self.database_wal_bytes,
                "database_free_page_bytes": self.database_free_page_bytes,
                "migration_backup_count": self.migration_backup_count,
                "migration_backup_bytes": self.migration_backup_bytes,
                "category_byte_measurement_available": all(
                    category.allocated_bytes is not None
                    for category in self.categories.values()
                ),
                "categories": {
                    key: value.to_payload()
                    for key, value in sorted(self.categories.items())
                },
            },
            "migration_backups": {
                "retention_days": 7,
                "eligible_count": self.migration_backup_eligible_count,
                "eligible_bytes": self.migration_backup_eligible_bytes,
                "recent_count": self.migration_backup_recent_count,
                "awaiting_verification_count": (
                    self.migration_backup_awaiting_verification_count
                ),
                "identity_mismatch_count": (
                    self.migration_backup_identity_mismatch_count
                ),
                "verification_current": (
                    self.migration_backup_verification_current
                ),
                "current_database_integrity_ok": (
                    self.migration_backup_current_database_integrity_ok
                ),
                "cleanup_blocked": self.migration_backup_cleanup_blocked,
            },
            "retention_candidates": {
                "eligible_session_count": self.eligible_session_count,
                "eligible_incomplete_session_count": (
                    self.eligible_incomplete_session_count
                ),
                "pending_session_count": self.pending_session_count,
                "eligible_unscoped_event_count": self.eligible_unscoped_event_count,
                "rows": dict(sorted(self.candidate_rows.items())),
                "estimated_reclaimable_bytes": (
                    self.estimated_expired_reclaimable_bytes
                ),
                "estimate_method": (
                    "proportional_owned_pages_v1"
                    if self.estimated_expired_reclaimable_bytes is not None
                    else "unavailable"
                ),
            },
            "compaction": {
                "temporary_space_required_bytes": (
                    self.temporary_space_required_bytes
                ),
                "temporary_space_available_bytes": (
                    self.temporary_space_available_bytes
                ),
                "temporary_space_sufficient": (
                    self.temporary_space_available_bytes
                    >= self.temporary_space_required_bytes
                ),
            },
            "preserved": {
                "records_newer_than_cutoff": True,
                "improvement_feedback": True,
                "workspace_settings": True,
                "protected_source_registrations": True,
                "human_decisions": True,
                "source_files": True,
            },
            "database_changes": 0,
            "source_file_changes": 0,
            "protected_manifest_read": False,
            "network_used": False,
            "review_required": True,
            "plan_revision": self.plan_revision,
        }


@dataclass(frozen=True)
class StorageCleanupApplyResult:
    cutoff_at: str
    deleted_session_count: int
    deleted_incomplete_session_count: int
    deleted_unscoped_event_count: int
    deleted_rows: dict[str, int]
    deleted_migration_backup_count: int
    deleted_migration_backup_bytes: int
    migration_backup_cleanup_status: str
    remaining_session_count: int
    remaining_unscoped_event_count: int
    next_plan_revision: str
    next_reviewed_at: str

    def to_payload(self) -> dict[str, Any]:
        return {
            "schema_version": STORAGE_CLEANUP_PLAN_SCHEMA_VERSION,
            "status": "applied",
            "action": "storage_cleanup",
            "retention_days": STORAGE_RETENTION_DAYS,
            "cutoff_at": self.cutoff_at,
            "deleted": {
                "session_count": self.deleted_session_count,
                "incomplete_session_count": self.deleted_incomplete_session_count,
                "unscoped_event_count": self.deleted_unscoped_event_count,
                "rows": dict(sorted(self.deleted_rows.items())),
            },
            "remaining": {
                "session_count": self.remaining_session_count,
                "unscoped_event_count": self.remaining_unscoped_event_count,
            },
            "migration_backups": {
                "status": self.migration_backup_cleanup_status,
                "deleted_count": self.deleted_migration_backup_count,
                "deleted_bytes": self.deleted_migration_backup_bytes,
            },
            "preserved": {
                "records_newer_than_cutoff": True,
                "improvement_feedback": True,
                "workspace_settings": True,
                "protected_source_registrations": True,
                "human_decisions": True,
                "source_files": True,
            },
            "database_changes": sum(self.deleted_rows.values()),
            "source_file_changes": 0,
            "protected_manifest_read": False,
            "network_used": False,
            "next_plan_revision": self.next_plan_revision,
            "next_reviewed_at": self.next_reviewed_at,
        }


def plan_storage_cleanup(
    db_path: Path,
    *,
    now: datetime | None = None,
    reviewed_at: datetime | None = None,
) -> StorageCleanupPlan:
    requested = Path(os.path.abspath(os.fspath(db_path.expanduser())))
    if requested.is_symlink():
        raise StorageCleanupPlanError("storage_database_symlink")
    try:
        database_stat = requested.stat()
    except OSError as exc:
        raise StorageCleanupPlanError("storage_database_unavailable") from exc
    if not requested.is_file():
        raise StorageCleanupPlanError("storage_database_unavailable")

    observed_now = now or datetime.now(UTC)
    if observed_now.tzinfo is None:
        raise StorageCleanupPlanError("storage_plan_time_timezone_required")
    observed_now = observed_now.astimezone(UTC)
    cutoff = observed_now - timedelta(days=STORAGE_RETENTION_DAYS)
    cutoff_at = cutoff.isoformat(timespec="seconds").replace("+00:00", "Z")

    try:
        with closing(_read_only_connection(requested)) as conn:
            conn.execute("BEGIN")
            schema_version = int(conn.execute("PRAGMA user_version").fetchone()[0])
            if schema_version != CURRENT_SCHEMA_VERSION:
                raise StorageCleanupPlanError("storage_database_schema_incompatible")
            page_size = int(conn.execute("PRAGMA page_size").fetchone()[0])
            page_count = int(conn.execute("PRAGMA page_count").fetchone()[0])
            freelist_count = int(conn.execute("PRAGMA freelist_count").fetchone()[0])
            table_rows = _table_row_counts(conn)
            owner_bytes = _owned_page_bytes(conn)
            categories = _category_usage(owner_bytes, table_rows)
            retention = _retention_candidates(conn, cutoff_at)
            maximum_sequence = int(
                conn.execute(
                    "SELECT COALESCE(MAX(sequence_no), 0) FROM events"
                ).fetchone()[0]
            )
            maximum_recorded_at = str(
                conn.execute(
                    "SELECT COALESCE(MAX(recorded_at), '') FROM events"
                ).fetchone()[0]
            )
    except StorageCleanupPlanError:
        raise
    except sqlite3.Error as exc:
        raise StorageCleanupPlanError("storage_database_read_failed") from exc

    try:
        backup_inventory = inventory_migration_backups(
            requested,
            now=observed_now,
            require_integrity_check=True,
        )
    except MigrationBackupError as exc:
        raise StorageCleanupPlanError(exc.code) from exc
    # Closing any of the read-only SQLite connections above may checkpoint an
    # already committed WAL. Bind the plan to the stable post-close files so
    # that physical housekeeping is not mistaken for a logical change
    # immediately after the plan is returned.
    try:
        database_stat = requested.stat()
    except OSError as exc:
        raise StorageCleanupPlanError("storage_database_unavailable") from exc
    wal_bytes = _regular_file_size(Path(f"{requested}-wal"))
    allocated_bytes = page_size * page_count
    free_page_bytes = page_size * freelist_count
    candidate_rows = retention.candidate_rows
    estimated_reclaimable = _estimate_reclaimable_bytes(
        owner_bytes,
        table_rows,
        candidate_rows,
    )
    temporary_required = (
        database_stat.st_size + wal_bytes + _TEMPORARY_SPACE_MARGIN_BYTES
    )
    try:
        available_bytes = shutil.disk_usage(requested.parent).free
    except OSError as exc:
        raise StorageCleanupPlanError("storage_disk_usage_unavailable") from exc

    reviewed_time = reviewed_at
    if reviewed_time is None:
        reviewed_time = observed_now if now is not None else datetime.now(UTC)
    if reviewed_time.tzinfo is None:
        raise StorageCleanupPlanError("storage_plan_time_timezone_required")
    reviewed_time = reviewed_time.astimezone(UTC)
    reviewed_at_text = reviewed_time.isoformat(timespec="seconds").replace(
        "+00:00", "Z"
    )
    revision = _storage_cleanup_plan_revision(
        database_stat=database_stat,
        schema_version=schema_version,
        page_size=page_size,
        page_count=page_count,
        freelist_count=freelist_count,
        maximum_sequence=maximum_sequence,
        maximum_recorded_at=maximum_recorded_at,
        wal_bytes=wal_bytes,
        backup_inventory=backup_inventory,
        cutoff_at=cutoff_at,
        reviewed_at=reviewed_at_text,
        retention=retention,
    )
    return StorageCleanupPlan(
        cutoff_at=cutoff_at,
        reviewed_at=reviewed_at_text,
        database_logical_bytes=database_stat.st_size,
        database_allocated_bytes=allocated_bytes,
        database_free_page_bytes=free_page_bytes,
        database_wal_bytes=wal_bytes,
        migration_backup_count=backup_inventory.total_count,
        migration_backup_bytes=backup_inventory.total_bytes,
        migration_backup_eligible_count=backup_inventory.eligible_count,
        migration_backup_eligible_bytes=backup_inventory.eligible_bytes,
        migration_backup_recent_count=backup_inventory.recent_count,
        migration_backup_awaiting_verification_count=(
            backup_inventory.awaiting_verification_count
        ),
        migration_backup_identity_mismatch_count=(
            backup_inventory.identity_mismatch_count
        ),
        migration_backup_verification_current=(
            backup_inventory.verification_current
        ),
        migration_backup_current_database_integrity_ok=(
            backup_inventory.current_database_integrity_ok
        ),
        migration_backup_cleanup_blocked=backup_inventory.cleanup_blocked,
        categories=categories,
        eligible_session_count=len(retention.eligible_sessions),
        eligible_incomplete_session_count=(
            retention.eligible_incomplete_session_count
        ),
        pending_session_count=retention.pending_session_count,
        eligible_unscoped_event_count=len(retention.eligible_unscoped_event_ids),
        candidate_rows=candidate_rows,
        estimated_expired_reclaimable_bytes=estimated_reclaimable,
        temporary_space_required_bytes=temporary_required,
        temporary_space_available_bytes=available_bytes,
        plan_revision=revision,
    )


def apply_storage_cleanup(
    db_path: Path,
    *,
    cutoff_at: str,
    reviewed_at: str,
    expected_plan_revision: str,
    batch_size: int = STORAGE_CLEANUP_DEFAULT_BATCH_SIZE,
    cancel_check: Callable[[], bool] | None = None,
) -> StorageCleanupApplyResult:
    if type(batch_size) is not int or not 1 <= batch_size <= STORAGE_CLEANUP_MAX_BATCH_SIZE:
        raise StorageCleanupPlanError("storage_cleanup_batch_size_invalid")
    if re.fullmatch(r"sc4_[0-9a-f]{64}", expected_plan_revision) is None:
        raise StorageCleanupPlanError("storage_plan_revision_invalid")
    cutoff = _parse_cleanup_cutoff(cutoff_at)
    reviewed = _parse_cleanup_cutoff(reviewed_at)
    plan_time = cutoff + timedelta(days=STORAGE_RETENTION_DAYS)
    initial_plan = plan_storage_cleanup(
        db_path,
        now=plan_time,
        reviewed_at=reviewed,
    )
    if initial_plan.plan_revision != expected_plan_revision:
        raise StorageCleanupPlanError("storage_plan_changed")

    requested = Path(os.path.abspath(os.fspath(db_path.expanduser())))
    try:
        with closing(_write_connection(requested)) as connection, connection as conn:
            if cancel_check is not None:
                conn.set_progress_handler(lambda: int(cancel_check()), 1000)
            _create_cleanup_temp_tables(conn)
            conn.execute("BEGIN IMMEDIATE")
            inventory = _retention_candidates(conn, cutoff_at)
            try:
                backup_inventory = inventory_migration_backups(
                    requested,
                    now=plan_time,
                    require_integrity_check=True,
                )
            except MigrationBackupError as exc:
                raise StorageCleanupPlanError(exc.code) from exc
            locked_revision = _locked_cleanup_plan_revision(
                requested,
                conn,
                cutoff_at=cutoff_at,
                reviewed_at=reviewed_at,
                retention=inventory,
                backup_inventory=backup_inventory,
            )
            if locked_revision != expected_plan_revision:
                raise StorageCleanupPlanError("storage_plan_changed")
            selected_sessions = inventory.eligible_sessions[:batch_size]
            remaining_slots = batch_size - len(selected_sessions)
            selected_unscoped = inventory.eligible_unscoped_event_ids[:remaining_slots]
            _prepare_cleanup_targets(
                conn,
                selected_sessions=selected_sessions,
                selected_unscoped_event_ids=selected_unscoped,
            )
            deleted_incomplete = int(
                conn.execute(
                    """
                    SELECT COUNT(*)
                    FROM cleanup_sessions selected
                    WHERE NOT EXISTS (
                        SELECT 1 FROM events event
                        WHERE event.session_id = selected.session_id
                          AND event.workspace_id IS selected.workspace_id
                          AND event.phase = 'stop'
                    )
                    """
                ).fetchone()[0]
            )
            deleted_rows = _delete_cleanup_targets(conn)
            foreign_key_problem = conn.execute("PRAGMA foreign_key_check").fetchone()
            if foreign_key_problem is not None:
                raise StorageCleanupPlanError("storage_cleanup_foreign_key_failed")
            quick_check = conn.execute("PRAGMA quick_check").fetchone()
            if quick_check is None or quick_check[0] != "ok":
                raise StorageCleanupPlanError("storage_cleanup_integrity_failed")
    except StorageCleanupPlanError:
        raise
    except sqlite3.Error as exc:
        raise StorageCleanupPlanError("storage_cleanup_write_failed") from exc

    deleted_backup_count = 0
    deleted_backup_bytes = 0
    backup_cleanup_status = (
        "blocked" if backup_inventory.cleanup_blocked else "nothing_to_delete"
    )
    if backup_inventory.eligible_count:
        try:
            deletion = delete_verified_migration_backups(
                requested,
                now=plan_time,
                expected_inventory_digest=backup_inventory.inventory_digest,
                limit=STORAGE_CLEANUP_DEFAULT_BATCH_SIZE,
                cancel_check=cancel_check,
            )
        except MigrationBackupError as exc:
            if exc.code == "migration_backup_cleanup_cancelled":
                raise StorageCleanupPlanError(exc.code) from exc
            backup_cleanup_status = "skipped_safely"
        else:
            deleted_backup_count = deletion.deleted_count
            deleted_backup_bytes = deletion.deleted_bytes
            backup_cleanup_status = (
                "applied"
                if deletion.completed
                else "partially_applied_safe_to_resume"
            )

    next_plan = plan_storage_cleanup(
        requested,
        now=plan_time,
        reviewed_at=datetime.now(UTC),
    )
    return StorageCleanupApplyResult(
        cutoff_at=cutoff_at,
        deleted_session_count=len(selected_sessions),
        deleted_incomplete_session_count=deleted_incomplete,
        deleted_unscoped_event_count=len(selected_unscoped),
        deleted_rows=deleted_rows,
        deleted_migration_backup_count=deleted_backup_count,
        deleted_migration_backup_bytes=deleted_backup_bytes,
        migration_backup_cleanup_status=backup_cleanup_status,
        remaining_session_count=next_plan.eligible_session_count,
        remaining_unscoped_event_count=next_plan.eligible_unscoped_event_count,
        next_plan_revision=next_plan.plan_revision,
        next_reviewed_at=next_plan.reviewed_at,
    )


def _locked_cleanup_plan_revision(
    path: Path,
    conn: sqlite3.Connection,
    *,
    cutoff_at: str,
    reviewed_at: str,
    retention: _RetentionInventory,
    backup_inventory: MigrationBackupInventory,
) -> str:
    database_stat = path.stat()
    schema_version = int(conn.execute("PRAGMA user_version").fetchone()[0])
    page_size = int(conn.execute("PRAGMA page_size").fetchone()[0])
    page_count = int(conn.execute("PRAGMA page_count").fetchone()[0])
    freelist_count = int(conn.execute("PRAGMA freelist_count").fetchone()[0])
    maximum_sequence = int(
        conn.execute("SELECT COALESCE(MAX(sequence_no), 0) FROM events").fetchone()[0]
    )
    maximum_recorded_at = str(
        conn.execute("SELECT COALESCE(MAX(recorded_at), '') FROM events").fetchone()[0]
    )
    wal_bytes = _regular_file_size(Path(f"{path}-wal"))
    return _storage_cleanup_plan_revision(
        database_stat=database_stat,
        schema_version=schema_version,
        page_size=page_size,
        page_count=page_count,
        freelist_count=freelist_count,
        maximum_sequence=maximum_sequence,
        maximum_recorded_at=maximum_recorded_at,
        wal_bytes=wal_bytes,
        backup_inventory=backup_inventory,
        cutoff_at=cutoff_at,
        reviewed_at=reviewed_at,
        retention=retention,
    )


def _storage_cleanup_plan_revision(
    *,
    database_stat: os.stat_result,
    schema_version: int,
    page_size: int,
    page_count: int,
    freelist_count: int,
    maximum_sequence: int,
    maximum_recorded_at: str,
    wal_bytes: int,
    backup_inventory: MigrationBackupInventory,
    cutoff_at: str,
    reviewed_at: str,
    retention: _RetentionInventory,
) -> str:
    commitment = {
        "schema_version": STORAGE_CLEANUP_PLAN_SCHEMA_VERSION,
        "database": {
            "device": database_stat.st_dev,
            "inode": database_stat.st_ino,
            "size": database_stat.st_size,
            "mtime_ns": database_stat.st_mtime_ns,
            "schema_version": schema_version,
            "page_size": page_size,
            "page_count": page_count,
            "freelist_count": freelist_count,
            "maximum_sequence": maximum_sequence,
            "maximum_recorded_at": maximum_recorded_at,
            "wal_bytes": wal_bytes,
        },
        "retention_days": STORAGE_RETENTION_DAYS,
        "cutoff_at": cutoff_at,
        "reviewed_at": reviewed_at,
        "eligible_session_count": len(retention.eligible_sessions),
        "eligible_incomplete_session_count": (
            retention.eligible_incomplete_session_count
        ),
        "pending_session_count": retention.pending_session_count,
        "eligible_unscoped_event_count": len(retention.eligible_unscoped_event_ids),
        "eligibility_digest": retention.eligibility_digest,
        "candidate_rows": retention.candidate_rows,
        "migration_backups": {
            "total_count": backup_inventory.total_count,
            "total_bytes": backup_inventory.total_bytes,
            "eligible_count": backup_inventory.eligible_count,
            "eligible_bytes": backup_inventory.eligible_bytes,
            "recent_count": backup_inventory.recent_count,
            "awaiting_verification_count": (
                backup_inventory.awaiting_verification_count
            ),
            "identity_mismatch_count": backup_inventory.identity_mismatch_count,
            "verification_current": backup_inventory.verification_current,
            "current_database_integrity_ok": (
                backup_inventory.current_database_integrity_ok
            ),
            "cleanup_blocked": backup_inventory.cleanup_blocked,
            "inventory_digest": backup_inventory.inventory_digest,
        },
    }
    return "sc4_" + hashlib.sha256(
        json.dumps(
            commitment,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def _parse_cleanup_cutoff(value: str) -> datetime:
    if not isinstance(value, str) or re.fullmatch(
        r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z",
        value,
    ) is None:
        raise StorageCleanupPlanError("storage_cutoff_invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise StorageCleanupPlanError("storage_cutoff_invalid") from exc
    return parsed.astimezone(UTC)


def validate_storage_cleanup_review(
    *,
    cutoff_at: str,
    reviewed_at: str,
    now: datetime | None = None,
) -> datetime:
    """Require five usable minutes after a cleanup plan finished rendering."""

    cutoff = _parse_cleanup_cutoff(cutoff_at)
    reviewed = _parse_cleanup_cutoff(reviewed_at)
    plan_started = cutoff + timedelta(days=STORAGE_RETENTION_DAYS)
    observed = now or datetime.now(UTC)
    if observed.tzinfo is None:
        raise StorageCleanupPlanError("storage_plan_time_timezone_required")
    observed = observed.astimezone(UTC)
    if reviewed < plan_started or reviewed > observed:
        raise StorageCleanupPlanError("storage_plan_review_time_invalid")
    if observed - reviewed > STORAGE_CLEANUP_REVIEW_WINDOW:
        raise StorageCleanupPlanError("storage_plan_expired")
    return reviewed


def _write_connection(path: Path) -> sqlite3.Connection:
    if path.is_symlink() or not path.is_file():
        raise StorageCleanupPlanError("storage_database_unavailable")
    conn = sqlite3.connect(
        f"{path.resolve(strict=True).as_uri()}?mode=rw",
        uri=True,
        timeout=1.0,
    )
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 1000")
    return conn


def _prepare_cleanup_targets(
    conn: sqlite3.Connection,
    *,
    selected_sessions: tuple[tuple[str | None, str], ...],
    selected_unscoped_event_ids: tuple[str, ...],
) -> None:
    conn.executemany(
        """
        INSERT INTO cleanup_sessions (selection_order, workspace_id, session_id)
        VALUES (?, ?, ?)
        """,
        (
            (index, workspace_id, session_id)
            for index, (workspace_id, session_id) in enumerate(selected_sessions)
        ),
    )
    conn.executemany(
        "INSERT INTO cleanup_events (event_id) VALUES (?)",
        ((event_id,) for event_id in selected_unscoped_event_ids),
    )
    conn.execute(
        """
        INSERT OR IGNORE INTO cleanup_events (event_id)
        SELECT event.event_id
        FROM events event
        JOIN cleanup_sessions selected
          ON selected.session_id = event.session_id
         AND selected.workspace_id IS event.workspace_id
        """
    )
    conn.execute(
        """
        INSERT INTO cleanup_artifacts (artifact_id)
        SELECT artifact.artifact_id
        FROM artifacts artifact
        JOIN cleanup_events event ON event.event_id = artifact.event_id
        """
    )
    conn.execute(
        """
        INSERT INTO cleanup_fragments (fragment_id)
        SELECT fragment.fragment_id
        FROM artifact_fragments fragment
        JOIN cleanup_artifacts artifact
          ON artifact.artifact_id = fragment.artifact_id
        """
    )
    conn.execute(
        """
        INSERT INTO cleanup_operations (operation_id)
        SELECT operation.operation_id
        FROM tool_operations operation
        JOIN cleanup_events event ON event.event_id = operation.event_id
        """
    )
    conn.execute(
        """
        INSERT INTO cleanup_analysis_runs (analysis_run_id)
        SELECT run.analysis_run_id
        FROM analysis_runs run
        JOIN cleanup_sessions selected
          ON selected.session_id = run.session_id
         AND selected.workspace_id IS run.workspace_id
        """
    )
    conn.execute(
        """
        INSERT OR IGNORE INTO cleanup_redaction_plans (plan_id)
        SELECT plan.plan_id
        FROM redaction_plans plan
        WHERE EXISTS (
            SELECT 1 FROM cleanup_sessions selected
            WHERE selected.session_id = plan.session_id
              AND selected.workspace_id IS plan.workspace_id
        ) OR plan.pre_event_id IN (SELECT event_id FROM cleanup_events)
          OR plan.post_event_id IN (SELECT event_id FROM cleanup_events)
          OR plan.analysis_run_id IN (
              SELECT analysis_run_id FROM cleanup_analysis_runs
          )
        """
    )
    conn.execute(
        """
        INSERT OR IGNORE INTO cleanup_analysis_runs (analysis_run_id)
        SELECT plan.analysis_run_id
        FROM redaction_plans plan
        JOIN cleanup_redaction_plans selected ON selected.plan_id = plan.plan_id
        """
    )
    dependency_conflict = conn.execute(
        """
        SELECT 1 FROM redaction_plans plan
        WHERE plan.analysis_run_id IN (
            SELECT analysis_run_id FROM cleanup_analysis_runs
        )
          AND plan.plan_id NOT IN (SELECT plan_id FROM cleanup_redaction_plans)
        LIMIT 1
        """
    ).fetchone()
    if dependency_conflict is not None:
        raise StorageCleanupPlanError("storage_cleanup_dependency_conflict")
    conn.execute(
        """
        INSERT INTO cleanup_scoped_edges (workspace_id, edge_id)
        SELECT DISTINCT scope.workspace_id, scope.edge_id
        FROM information_flow_edge_scopes scope
        JOIN cleanup_sessions selected
          ON selected.workspace_id = scope.workspace_id
         AND selected.session_id = scope.session_id
        """
    )
    conn.execute(
        """
        INSERT INTO cleanup_content_hashes (text_hash)
        SELECT artifact.text_hash FROM artifacts artifact
        JOIN cleanup_artifacts selected ON selected.artifact_id = artifact.artifact_id
        UNION
        SELECT fragment.text_hash FROM artifact_fragments fragment
        JOIN cleanup_fragments selected ON selected.fragment_id = fragment.fragment_id
        """
    )
    conn.execute(
        """
        INSERT INTO cleanup_snapshot_keys (workspace_id, snapshot_hash)
        SELECT DISTINCT node.workspace_id, node.snapshot_hash
        FROM analysis_run_nodes node
        JOIN cleanup_analysis_runs run ON run.analysis_run_id = node.analysis_run_id
        """
    )


def _create_cleanup_temp_tables(conn: sqlite3.Connection) -> None:
    statements = (
        """CREATE TEMP TABLE cleanup_sessions (
            selection_order INTEGER PRIMARY KEY,
            workspace_id TEXT,
            session_id TEXT NOT NULL
        )""",
        "CREATE TEMP TABLE cleanup_events (event_id TEXT PRIMARY KEY) WITHOUT ROWID",
        "CREATE TEMP TABLE cleanup_artifacts (artifact_id TEXT PRIMARY KEY) WITHOUT ROWID",
        "CREATE TEMP TABLE cleanup_fragments (fragment_id TEXT PRIMARY KEY) WITHOUT ROWID",
        "CREATE TEMP TABLE cleanup_operations (operation_id TEXT PRIMARY KEY) WITHOUT ROWID",
        """CREATE TEMP TABLE cleanup_analysis_runs (
            analysis_run_id TEXT PRIMARY KEY
        ) WITHOUT ROWID""",
        "CREATE TEMP TABLE cleanup_redaction_plans (plan_id TEXT PRIMARY KEY) WITHOUT ROWID",
        """CREATE TEMP TABLE cleanup_scoped_edges (
            workspace_id TEXT NOT NULL,
            edge_id TEXT NOT NULL,
            PRIMARY KEY (workspace_id, edge_id)
        ) WITHOUT ROWID""",
        """CREATE TEMP TABLE cleanup_content_hashes (
            text_hash TEXT PRIMARY KEY
        ) WITHOUT ROWID""",
        """CREATE TEMP TABLE cleanup_snapshot_keys (
            workspace_id TEXT NOT NULL,
            snapshot_hash TEXT NOT NULL,
            PRIMARY KEY (workspace_id, snapshot_hash)
        ) WITHOUT ROWID""",
    )
    for statement in statements:
        conn.execute(statement)


def _delete_cleanup_targets(conn: sqlite3.Connection) -> dict[str, int]:
    deleted: dict[str, int] = {}

    def remove(table: str, predicate: str) -> None:
        if re.fullmatch(r"[a-z0-9_]+", table) is None:
            raise StorageCleanupPlanError("storage_table_name_invalid")
        cursor = conn.execute(f'DELETE FROM "{table}" WHERE {predicate}')
        deleted[table] = deleted.get(table, 0) + max(cursor.rowcount, 0)

    remove(
        "redaction_decision_links",
        "enforce_plan_id IN (SELECT plan_id FROM cleanup_redaction_plans) "
        "OR preview_plan_id IN (SELECT plan_id FROM cleanup_redaction_plans)",
    )
    remove("redaction_targets", "plan_id IN (SELECT plan_id FROM cleanup_redaction_plans)")
    remove("redaction_plans", "plan_id IN (SELECT plan_id FROM cleanup_redaction_plans)")
    for table in ("policy_decisions", "source_binding_edges", "lineage_assignments"):
        remove(
            table,
            "analysis_run_id IN (SELECT analysis_run_id FROM cleanup_analysis_runs)",
        )
    remove(
        "analysis_run_flow_edges",
        "analysis_run_id IN (SELECT analysis_run_id FROM cleanup_analysis_runs)",
    )
    remove(
        "analysis_run_nodes",
        "analysis_run_id IN (SELECT analysis_run_id FROM cleanup_analysis_runs)",
    )
    remove(
        "analysis_run_graphs",
        "analysis_run_id IN (SELECT analysis_run_id FROM cleanup_analysis_runs)",
    )
    remove(
        "analysis_runs",
        "analysis_run_id IN (SELECT analysis_run_id FROM cleanup_analysis_runs)",
    )
    remove(
        "analysis_node_snapshots",
        "EXISTS (SELECT 1 FROM cleanup_snapshot_keys selected "
        "WHERE selected.workspace_id = analysis_node_snapshots.workspace_id "
        "AND selected.snapshot_hash = analysis_node_snapshots.snapshot_hash) "
        "AND NOT EXISTS (SELECT 1 FROM analysis_run_nodes node "
        "WHERE node.workspace_id = analysis_node_snapshots.workspace_id "
        "AND node.snapshot_hash = analysis_node_snapshots.snapshot_hash)",
    )
    remove(
        "resource_snapshots",
        "post_event_id IN (SELECT event_id FROM cleanup_events) "
        "OR operation_id IN (SELECT operation_id FROM cleanup_operations)",
    )
    remove(
        "tool_operation_outcomes",
        "post_event_id IN (SELECT event_id FROM cleanup_events) "
        "OR operation_id IN (SELECT operation_id FROM cleanup_operations)",
    )
    remove("tool_operations", "operation_id IN (SELECT operation_id FROM cleanup_operations)")
    remove("flow_edges", "dst_artifact_id IN (SELECT artifact_id FROM cleanup_artifacts)")
    remove("event_payload_metadata", "event_id IN (SELECT event_id FROM cleanup_events)")

    remove(
        "information_flow_edge_scopes",
        "EXISTS (SELECT 1 FROM cleanup_sessions selected "
        "WHERE selected.workspace_id = information_flow_edge_scopes.workspace_id "
        "AND selected.session_id = information_flow_edge_scopes.session_id)",
    )
    remove(
        "information_flow_edges",
        "EXISTS (SELECT 1 FROM cleanup_scoped_edges selected "
        "WHERE selected.workspace_id = information_flow_edges.workspace_id "
        "AND selected.edge_id = information_flow_edges.edge_id) "
        "AND NOT EXISTS (SELECT 1 FROM information_flow_edge_scopes scope "
        "WHERE scope.workspace_id = information_flow_edges.workspace_id "
        "AND scope.edge_id = information_flow_edges.edge_id)",
    )
    session_predicate = (
        "EXISTS (SELECT 1 FROM cleanup_sessions selected "
        "WHERE selected.workspace_id = {table}.workspace_id "
        "AND selected.session_id = {table}.session_id)"
    )
    remove(
        "runtime_lineage_state",
        session_predicate.format(table="runtime_lineage_state"),
    )
    remove(
        "runtime_source_binding_edges",
        session_predicate.format(table="runtime_source_binding_edges"),
    )
    remove("analysis_cursors", session_predicate.format(table="analysis_cursors"))
    remove(
        "resource_versions",
        session_predicate.format(table="resource_versions"),
    )
    remove(
        "sink_candidates",
        session_predicate.format(table="sink_candidates"),
    )
    remove(
        "fragment_exact_index",
        session_predicate.format(table="fragment_exact_index"),
    )
    remove("artifact_fragments", "fragment_id IN (SELECT fragment_id FROM cleanup_fragments)")
    remove("artifacts", "artifact_id IN (SELECT artifact_id FROM cleanup_artifacts)")
    remove("events", "event_id IN (SELECT event_id FROM cleanup_events)")
    remove(
        "content_similarity_features",
        "text_hash IN (SELECT text_hash FROM cleanup_content_hashes) "
        "AND NOT EXISTS (SELECT 1 FROM artifact_fragments fragment "
        "JOIN fragment_exact_index exact_entry "
        "ON exact_entry.fragment_id = fragment.fragment_id "
        "WHERE fragment.text_hash = content_similarity_features.text_hash)",
    )
    remove(
        "artifact_contents",
        "text_hash IN (SELECT text_hash FROM cleanup_content_hashes) "
        "AND NOT EXISTS (SELECT 1 FROM artifacts artifact "
        "WHERE artifact.text_hash = artifact_contents.text_hash) "
        "AND NOT EXISTS (SELECT 1 FROM artifact_fragments fragment "
        "WHERE fragment.text_hash = artifact_contents.text_hash)",
    )
    return deleted


def _read_only_connection(path: Path) -> sqlite3.Connection:
    uri = f"{path.resolve(strict=True).as_uri()}?mode=ro"
    conn = sqlite3.connect(uri, uri=True, timeout=1.0)
    conn.execute("PRAGMA query_only = ON")
    return conn


def _table_row_counts(conn: sqlite3.Connection) -> dict[str, int]:
    existing = [
        str(row[0])
        for row in conn.execute(
            """
            SELECT name FROM sqlite_master
            WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
            ORDER BY name
            """
        )
    ]
    counts: dict[str, int] = {}
    for table in existing:
        if re.fullmatch(r"[a-z0-9_]+", table) is None:
            raise StorageCleanupPlanError("storage_table_name_invalid")
        counts[table] = int(
            conn.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0]
        )
    return counts


def _owned_page_bytes(conn: sqlite3.Connection) -> dict[str, int] | None:
    index_owners = {
        str(row[0]): str(row[1])
        for row in conn.execute(
            """
            SELECT name, tbl_name
            FROM sqlite_master
            WHERE type IN ('table', 'index') AND name IS NOT NULL
            """
        )
    }
    owned: dict[str, int] = {}
    try:
        rows = conn.execute(
            "SELECT name, pgsize FROM dbstat WHERE aggregate = TRUE"
        ).fetchall()
    except sqlite3.Error:
        return None
    for object_name, size in rows:
        owner = index_owners.get(str(object_name), str(object_name))
        owned[owner] = owned.get(owner, 0) + int(size)
    return owned


def _category_usage(
    owner_bytes: dict[str, int] | None,
    table_rows: dict[str, int],
) -> dict[str, StorageCategoryUsage]:
    totals: dict[str, list[int]] = {
        "detailed_operation_records": [0, 0],
        "rebuildable_detection_data": [0, 0],
        "improvement_feedback": [0, 0],
        "durable_configuration": [0, 0],
        "other": [0, 0],
    }
    tables = set(table_rows)
    if owner_bytes is not None:
        tables.update(owner_bytes)
    for table in tables:
        byte_count = 0 if owner_bytes is None else owner_bytes.get(table, 0)
        if table in _IMPROVEMENT_FEEDBACK_TABLES:
            category = "improvement_feedback"
        elif table in _DURABLE_CONFIGURATION_TABLES:
            category = "durable_configuration"
        elif table in _REBUILDABLE_DETECTION_TABLES:
            category = "rebuildable_detection_data"
        elif table == "sqlite_schema" or table.startswith("sqlite_"):
            category = "other"
        else:
            category = "detailed_operation_records"
        totals[category][0] += byte_count
        totals[category][1] += table_rows.get(table, 0)
    return {
        category: StorageCategoryUsage(
            values[0] if owner_bytes is not None else None,
            values[1],
        )
        for category, values in totals.items()
    }


def _retention_candidates(
    conn: sqlite3.Connection,
    cutoff_at: str,
) -> _RetentionInventory:
    eligible_cte = "WITH " + _SESSION_ACTIVITY_CTE + "," + _UNSCOPED_ACTIVITY_CTE
    session_rows = conn.execute(
        eligible_cte
        + """
        SELECT workspace_id, session_id, stop_count
        FROM eligible
        ORDER BY last_activity_jd, COALESCE(workspace_id, ''), session_id
        """,
        {"cutoff": cutoff_at},
    ).fetchall()
    eligible_sessions = tuple((row[0], str(row[1])) for row in session_rows)
    incomplete_count = sum(int(row[2]) == 0 for row in session_rows)
    pending_count = int(
        conn.execute(
            eligible_cte + "SELECT COUNT(*) FROM pending_expired",
            {"cutoff": cutoff_at},
        ).fetchone()[0]
    )
    eligible_unscoped_event_ids = tuple(
        str(row[0])
        for row in conn.execute(
            eligible_cte
            + """
            SELECT event_id FROM eligible_unscoped
            ORDER BY last_activity_jd, event_id
            """,
            {"cutoff": cutoff_at},
        ).fetchall()
    )
    event_filter = """
        (e.session_id IS NULL AND EXISTS (
            SELECT 1 FROM eligible_unscoped u WHERE u.event_id = e.event_id
        )) OR EXISTS (
            SELECT 1 FROM eligible x
            WHERE x.session_id = e.session_id
              AND x.workspace_id IS e.workspace_id
        )
    """
    run_filter = """
        EXISTS (
            SELECT 1 FROM eligible x
            WHERE x.session_id = run.session_id
              AND x.workspace_id IS run.workspace_id
        )
    """
    plan_filter = """
        EXISTS (
            SELECT 1 FROM eligible x
            WHERE x.session_id = plan.session_id
              AND x.workspace_id IS plan.workspace_id
        ) OR EXISTS (
            SELECT 1 FROM eligible_unscoped u
            WHERE u.event_id = plan.pre_event_id
               OR u.event_id = plan.post_event_id
        )
    """
    queries = {
        "analysis_cursors": """
            SELECT COUNT(*) FROM analysis_cursors cursor
            WHERE EXISTS (
                SELECT 1 FROM eligible x
                WHERE x.session_id = cursor.session_id
                  AND x.workspace_id = cursor.workspace_id
            )
        """,
        "analysis_run_flow_edges": f"""
            SELECT COUNT(*) FROM analysis_run_flow_edges edge
            JOIN analysis_runs run ON run.analysis_run_id = edge.analysis_run_id
            WHERE {run_filter}
        """,
        "analysis_run_graphs": f"""
            SELECT COUNT(*) FROM analysis_run_graphs graph
            JOIN analysis_runs run ON run.analysis_run_id = graph.analysis_run_id
            WHERE {run_filter}
        """,
        "analysis_run_nodes": f"""
            SELECT COUNT(*) FROM analysis_run_nodes node
            JOIN analysis_runs run ON run.analysis_run_id = node.analysis_run_id
            WHERE {run_filter}
        """,
        "analysis_runs": f"""
            SELECT COUNT(*) FROM analysis_runs run WHERE {run_filter}
        """,
        "analysis_node_snapshots": f"""
            SELECT COUNT(*) FROM analysis_node_snapshots snapshot
            WHERE EXISTS (
                SELECT 1 FROM analysis_run_nodes node
                JOIN analysis_runs run ON run.analysis_run_id = node.analysis_run_id
                WHERE node.workspace_id = snapshot.workspace_id
                  AND node.snapshot_hash = snapshot.snapshot_hash
                  AND {run_filter}
            )
              AND NOT EXISTS (
                SELECT 1 FROM analysis_run_nodes node
                JOIN analysis_runs run ON run.analysis_run_id = node.analysis_run_id
                WHERE node.workspace_id = snapshot.workspace_id
                  AND node.snapshot_hash = snapshot.snapshot_hash
                  AND NOT ({run_filter})
            )
        """,
        "artifact_contents": """
            SELECT COUNT(*) FROM artifact_contents content
            WHERE (
                EXISTS (
                    SELECT 1 FROM artifacts artifact
                    JOIN events e ON e.event_id = artifact.event_id
                    WHERE artifact.text_hash = content.text_hash
                      AND (""" + event_filter + """
                      )
                ) OR EXISTS (
                    SELECT 1 FROM artifact_fragments fragment
                    JOIN artifacts artifact
                      ON artifact.artifact_id = fragment.artifact_id
                    JOIN events e ON e.event_id = artifact.event_id
                    WHERE fragment.text_hash = content.text_hash
                      AND (""" + event_filter + """
                      )
                )
            )
              AND NOT EXISTS (
                  SELECT 1 FROM artifacts artifact
                  JOIN events e ON e.event_id = artifact.event_id
                  WHERE artifact.text_hash = content.text_hash
                    AND NOT (""" + event_filter + """
                    )
              )
              AND NOT EXISTS (
                  SELECT 1 FROM artifact_fragments fragment
                  JOIN artifacts artifact
                    ON artifact.artifact_id = fragment.artifact_id
                  JOIN events e ON e.event_id = artifact.event_id
                  WHERE fragment.text_hash = content.text_hash
                    AND NOT (""" + event_filter + """
                    )
              )
        """,
        "events": "SELECT COUNT(*) FROM events e WHERE " + event_filter,
        "event_payload_metadata": """
            SELECT COUNT(*) FROM event_payload_metadata metadata
            JOIN events e ON e.event_id = metadata.event_id
            WHERE """ + event_filter,
        "artifacts": """
            SELECT COUNT(*) FROM artifacts a JOIN events e ON e.event_id = a.event_id
            WHERE """ + event_filter,
        "artifact_fragments": """
            SELECT COUNT(*) FROM artifact_fragments f
            JOIN artifacts a ON a.artifact_id = f.artifact_id
            JOIN events e ON e.event_id = a.event_id
            WHERE """ + event_filter,
        "content_similarity_features": """
            SELECT COUNT(*) FROM content_similarity_features feature
            WHERE EXISTS (
                SELECT 1 FROM artifact_fragments fragment
                JOIN fragment_exact_index exact_entry
                  ON exact_entry.fragment_id = fragment.fragment_id
                JOIN eligible x
                  ON x.workspace_id = exact_entry.workspace_id
                 AND x.session_id = exact_entry.session_id
                WHERE fragment.text_hash = feature.text_hash
            )
              AND NOT EXISTS (
                  SELECT 1 FROM artifact_fragments fragment
                  JOIN fragment_exact_index exact_entry
                    ON exact_entry.fragment_id = fragment.fragment_id
                  WHERE fragment.text_hash = feature.text_hash
                    AND NOT EXISTS (
                        SELECT 1 FROM eligible x
                        WHERE x.workspace_id = exact_entry.workspace_id
                          AND x.session_id = exact_entry.session_id
                    )
              )
        """,
        "flow_edges": """
            SELECT COUNT(*) FROM flow_edges edge
            JOIN artifacts a ON a.artifact_id = edge.dst_artifact_id
            JOIN events e ON e.event_id = a.event_id
            WHERE """ + event_filter,
        "fragment_exact_index": """
            SELECT COUNT(*) FROM fragment_exact_index exact_entry
            WHERE EXISTS (
                SELECT 1 FROM eligible x
                WHERE x.session_id = exact_entry.session_id
                  AND x.workspace_id = exact_entry.workspace_id
            )
        """,
        "information_flow_edges": """
            SELECT COUNT(*) FROM information_flow_edges edge
            WHERE EXISTS (
                SELECT 1 FROM information_flow_edge_scopes scope
                JOIN eligible x
                  ON x.workspace_id = scope.workspace_id
                 AND x.session_id = scope.session_id
                WHERE scope.workspace_id = edge.workspace_id
                  AND scope.edge_id = edge.edge_id
            )
              AND NOT EXISTS (
                SELECT 1 FROM information_flow_edge_scopes scope
                WHERE scope.workspace_id = edge.workspace_id
                  AND scope.edge_id = edge.edge_id
                  AND NOT EXISTS (
                      SELECT 1 FROM eligible x
                      WHERE x.workspace_id = scope.workspace_id
                        AND x.session_id = scope.session_id
                  )
            )
        """,
        "lineage_assignments": f"""
            SELECT COUNT(*) FROM lineage_assignments assignment
            JOIN analysis_runs run
              ON run.analysis_run_id = assignment.analysis_run_id
            WHERE {run_filter}
        """,
        "policy_decisions": f"""
            SELECT COUNT(*) FROM policy_decisions decision
            JOIN analysis_runs run ON run.analysis_run_id = decision.analysis_run_id
            WHERE {run_filter}
        """,
        "redaction_decision_links": f"""
            SELECT COUNT(*) FROM redaction_decision_links link
            WHERE EXISTS (
                SELECT 1 FROM redaction_plans plan
                WHERE (plan.plan_id = link.enforce_plan_id
                       OR plan.plan_id = link.preview_plan_id)
                  AND ({plan_filter})
            )
        """,
        "redaction_plans": f"""
            SELECT COUNT(*) FROM redaction_plans plan WHERE {plan_filter}
        """,
        "redaction_targets": f"""
            SELECT COUNT(*) FROM redaction_targets target
            JOIN redaction_plans plan ON plan.plan_id = target.plan_id
            WHERE {plan_filter}
        """,
        "resource_versions": """
            SELECT COUNT(*) FROM resource_versions version
            WHERE EXISTS (
                SELECT 1 FROM eligible x
                WHERE x.session_id = version.session_id
                  AND x.workspace_id = version.workspace_id
            )
        """,
        "runtime_lineage_state": """
            SELECT COUNT(*) FROM runtime_lineage_state state
            WHERE EXISTS (
                SELECT 1 FROM eligible x
                WHERE x.session_id = state.session_id
                  AND x.workspace_id = state.workspace_id
            )
        """,
        "runtime_source_binding_edges": """
            SELECT COUNT(*) FROM runtime_source_binding_edges edge
            WHERE EXISTS (
                SELECT 1 FROM eligible x
                WHERE x.session_id = edge.session_id
                  AND x.workspace_id = edge.workspace_id
            )
        """,
        "source_binding_edges": f"""
            SELECT COUNT(*) FROM source_binding_edges edge
            JOIN analysis_runs run ON run.analysis_run_id = edge.analysis_run_id
            WHERE {run_filter}
        """,
        "tool_operations": """
            SELECT COUNT(*) FROM tool_operations o
            JOIN events e ON e.event_id = o.event_id
            WHERE """ + event_filter,
        "tool_operation_outcomes": """
            SELECT COUNT(*) FROM tool_operation_outcomes o
            JOIN events e ON e.event_id = o.post_event_id
            WHERE """ + event_filter,
        "resource_snapshots": """
            SELECT COUNT(*) FROM resource_snapshots r
            JOIN events e ON e.event_id = r.post_event_id
            WHERE """ + event_filter,
        "sink_candidates": """
            SELECT COUNT(*) FROM sink_candidates s
            WHERE EXISTS (
                SELECT 1 FROM eligible x
                WHERE x.session_id = s.session_id
                  AND x.workspace_id = s.workspace_id
            )
        """,
        "information_flow_edge_scopes": """
            SELECT COUNT(*) FROM information_flow_edge_scopes s
            WHERE EXISTS (
                SELECT 1 FROM eligible x
                WHERE x.session_id = s.session_id
                  AND x.workspace_id = s.workspace_id
            )
        """,
    }
    count_select = ",\n".join(
        f"({queries[table]}) AS {table}" for table in _CORE_RETENTION_TABLES
    )
    try:
        count_row = conn.execute(
            eligible_cte + "SELECT\n" + count_select,
            {"cutoff": cutoff_at},
        ).fetchone()
    except sqlite3.Error as exc:
        raise sqlite3.OperationalError("retention row count query failed") from exc
    if count_row is None:
        raise sqlite3.OperationalError("retention row count query returned no row")
    counts = {
        table: int(count_row[index])
        for index, table in enumerate(_CORE_RETENTION_TABLES)
    }
    eligibility_digest = hashlib.sha256(
        json.dumps(
            {
                "sessions": eligible_sessions,
                "unscoped_events": eligible_unscoped_event_ids,
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    return _RetentionInventory(
        eligible_sessions=eligible_sessions,
        eligible_incomplete_session_count=incomplete_count,
        pending_session_count=pending_count,
        eligible_unscoped_event_ids=eligible_unscoped_event_ids,
        candidate_rows=counts,
        eligibility_digest=eligibility_digest,
    )


def _estimate_reclaimable_bytes(
    owner_bytes: dict[str, int] | None,
    table_rows: dict[str, int],
    candidate_rows: dict[str, int],
) -> int | None:
    if owner_bytes is None:
        return None
    estimate = 0
    for table, candidates in candidate_rows.items():
        total = table_rows.get(table, 0)
        if candidates <= 0 or total <= 0:
            continue
        estimate += owner_bytes.get(table, 0) * min(candidates, total) // total
    return estimate


def _regular_file_size(path: Path) -> int:
    try:
        if path.is_symlink() or not path.is_file():
            return 0
        return path.stat().st_size
    except OSError as exc:
        raise StorageCleanupPlanError("storage_sidecar_inventory_failed") from exc
