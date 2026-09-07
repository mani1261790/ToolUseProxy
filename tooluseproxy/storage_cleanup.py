from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from hook_monitor.runtime.storage import CURRENT_SCHEMA_VERSION


STORAGE_CLEANUP_PLAN_SCHEMA_VERSION = 1
STORAGE_RETENTION_DAYS = 30
STORAGE_WARNING_BYTES = 2 * 1024 * 1024 * 1024
STORAGE_ACTION_BYTES = 4 * 1024 * 1024 * 1024
_TEMPORARY_SPACE_MARGIN_BYTES = 16 * 1024 * 1024
_MIGRATION_BACKUP_PATTERN = re.compile(
    r"^events\.db\.pre-migration-v(?P<version>[0-9]+)\.bak(?:\.[0-9]+)?$"
)

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
        "fragment_exact_index",
        "fragment_shingles",
        "runtime_lineage_state",
        "runtime_source_binding_edges",
    }
)
_CORE_RETENTION_TABLES = (
    "events",
    "artifacts",
    "artifact_fragments",
    "fragment_shingles",
    "fragment_exact_index",
    "tool_operations",
    "tool_operation_outcomes",
    "resource_snapshots",
    "sink_candidates",
    "information_flow_edge_scopes",
)


class StorageCleanupPlanError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class StorageCategoryUsage:
    allocated_bytes: int
    row_count: int

    def to_payload(self) -> dict[str, int]:
        return {
            "allocated_bytes": self.allocated_bytes,
            "row_count": self.row_count,
        }


@dataclass(frozen=True)
class StorageCleanupPlan:
    cutoff_at: str
    database_logical_bytes: int
    database_allocated_bytes: int
    database_free_page_bytes: int
    database_wal_bytes: int
    migration_backup_count: int
    migration_backup_bytes: int
    categories: dict[str, StorageCategoryUsage]
    eligible_session_count: int
    eligible_incomplete_session_count: int
    eligible_unscoped_event_count: int
    candidate_rows: dict[str, int]
    estimated_expired_reclaimable_bytes: int
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
                "categories": {
                    key: value.to_payload()
                    for key, value in sorted(self.categories.items())
                },
            },
            "retention_candidates": {
                "eligible_session_count": self.eligible_session_count,
                "eligible_incomplete_session_count": (
                    self.eligible_incomplete_session_count
                ),
                "eligible_unscoped_event_count": self.eligible_unscoped_event_count,
                "rows": dict(sorted(self.candidate_rows.items())),
                "estimated_reclaimable_bytes": (
                    self.estimated_expired_reclaimable_bytes
                ),
                "estimate_method": "proportional_owned_pages_v1",
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


def plan_storage_cleanup(
    db_path: Path,
    *,
    now: datetime | None = None,
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
        with _read_only_connection(requested) as conn:
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

    backup_count, backup_bytes = _migration_backup_usage(requested)
    wal_bytes = _regular_file_size(Path(f"{requested}-wal"))
    allocated_bytes = page_size * page_count
    free_page_bytes = page_size * freelist_count
    candidate_rows = retention[3]
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
        },
        "retention_days": STORAGE_RETENTION_DAYS,
        "cutoff_at": cutoff_at,
        "eligible_session_count": retention[0],
        "eligible_incomplete_session_count": retention[1],
        "eligible_unscoped_event_count": retention[2],
        "candidate_rows": candidate_rows,
        "migration_backup_count": backup_count,
        "migration_backup_bytes": backup_bytes,
    }
    revision = "sc1_" + hashlib.sha256(
        json.dumps(
            commitment,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    return StorageCleanupPlan(
        cutoff_at=cutoff_at,
        database_logical_bytes=database_stat.st_size,
        database_allocated_bytes=allocated_bytes,
        database_free_page_bytes=free_page_bytes,
        database_wal_bytes=wal_bytes,
        migration_backup_count=backup_count,
        migration_backup_bytes=backup_bytes,
        categories=categories,
        eligible_session_count=retention[0],
        eligible_incomplete_session_count=retention[1],
        eligible_unscoped_event_count=retention[2],
        candidate_rows=candidate_rows,
        estimated_expired_reclaimable_bytes=estimated_reclaimable,
        temporary_space_required_bytes=temporary_required,
        temporary_space_available_bytes=available_bytes,
        plan_revision=revision,
    )


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


def _owned_page_bytes(conn: sqlite3.Connection) -> dict[str, int]:
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
    except sqlite3.Error as exc:
        raise StorageCleanupPlanError("storage_page_classification_unavailable") from exc
    for object_name, size in rows:
        owner = index_owners.get(str(object_name), str(object_name))
        owned[owner] = owned.get(owner, 0) + int(size)
    return owned


def _category_usage(
    owner_bytes: dict[str, int],
    table_rows: dict[str, int],
) -> dict[str, StorageCategoryUsage]:
    totals: dict[str, list[int]] = {
        "detailed_operation_records": [0, 0],
        "rebuildable_detection_data": [0, 0],
        "improvement_feedback": [0, 0],
        "durable_configuration": [0, 0],
        "other": [0, 0],
    }
    for table, byte_count in owner_bytes.items():
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
        category: StorageCategoryUsage(values[0], values[1])
        for category, values in totals.items()
    }


def _retention_candidates(
    conn: sqlite3.Connection,
    cutoff_at: str,
) -> tuple[int, int, int, dict[str, int]]:
    eligible_cte = """
        WITH eligible AS (
            SELECT workspace_id, session_id,
                   SUM(CASE WHEN phase = 'stop' THEN 1 ELSE 0 END) AS stop_count
            FROM events
            WHERE session_id IS NOT NULL
            GROUP BY workspace_id, session_id
            HAVING MAX(julianday(recorded_at)) < julianday(:cutoff)
        )
    """
    session_count, incomplete_count = conn.execute(
        eligible_cte
        + "SELECT COUNT(*), COALESCE(SUM(stop_count = 0), 0) FROM eligible",
        {"cutoff": cutoff_at},
    ).fetchone()
    unscoped_count = int(
        conn.execute(
            """
            SELECT COUNT(*) FROM events
            WHERE session_id IS NULL AND julianday(recorded_at) < julianday(:cutoff)
            """,
            {"cutoff": cutoff_at},
        ).fetchone()[0]
    )
    queries = {
        "events": """
            SELECT COUNT(*) FROM events e
            WHERE (e.session_id IS NULL AND julianday(e.recorded_at) < julianday(:cutoff))
               OR EXISTS (
                   SELECT 1 FROM eligible x
                   WHERE x.session_id = e.session_id
                     AND x.workspace_id IS e.workspace_id
               )
        """,
        "artifacts": """
            SELECT COUNT(*) FROM artifacts a JOIN events e ON e.event_id = a.event_id
            WHERE (e.session_id IS NULL AND julianday(e.recorded_at) < julianday(:cutoff))
               OR EXISTS (SELECT 1 FROM eligible x WHERE x.session_id = e.session_id AND x.workspace_id IS e.workspace_id)
        """,
        "artifact_fragments": """
            SELECT COUNT(*) FROM artifact_fragments f
            JOIN artifacts a ON a.artifact_id = f.artifact_id
            JOIN events e ON e.event_id = a.event_id
            WHERE (e.session_id IS NULL AND julianday(e.recorded_at) < julianday(:cutoff))
               OR EXISTS (SELECT 1 FROM eligible x WHERE x.session_id = e.session_id AND x.workspace_id IS e.workspace_id)
        """,
        "fragment_shingles": """
            SELECT COUNT(*) FROM fragment_shingles f
            WHERE EXISTS (SELECT 1 FROM eligible x WHERE x.session_id = f.session_id AND x.workspace_id = f.workspace_id)
        """,
        "fragment_exact_index": """
            SELECT COUNT(*) FROM fragment_exact_index f
            WHERE EXISTS (SELECT 1 FROM eligible x WHERE x.session_id = f.session_id AND x.workspace_id = f.workspace_id)
        """,
        "tool_operations": """
            SELECT COUNT(*) FROM tool_operations o JOIN events e ON e.event_id = o.event_id
            WHERE (e.session_id IS NULL AND julianday(e.recorded_at) < julianday(:cutoff))
               OR EXISTS (SELECT 1 FROM eligible x WHERE x.session_id = e.session_id AND x.workspace_id IS e.workspace_id)
        """,
        "tool_operation_outcomes": """
            SELECT COUNT(*) FROM tool_operation_outcomes o JOIN events e ON e.event_id = o.post_event_id
            WHERE (e.session_id IS NULL AND julianday(e.recorded_at) < julianday(:cutoff))
               OR EXISTS (SELECT 1 FROM eligible x WHERE x.session_id = e.session_id AND x.workspace_id IS e.workspace_id)
        """,
        "resource_snapshots": """
            SELECT COUNT(*) FROM resource_snapshots r JOIN events e ON e.event_id = r.post_event_id
            WHERE (e.session_id IS NULL AND julianday(e.recorded_at) < julianday(:cutoff))
               OR EXISTS (SELECT 1 FROM eligible x WHERE x.session_id = e.session_id AND x.workspace_id IS e.workspace_id)
        """,
        "sink_candidates": """
            SELECT COUNT(*) FROM sink_candidates s
            WHERE EXISTS (SELECT 1 FROM eligible x WHERE x.session_id = s.session_id AND x.workspace_id = s.workspace_id)
        """,
        "information_flow_edge_scopes": """
            SELECT COUNT(*) FROM information_flow_edge_scopes s
            WHERE EXISTS (SELECT 1 FROM eligible x WHERE x.session_id = s.session_id AND x.workspace_id = s.workspace_id)
        """,
    }
    counts: dict[str, int] = {}
    for table in _CORE_RETENTION_TABLES:
        query = eligible_cte + queries[table]
        counts[table] = int(
            conn.execute(query, {"cutoff": cutoff_at}).fetchone()[0]
        )
    return int(session_count), int(incomplete_count), unscoped_count, counts


def _estimate_reclaimable_bytes(
    owner_bytes: dict[str, int],
    table_rows: dict[str, int],
    candidate_rows: dict[str, int],
) -> int:
    estimate = 0
    for table, candidates in candidate_rows.items():
        total = table_rows.get(table, 0)
        if candidates <= 0 or total <= 0:
            continue
        estimate += owner_bytes.get(table, 0) * min(candidates, total) // total
    return estimate


def _migration_backup_usage(db_path: Path) -> tuple[int, int]:
    count = 0
    byte_count = 0
    try:
        entries = list(db_path.parent.iterdir())
    except OSError as exc:
        raise StorageCleanupPlanError("storage_backup_inventory_failed") from exc
    for entry in entries:
        if _MIGRATION_BACKUP_PATTERN.fullmatch(entry.name) is None:
            continue
        if entry.is_symlink():
            raise StorageCleanupPlanError("storage_backup_symlink")
        try:
            if not entry.is_file():
                continue
            byte_count += entry.stat().st_size
        except OSError as exc:
            raise StorageCleanupPlanError("storage_backup_inventory_failed") from exc
        count += 1
    return count, byte_count


def _regular_file_size(path: Path) -> int:
    try:
        if path.is_symlink() or not path.is_file():
            return 0
        return path.stat().st_size
    except OSError as exc:
        raise StorageCleanupPlanError("storage_sidecar_inventory_failed") from exc
