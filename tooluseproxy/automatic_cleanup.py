from __future__ import annotations

import json
import os
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time
import uuid
from contextlib import closing, contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Iterator

if os.name == "nt":  # pragma: no cover - exercised by Windows package checks
    import msvcrt
else:
    import fcntl

from tooluseproxy.storage_cleanup import (
    STORAGE_ACTION_BYTES,
    STORAGE_CLEANUP_DEFAULT_BATCH_SIZE,
    STORAGE_WARNING_BYTES,
    StorageCleanupPlan,
    StorageCleanupPlanError,
    apply_storage_cleanup,
    plan_storage_cleanup,
    validate_storage_cleanup_review,
)


AUTOMATIC_CLEANUP_STATE_FILENAME = "storage-cleanup-state.json"
AUTOMATIC_CLEANUP_LOCK_FILENAME = "storage-cleanup-auto.lock"
AUTOMATIC_CLEANUP_REQUEST_FILENAME = "storage-cleanup.request"
AUTOMATIC_CLEANUP_DEFER_FILENAME = "storage-cleanup.defer"
RUNTIME_ACTIVITY_FILENAME = "runtime-activity"
AUTOMATIC_CLEANUP_STATE_SCHEMA_VERSION = 1
AUTOMATIC_CLEANUP_INTERVAL = timedelta(hours=24)
AUTOMATIC_CLEANUP_DEFER_RETRY = timedelta(minutes=5)
RUNTIME_QUIET_SECONDS = 1.0
COMPACTION_MINIMUM_FREE_BYTES = 16 * 1024 * 1024
_MAX_STATE_BYTES = 256 * 1024


class AutomaticCleanupError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class AutomaticCleanupRunResult:
    status: str
    reason: str | None
    deleted_session_count: int
    deleted_unscoped_event_count: int
    deleted_row_count: int
    deleted_migration_backup_count: int
    remaining_session_count: int
    remaining_unscoped_event_count: int
    remaining_migration_backup_count: int
    reclaimed_bytes: int
    database_compacted: bool
    storage_level: str
    total_managed_bytes: int | None

    def to_payload(self) -> dict[str, object]:
        return {
            "schema_version": AUTOMATIC_CLEANUP_STATE_SCHEMA_VERSION,
            "status": self.status,
            "reason": self.reason,
            "deleted": {
                "session_count": self.deleted_session_count,
                "unscoped_event_count": self.deleted_unscoped_event_count,
                "row_count": self.deleted_row_count,
                "migration_backup_count": (
                    self.deleted_migration_backup_count
                ),
            },
            "remaining": {
                "session_count": self.remaining_session_count,
                "unscoped_event_count": self.remaining_unscoped_event_count,
                "migration_backup_count": self.remaining_migration_backup_count,
            },
            "reclaimed_bytes": self.reclaimed_bytes,
            "database_compacted": self.database_compacted,
            "storage_level": self.storage_level,
            "total_managed_bytes": self.total_managed_bytes,
            "protected_manifest_read": False,
            "network_used": False,
        }


def automatic_cleanup_status(data_dir: Path) -> dict[str, object]:
    """Return value-free persistent status without creating any files."""

    try:
        state = _load_state(data_dir, missing_ok=True)
    except AutomaticCleanupError as exc:
        return {
            "schema_version": AUTOMATIC_CLEANUP_STATE_SCHEMA_VERSION,
            "enabled": False,
            "status": "unavailable",
            "reason": exc.code,
            "notification_pending": True,
        }
    return _public_state(state)


def enable_automatic_cleanup(
    db_path: Path,
    *,
    cutoff_at: str,
    reviewed_at: str,
    expected_plan_revision: str,
    now: datetime | None = None,
) -> dict[str, object]:
    """Enable future runs only after validating the exact reviewed plan."""

    observed = _utc_now(now)
    plan_time = _plan_time_from_cutoff(cutoff_at)
    try:
        reviewed = validate_storage_cleanup_review(
            cutoff_at=cutoff_at,
            reviewed_at=reviewed_at,
            now=observed,
        )
    except StorageCleanupPlanError as exc:
        code = (
            "automatic_cleanup_plan_expired"
            if exc.code == "storage_plan_expired"
            else "automatic_cleanup_plan_review_time_invalid"
        )
        raise AutomaticCleanupError(code) from exc
    plan = plan_storage_cleanup(
        db_path,
        now=plan_time,
        reviewed_at=reviewed,
    )
    if plan.plan_revision != expected_plan_revision:
        raise AutomaticCleanupError("automatic_cleanup_plan_changed")
    data_dir = db_path.parent
    with _automatic_cleanup_lock(data_dir, blocking=True) as acquired:
        if not acquired:  # pragma: no cover - blocking lock always resolves
            raise AutomaticCleanupError("automatic_cleanup_busy")
        state = _load_state(data_dir, missing_ok=True)
        state.update(
            {
                "enabled": True,
                "enabled_at": _format_time(observed),
                "authorization_cutoff_at": cutoff_at,
                "authorization_reviewed_at": reviewed_at,
                "authorization_plan_revision": expected_plan_revision,
                "status": "waiting",
                "reason": None,
            }
        )
        _write_state(data_dir, state)
    return _public_state(state)


def disable_automatic_cleanup(
    data_dir: Path,
    *,
    now: datetime | None = None,
) -> dict[str, object]:
    observed = _utc_now(now)
    with _automatic_cleanup_lock(data_dir, blocking=True) as acquired:
        if not acquired:  # pragma: no cover - blocking lock always resolves
            raise AutomaticCleanupError("automatic_cleanup_busy")
        state = _load_state(data_dir, missing_ok=True)
        state.update(
            {
                "enabled": False,
                "disabled_at": _format_time(observed),
                "status": "disabled",
                "reason": None,
            }
        )
        _write_state(data_dir, state)
        _remove_request(data_dir)
    return _public_state(state)


def signal_runtime_activity(data_dir: Path) -> None:
    """Publish a tiny cancellation signal before an enabled Hook uses SQLite."""

    data_dir.mkdir(parents=True, exist_ok=True)
    try:
        _atomic_write(
            data_dir / RUNTIME_ACTIVITY_FILENAME,
            (uuid.uuid4().hex + "\n").encode("ascii"),
            sync_directory=False,
        )
    except AutomaticCleanupError:
        # Use a separate fail-safe marker so a failure limited to the normal
        # activity channel still prevents a worker from deleting anything.
        try:
            _atomic_write(
                data_dir / AUTOMATIC_CLEANUP_DEFER_FILENAME,
                b"runtime_activity_signal_failed\n",
                sync_directory=False,
            )
        except AutomaticCleanupError:
            pass
        raise
    else:
        try:
            (data_dir / AUTOMATIC_CLEANUP_DEFER_FILENAME).unlink(missing_ok=True)
        except OSError:
            # A stale fail-safe marker only postpones cleanup.
            pass


def record_automatic_cleanup_failure(data_dir: Path, reason: str) -> None:
    """Persist a value-free notice without delaying the protection path."""

    try:
        with _automatic_cleanup_lock(data_dir, blocking=False) as acquired:
            if not acquired:
                return
            state = _load_state(data_dir, missing_ok=True)
            if not state.get("enabled"):
                return
            state.update(
                {
                    "status": "deferred",
                    "reason": reason,
                    "last_deferred_at": _format_time(datetime.now(UTC)),
                    "notification_pending": "cleanup_failed",
                }
            )
            _write_state(data_dir, state)
    except (OSError, AutomaticCleanupError):
        pass


def reserve_automatic_cleanup(db_path: Path) -> bool:
    """Create a lightweight request and launch a detached local worker."""

    data_dir = db_path.parent
    try:
        state = _load_state(data_dir, missing_ok=True)
    except AutomaticCleanupError:
        return False
    if not state.get("enabled"):
        return False
    try:
        _atomic_write(
            data_dir / AUTOMATIC_CLEANUP_REQUEST_FILENAME,
            (_format_time(datetime.now(UTC)) + "\n").encode("ascii"),
            sync_directory=False,
        )
        entrypoint = Path(__file__).resolve().parents[1] / "tooluseproxy_plugin.py"
        command = (
            [sys.executable, str(entrypoint)]
            if entrypoint.is_file()
            else [sys.executable, "-m", "tooluseproxy"]
        )
        subprocess.Popen(
            [
                *command,
                "storage",
                "cleanup",
                "auto",
                "run",
                "--data-dir",
                str(data_dir),
                "--json",
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
            close_fds=True,
        )
    except (OSError, AutomaticCleanupError):
        return False
    return True


def run_automatic_cleanup(
    db_path: Path,
    *,
    now: datetime | None = None,
    wait_for_quiet: bool = True,
) -> AutomaticCleanupRunResult:
    """Run one bounded daily cleanup outside the Hook process."""

    observed = _utc_now(now)
    data_dir = db_path.parent
    with _automatic_cleanup_lock(data_dir, blocking=False) as acquired:
        if not acquired:
            return _result("deferred", "another_cleanup_running")
        state = _load_state(data_dir, missing_ok=True)
        if not state.get("enabled"):
            _remove_request(data_dir)
            return _result("disabled", "initial_confirmation_required")

        previous_started = _parse_time(state.get("last_started_at"))
        if state.get("status") == "running" and previous_started is not None:
            state.update(
                {
                    "status": "interrupted",
                    "reason": "previous_run_interrupted",
                    "notification_pending": "cleanup_failed",
                }
            )
            _write_state(data_dir, state)

        last_started = _parse_time(state.get("last_started_at"))
        if last_started is not None and observed < last_started + AUTOMATIC_CLEANUP_INTERVAL:
            _remove_request(data_dir)
            return _result_from_state(state, "not_due", "daily_limit")
        last_deferred = _parse_time(state.get("last_deferred_at"))
        if (
            last_deferred is not None
            and observed < last_deferred + AUTOMATIC_CLEANUP_DEFER_RETRY
        ):
            _remove_request(data_dir)
            return _result_from_state(state, "deferred", "retry_delay")

        if wait_for_quiet:
            _wait_for_runtime_quiet(data_dir)
        activity_revision = _activity_revision(data_dir)
        if _defer_requested(data_dir):
            return _defer(state, data_dir, observed, "runtime_signal_failed")
        if not _runtime_is_quiet(data_dir):
            return _defer(state, data_dir, observed, "runtime_active")
        if not _database_is_idle(db_path):
            return _defer(state, data_dir, observed, "database_busy")

        def cleanup_cancelled() -> bool:
            return (
                _activity_revision(data_dir) != activity_revision
                or _defer_requested(data_dir)
            )

        try:
            initial_plan = plan_storage_cleanup(
                db_path,
                now=observed,
                cancel_check=cleanup_cancelled,
            )
        except (OSError, sqlite3.Error, StorageCleanupPlanError) as exc:
            if cleanup_cancelled():
                return _defer(state, data_dir, observed, "runtime_active")
            return _fail(state, data_dir, observed, _safe_failure_code(exc))

        initial_total = _total_managed_bytes(initial_plan)
        state.update(
            {
                "status": "running",
                "reason": None,
                "last_started_at": _format_time(observed),
                "storage_level": _storage_level(initial_total),
                "total_managed_bytes": initial_total,
            }
        )
        _write_state(data_dir, state)

        deleted_sessions = 0
        deleted_unscoped = 0
        deleted_rows = 0
        deleted_backups = 0
        try:
            if _plan_has_deletion_candidates(initial_plan):
                result = apply_storage_cleanup(
                    db_path,
                    cutoff_at=initial_plan.cutoff_at,
                    reviewed_at=initial_plan.reviewed_at,
                    expected_plan_revision=initial_plan.plan_revision,
                    batch_size=STORAGE_CLEANUP_DEFAULT_BATCH_SIZE,
                    cancel_check=cleanup_cancelled,
                )
                deleted_sessions = result.deleted_session_count
                deleted_unscoped = result.deleted_unscoped_event_count
                deleted_rows = sum(result.deleted_rows.values())
                deleted_backups = result.deleted_migration_backup_count
            after_delete = plan_storage_cleanup(
                db_path,
                now=observed,
                cancel_check=cleanup_cancelled,
            )
        except (OSError, sqlite3.Error, StorageCleanupPlanError) as exc:
            reason = (
                "runtime_active"
                if (
                    _activity_revision(data_dir) != activity_revision
                    or _defer_requested(data_dir)
                )
                else _safe_failure_code(exc)
            )
            if reason == "runtime_active":
                return _defer(state, data_dir, observed, reason)
            return _fail(state, data_dir, observed, reason)

        if (
            _activity_revision(data_dir) != activity_revision
            or _defer_requested(data_dir)
        ):
            return _finish(
                state,
                data_dir,
                observed,
                after_delete,
                initial_total=initial_total,
                deleted_sessions=deleted_sessions,
                deleted_unscoped=deleted_unscoped,
                deleted_rows=deleted_rows,
                deleted_backups=deleted_backups,
                compacted=False,
                reason="runtime_active",
                notification=None,
            )

        compacted = False
        if _compaction_worthwhile(after_delete):
            if (
                after_delete.temporary_space_available_bytes
                < after_delete.temporary_space_required_bytes
            ):
                return _finish(
                    state,
                    data_dir,
                    observed,
                    after_delete,
                    initial_total=initial_total,
                    deleted_sessions=deleted_sessions,
                    deleted_unscoped=deleted_unscoped,
                    deleted_rows=deleted_rows,
                    deleted_backups=deleted_backups,
                    compacted=False,
                    reason="insufficient_temporary_space",
                    notification="insufficient_space",
                )
            compacted = _compact_database(
                db_path,
                data_dir=data_dir,
                expected_activity_revision=activity_revision,
            )
            if not compacted and (
                _activity_revision(data_dir) != activity_revision
                or _defer_requested(data_dir)
            ):
                return _defer(state, data_dir, observed, "runtime_active")
            if not compacted:
                return _fail(state, data_dir, observed, "database_compaction_failed")

        try:
            final_plan = plan_storage_cleanup(
                db_path,
                now=observed,
                cancel_check=cleanup_cancelled,
            )
        except (OSError, sqlite3.Error, StorageCleanupPlanError) as exc:
            if cleanup_cancelled():
                return _defer(state, data_dir, observed, "runtime_active")
            return _fail(state, data_dir, observed, _safe_failure_code(exc))
        notification = (
            "action_threshold_persists"
            if _total_managed_bytes(final_plan) >= STORAGE_ACTION_BYTES
            else None
        )
        return _finish(
            state,
            data_dir,
            observed,
            final_plan,
            initial_total=initial_total,
            deleted_sessions=deleted_sessions,
            deleted_unscoped=deleted_unscoped,
            deleted_rows=deleted_rows,
            deleted_backups=deleted_backups,
            compacted=compacted,
            reason=None,
            notification=notification,
        )


def take_automatic_cleanup_notice(data_dir: Path) -> str | None:
    """Consume one pending notice for a later SessionStart Hook."""

    with _automatic_cleanup_lock(data_dir, blocking=False) as acquired:
        if not acquired:
            return None
        state = _load_state(data_dir, missing_ok=True)
        code = state.get("notification_pending")
        messages = {
            "cleanup_failed": (
                "ToolUseProxyの自動整理を完了できませんでした。"
                " `tooluseproxy status`で状態を確認してください。"
            ),
            "action_threshold_persists": (
                "ToolUseProxyの保存容量が自動整理後も4 GiB以上です。"
                " `tooluseproxy status`で状態を確認してください。"
            ),
            "insufficient_space": (
                "ToolUseProxyのDBを安全に縮小するための空き容量が不足しています。"
                " `tooluseproxy status`で状態を確認してください。"
            ),
        }
        if not isinstance(code, str) or code not in messages:
            return None
        state["notification_pending"] = None
        state["notification_delivered_at"] = _format_time(datetime.now(UTC))
        _write_state(data_dir, state)
        return messages[code]


def _finish(
    state: dict[str, Any],
    data_dir: Path,
    observed: datetime,
    plan: StorageCleanupPlan,
    *,
    initial_total: int,
    deleted_sessions: int,
    deleted_unscoped: int,
    deleted_rows: int,
    deleted_backups: int,
    compacted: bool,
    reason: str | None,
    notification: str | None,
) -> AutomaticCleanupRunResult:
    final_total = _total_managed_bytes(plan)
    status = "completed" if reason is None else "completed_with_warning"
    state.update(
        {
            "status": status,
            "reason": reason,
            "last_completed_at": _format_time(observed),
            "last_deleted_session_count": deleted_sessions,
            "last_deleted_unscoped_event_count": deleted_unscoped,
            "last_deleted_row_count": deleted_rows,
            "last_deleted_migration_backup_count": deleted_backups,
            "remaining_session_count": plan.eligible_session_count,
            "remaining_unscoped_event_count": plan.eligible_unscoped_event_count,
            "remaining_migration_backup_count": (
                plan.migration_backup_eligible_count
            ),
            "last_reclaimed_bytes": max(0, initial_total - final_total),
            "last_database_compacted": compacted,
            "storage_level": _storage_level(final_total),
            "total_managed_bytes": final_total,
            # A later normal run must not erase an earlier warning before the
            # next SessionStart has shown it to the user.
            "notification_pending": (
                notification
                if notification is not None
                else state.get("notification_pending")
            ),
        }
    )
    _write_state(data_dir, state)
    _remove_request(data_dir)
    return _result_from_state(state, status, reason)


def _defer(
    state: dict[str, Any],
    data_dir: Path,
    observed: datetime,
    reason: str,
) -> AutomaticCleanupRunResult:
    state.update(
        {
            "status": "deferred",
            "reason": reason,
            "last_deferred_at": _format_time(observed),
        }
    )
    _write_state(data_dir, state)
    _remove_request(data_dir)
    return _result_from_state(state, "deferred", reason)


def _fail(
    state: dict[str, Any],
    data_dir: Path,
    observed: datetime,
    reason: str,
) -> AutomaticCleanupRunResult:
    state.update(
        {
            "status": "failed",
            "reason": reason,
            "last_failed_at": _format_time(observed),
            "notification_pending": "cleanup_failed",
        }
    )
    _write_state(data_dir, state)
    _remove_request(data_dir)
    return _result_from_state(state, "failed", reason)


def _result_from_state(
    state: dict[str, Any],
    status: str,
    reason: str | None,
) -> AutomaticCleanupRunResult:
    return AutomaticCleanupRunResult(
        status=status,
        reason=reason,
        deleted_session_count=_state_int(state, "last_deleted_session_count"),
        deleted_unscoped_event_count=_state_int(
            state, "last_deleted_unscoped_event_count"
        ),
        deleted_row_count=_state_int(state, "last_deleted_row_count"),
        deleted_migration_backup_count=_state_int(
            state, "last_deleted_migration_backup_count"
        ),
        remaining_session_count=_state_int(state, "remaining_session_count"),
        remaining_unscoped_event_count=_state_int(
            state, "remaining_unscoped_event_count"
        ),
        remaining_migration_backup_count=_state_int(
            state, "remaining_migration_backup_count"
        ),
        reclaimed_bytes=_state_int(state, "last_reclaimed_bytes"),
        database_compacted=bool(state.get("last_database_compacted", False)),
        storage_level=str(state.get("storage_level", "unknown")),
        total_managed_bytes=(
            state.get("total_managed_bytes")
            if type(state.get("total_managed_bytes")) is int
            else None
        ),
    )


def _result(status: str, reason: str | None) -> AutomaticCleanupRunResult:
    return AutomaticCleanupRunResult(
        status=status,
        reason=reason,
        deleted_session_count=0,
        deleted_unscoped_event_count=0,
        deleted_row_count=0,
        deleted_migration_backup_count=0,
        remaining_session_count=0,
        remaining_unscoped_event_count=0,
        remaining_migration_backup_count=0,
        reclaimed_bytes=0,
        database_compacted=False,
        storage_level="unknown",
        total_managed_bytes=None,
    )


def _public_state(state: dict[str, Any]) -> dict[str, object]:
    return {
        "schema_version": AUTOMATIC_CLEANUP_STATE_SCHEMA_VERSION,
        "enabled": bool(state.get("enabled", False)),
        "status": str(state.get("status", "never_run")),
        "reason": state.get("reason") if isinstance(state.get("reason"), str) else None,
        "last_started_at": _public_time(state.get("last_started_at")),
        "last_completed_at": _public_time(state.get("last_completed_at")),
        "last_deferred_at": _public_time(state.get("last_deferred_at")),
        "deleted": {
            "session_count": _state_int(state, "last_deleted_session_count"),
            "unscoped_event_count": _state_int(
                state, "last_deleted_unscoped_event_count"
            ),
            "row_count": _state_int(state, "last_deleted_row_count"),
            "migration_backup_count": _state_int(
                state, "last_deleted_migration_backup_count"
            ),
        },
        "remaining": {
            "session_count": _state_int(state, "remaining_session_count"),
            "unscoped_event_count": _state_int(
                state, "remaining_unscoped_event_count"
            ),
            "migration_backup_count": _state_int(
                state, "remaining_migration_backup_count"
            ),
        },
        "reclaimed_bytes": _state_int(state, "last_reclaimed_bytes"),
        "database_compacted": bool(state.get("last_database_compacted", False)),
        "storage_level": str(state.get("storage_level", "unknown")),
        "total_managed_bytes": (
            state.get("total_managed_bytes")
            if type(state.get("total_managed_bytes")) is int
            else None
        ),
        "notification_pending": isinstance(
            state.get("notification_pending"), str
        ),
        "next_eligible_at": _next_eligible_time(state),
    }


def _empty_state() -> dict[str, Any]:
    return {
        "schema_version": AUTOMATIC_CLEANUP_STATE_SCHEMA_VERSION,
        "enabled": False,
        "status": "never_run",
        "reason": None,
        "notification_pending": None,
    }


def _load_state(data_dir: Path, *, missing_ok: bool) -> dict[str, Any]:
    path = data_dir / AUTOMATIC_CLEANUP_STATE_FILENAME
    if path.is_symlink():
        raise AutomaticCleanupError("automatic_cleanup_state_symlink")
    if not path.exists():
        if missing_ok:
            return _empty_state()
        raise AutomaticCleanupError("automatic_cleanup_state_missing")
    try:
        if path.stat().st_size > _MAX_STATE_BYTES:
            raise AutomaticCleanupError("automatic_cleanup_state_invalid")
        state = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise AutomaticCleanupError("automatic_cleanup_state_invalid") from exc
    if (
        not isinstance(state, dict)
        or state.get("schema_version")
        != AUTOMATIC_CLEANUP_STATE_SCHEMA_VERSION
    ):
        raise AutomaticCleanupError("automatic_cleanup_state_invalid")
    return state


def _write_state(data_dir: Path, state: dict[str, Any]) -> None:
    state["schema_version"] = AUTOMATIC_CLEANUP_STATE_SCHEMA_VERSION
    encoded = (
        json.dumps(state, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    if len(encoded) > _MAX_STATE_BYTES:
        raise AutomaticCleanupError("automatic_cleanup_state_too_large")
    _atomic_write(data_dir / AUTOMATIC_CLEANUP_STATE_FILENAME, encoded)


def _atomic_write(
    path: Path,
    data: bytes,
    *,
    sync_directory: bool = True,
) -> None:
    descriptor, name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
    )
    temporary = Path(name)
    try:
        if os.name == "posix":
            os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            descriptor = -1
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        if sync_directory and os.name == "posix":
            directory_descriptor = os.open(
                path.parent,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
            )
            try:
                os.fsync(directory_descriptor)
            finally:
                os.close(directory_descriptor)
    except Exception as exc:
        if descriptor >= 0:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)
        if isinstance(exc, AutomaticCleanupError):
            raise
        raise AutomaticCleanupError("automatic_cleanup_state_write_failed") from exc


@contextmanager
def _automatic_cleanup_lock(
    data_dir: Path,
    *,
    blocking: bool,
    create: bool = True,
) -> Iterator[bool]:
    path = data_dir / AUTOMATIC_CLEANUP_LOCK_FILENAME
    flags = os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
    if create:
        flags |= os.O_CREAT
    try:
        descriptor = os.open(path, flags, 0o600)
    except FileNotFoundError:
        if not create:
            yield False
            return
        raise AutomaticCleanupError("automatic_cleanup_lock_unavailable") from None
    except OSError as exc:
        raise AutomaticCleanupError("automatic_cleanup_lock_unavailable") from exc
    with os.fdopen(descriptor, "r+b", closefd=True) as lock:
        if not stat.S_ISREG(os.fstat(lock.fileno()).st_mode):
            raise AutomaticCleanupError("automatic_cleanup_lock_invalid")
        if os.name == "posix":
            os.fchmod(lock.fileno(), 0o600)
        acquired = _acquire_lock(lock, blocking=blocking)
        try:
            yield acquired
        finally:
            if acquired:
                _release_lock(lock)


@contextmanager
def automatic_cleanup_uninstall_guard(data_dir: Path) -> Iterator[bool]:
    """Prevent cleanup workers from overlapping managed-data deletion."""

    state_path = data_dir / AUTOMATIC_CLEANUP_STATE_FILENAME
    request_path = data_dir / AUTOMATIC_CLEANUP_REQUEST_FILENAME
    lock_path = data_dir / AUTOMATIC_CLEANUP_LOCK_FILENAME
    if not state_path.exists() and not request_path.exists() and not lock_path.exists():
        yield True
        return
    with _automatic_cleanup_lock(
        data_dir,
        blocking=False,
        create=False,
    ) as acquired:
        yield acquired


def _acquire_lock(lock: Any, *, blocking: bool) -> bool:
    if os.name == "nt":  # pragma: no cover - exercised by Windows package checks
        lock.seek(0)
        lock.write(b"\0")
        lock.flush()
        lock.seek(0)
        mode = msvcrt.LK_LOCK if blocking else msvcrt.LK_NBLCK
        try:
            msvcrt.locking(lock.fileno(), mode, 1)
        except OSError:
            return False
        return True
    operation = fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB)
    try:
        fcntl.flock(lock, operation)
    except BlockingIOError:
        return False
    return True


def _release_lock(lock: Any) -> None:
    if os.name == "nt":  # pragma: no cover - exercised by Windows package checks
        lock.seek(0)
        msvcrt.locking(lock.fileno(), msvcrt.LK_UNLCK, 1)
    else:
        fcntl.flock(lock, fcntl.LOCK_UN)


def _database_is_idle(path: Path) -> bool:
    try:
        with closing(
            sqlite3.connect(
                f"{path.resolve(strict=True).as_uri()}?mode=rw",
                uri=True,
                timeout=0,
                isolation_level=None,
            )
        ) as conn:
            conn.execute("PRAGMA busy_timeout = 0")
            conn.execute("BEGIN IMMEDIATE")
            conn.execute("ROLLBACK")
    except (OSError, sqlite3.Error):
        return False
    return True


def _compact_database(
    path: Path,
    *,
    data_dir: Path,
    expected_activity_revision: tuple[int, int, int] | None,
) -> bool:
    try:
        with closing(
            sqlite3.connect(
                f"{path.resolve(strict=True).as_uri()}?mode=rw",
                uri=True,
                timeout=0,
                isolation_level=None,
            )
        ) as conn:
            conn.execute("PRAGMA busy_timeout = 0")
            conn.set_progress_handler(
                lambda: int(
                    _activity_revision(data_dir)
                    != expected_activity_revision
                    or _defer_requested(data_dir)
                ),
                1000,
            )
            conn.execute("VACUUM")
            checkpoint = conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
            if checkpoint is None or checkpoint[0] != 0:
                return False
            row = conn.execute("PRAGMA quick_check").fetchone()
            return row is not None and row[0] == "ok"
    except (OSError, sqlite3.Error):
        return False


def _wait_for_runtime_quiet(data_dir: Path) -> None:
    absolute_deadline = time.monotonic() + (RUNTIME_QUIET_SECONDS * 5)
    deadline = time.monotonic() + RUNTIME_QUIET_SECONDS
    revision = _activity_revision(data_dir)
    while time.monotonic() < min(deadline, absolute_deadline):
        time.sleep(
            min(
                0.05,
                max(0.0, min(deadline, absolute_deadline) - time.monotonic()),
            )
        )
        current = _activity_revision(data_dir)
        if current != revision:
            revision = current
            deadline = time.monotonic() + RUNTIME_QUIET_SECONDS


def _runtime_is_quiet(data_dir: Path) -> bool:
    path = data_dir / RUNTIME_ACTIVITY_FILENAME
    try:
        age = time.time() - path.stat().st_mtime
    except FileNotFoundError:
        return True
    except OSError:
        return False
    return age >= RUNTIME_QUIET_SECONDS


def _defer_requested(data_dir: Path) -> bool:
    path = data_dir / AUTOMATIC_CLEANUP_DEFER_FILENAME
    try:
        return path.is_file() or path.is_symlink()
    except OSError:
        return True


def _activity_revision(data_dir: Path) -> tuple[int, int, int] | None:
    try:
        metadata = (data_dir / RUNTIME_ACTIVITY_FILENAME).stat()
    except FileNotFoundError:
        return None
    except OSError:
        return (-1, -1, -1)
    return (metadata.st_ino, metadata.st_size, metadata.st_mtime_ns)


def _plan_has_deletion_candidates(plan: StorageCleanupPlan) -> bool:
    return bool(
        plan.eligible_session_count
        or plan.eligible_unscoped_event_count
        or plan.migration_backup_eligible_count
    )


def _compaction_worthwhile(plan: StorageCleanupPlan) -> bool:
    threshold = max(
        COMPACTION_MINIMUM_FREE_BYTES,
        plan.database_allocated_bytes // 20,
    )
    return plan.database_free_page_bytes >= threshold


def _total_managed_bytes(plan: StorageCleanupPlan) -> int:
    return (
        plan.database_allocated_bytes
        + plan.database_wal_bytes
        + plan.migration_backup_bytes
    )


def _storage_level(total: int) -> str:
    if total >= STORAGE_ACTION_BYTES:
        return "action_required"
    if total >= STORAGE_WARNING_BYTES:
        return "warning"
    return "normal"


def _safe_failure_code(exc: BaseException) -> str:
    code = getattr(exc, "code", None)
    if isinstance(code, str) and len(code) <= 80:
        return code
    return "automatic_cleanup_failed"


def _remove_request(data_dir: Path) -> None:
    try:
        (data_dir / AUTOMATIC_CLEANUP_REQUEST_FILENAME).unlink(missing_ok=True)
    except OSError:
        pass


def _state_int(state: dict[str, Any], key: str) -> int:
    value = state.get(key)
    return value if type(value) is int and value >= 0 else 0


def _next_eligible_time(state: dict[str, Any]) -> str | None:
    started = _parse_time(state.get("last_started_at"))
    if started is None:
        return None
    return _format_time(started + AUTOMATIC_CLEANUP_INTERVAL)


def _public_time(value: Any) -> str | None:
    parsed = _parse_time(value)
    return None if parsed is None else _format_time(parsed)


def _plan_time_from_cutoff(value: str) -> datetime:
    try:
        cutoff = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, ValueError) as exc:
        raise AutomaticCleanupError("automatic_cleanup_cutoff_invalid") from exc
    if cutoff.tzinfo is None or not value.endswith("Z"):
        raise AutomaticCleanupError("automatic_cleanup_cutoff_invalid")
    from tooluseproxy.storage_cleanup import STORAGE_RETENTION_DAYS

    return cutoff.astimezone(UTC) + timedelta(days=STORAGE_RETENTION_DAYS)


def _utc_now(value: datetime | None) -> datetime:
    observed = value or datetime.now(UTC)
    if observed.tzinfo is None:
        raise AutomaticCleanupError("automatic_cleanup_time_timezone_required")
    return observed.astimezone(UTC)


def _format_time(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="seconds").replace(
        "+00:00", "Z"
    )


def _parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.endswith("Z"):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.astimezone(UTC)
