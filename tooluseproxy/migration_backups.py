from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import sqlite3
import stat
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Callable, Iterator

from hook_monitor.runtime.storage import CURRENT_SCHEMA_VERSION


MIGRATION_BACKUP_RETENTION_DAYS = 7
MIGRATION_BACKUP_STATE_FILENAME = "migration-backups.json"
MIGRATION_BACKUP_LOCK_FILENAME = "migration-backups.lock"
MIGRATION_BACKUP_STATE_SCHEMA_VERSION = 1
_MAX_STATE_BYTES = 1024 * 1024
_BACKUP_PATTERN = re.compile(
    r"^events\.db\.pre-migration-v(?P<version>[0-9]+)\.bak(?:\.[0-9]+)?$"
)


class MigrationBackupError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class MigrationBackupInventory:
    total_count: int
    total_bytes: int
    eligible_count: int
    eligible_bytes: int
    recent_count: int
    awaiting_verification_count: int
    identity_mismatch_count: int
    current_database_integrity_ok: bool
    verification_current: bool
    cleanup_blocked: bool
    eligible_names: tuple[str, ...]
    inventory_digest: str


@dataclass(frozen=True)
class MigrationBackupDeleteResult:
    deleted_count: int
    deleted_bytes: int
    completed: bool


def record_migration_backup(
    backup_path: Path,
    *,
    source_schema_version: int,
    target_schema_version: int,
    runtime_version: str,
    now: datetime | None = None,
    _lock_held: bool = False,
) -> None:
    """Record a new SQLite backup awaiting live-runtime verification."""

    observed = _utc_now(now)
    backup = _regular_backup_path(backup_path)
    source_from_name = _source_version_from_name(backup.name)
    if (
        type(source_schema_version) is not int
        or source_schema_version < 0
        or source_from_name != source_schema_version
        or type(target_schema_version) is not int
        or target_schema_version != CURRENT_SCHEMA_VERSION
        or source_schema_version > target_schema_version
        or not _runtime_version_is_safe(runtime_version)
    ):
        raise MigrationBackupError("migration_backup_metadata_invalid")
    def update() -> None:
        try:
            metadata = backup.stat()
        except OSError as exc:
            raise MigrationBackupError("migration_backup_invalid") from exc
        state = _load_state(backup.parent, missing_ok=True)
        records = _state_records(state)
        _discard_absent_records(
            records,
            {
                discovered.name
                for discovered, _version, _metadata in _discover_backups(
                    backup.parent
                )
            },
        )
        if _record_matches_file(
            records.get(backup.name),
            metadata,
            source_schema_version,
        ):
            raise MigrationBackupError("migration_backup_record_conflict")
        records[backup.name] = {
            "source_schema_version": source_schema_version,
            "target_schema_version": target_schema_version,
            "created_at": _format_time(observed),
            "runtime_version": runtime_version,
            "device": metadata.st_dev,
            "inode": metadata.st_ino,
            "size": metadata.st_size,
            "mtime_ns": metadata.st_mtime_ns,
            "verified_at": None,
            "verified_runtime_version": None,
            "verified_database_device": None,
            "verified_database_inode": None,
            "verified_database_schema_version": None,
            "provenance": "recorded_at_creation",
        }
        _write_state(backup.parent, state)

    if _lock_held:
        update()
    else:
        with migration_backup_lock(backup.parent, exclusive=True, create=True):
            update()


def mark_migration_backups_verified(
    db_path: Path,
    *,
    runtime_version: str,
    now: datetime | None = None,
) -> int:
    """Bind all current backups to a live, integrity-checked current runtime."""

    observed = _utc_now(now)
    if not _runtime_version_is_safe(runtime_version):
        raise MigrationBackupError("migration_backup_runtime_version_invalid")
    database = _regular_database_path(db_path)
    database_stat = database.stat()
    if not _database_integrity_ok(database):
        raise MigrationBackupError("migration_current_database_integrity_failed")
    with migration_backup_lock(database.parent, exclusive=True, create=True):
        state = _load_state(database.parent, missing_ok=True)
        records = _state_records(state)
        discovered = _discover_backups(database.parent)
        _discard_absent_records(
            records,
            {backup.name for backup, _version, _metadata in discovered},
        )
        for backup, source_version, metadata in discovered:
            existing = records.get(backup.name)
            if existing is None:
                records[backup.name] = {
                    "source_schema_version": source_version,
                    "target_schema_version": CURRENT_SCHEMA_VERSION,
                    "created_at": _format_time(
                        datetime.fromtimestamp(metadata.st_mtime, tz=UTC)
                    ),
                    "runtime_version": None,
                    "device": metadata.st_dev,
                    "inode": metadata.st_ino,
                    "size": metadata.st_size,
                    "mtime_ns": metadata.st_mtime_ns,
                    "verified_at": None,
                    "verified_runtime_version": None,
                    "verified_database_device": None,
                    "verified_database_inode": None,
                    "verified_database_schema_version": None,
                    "provenance": "adopted_legacy_backup",
                }
                existing = records[backup.name]
            if not _record_matches_file(existing, metadata, source_version):
                continue
            already_bound = bool(
                existing.get("verified_at") is not None
                and existing.get("verified_database_device")
                == database_stat.st_dev
                and existing.get("verified_database_inode")
                == database_stat.st_ino
                and existing.get("verified_database_schema_version")
                == CURRENT_SCHEMA_VERSION
            )
            existing.update(
                {
                    "verified_at": (
                        existing.get("verified_at")
                        if already_bound
                        else _format_time(observed)
                    ),
                    "verified_runtime_version": runtime_version,
                    "verified_database_device": database_stat.st_dev,
                    "verified_database_inode": database_stat.st_ino,
                    "verified_database_schema_version": CURRENT_SCHEMA_VERSION,
                }
            )
        _write_state(database.parent, state)
        return sum(
            1
            for _backup, _version, metadata in discovered
            if _record_is_verified(
                records.get(_backup.name),
                metadata,
                database_stat=database_stat,
            )
        )


def inventory_migration_backups(
    db_path: Path,
    *,
    now: datetime,
    require_integrity_check: bool = True,
    cancel_check: Callable[[], bool] | None = None,
    _lock_held: bool = False,
) -> MigrationBackupInventory:
    """Classify backup files without exposing their names or paths."""

    observed = _utc_now(now)
    database = _regular_database_path(db_path)
    database_stat = database.stat()
    integrity_ok = (
        _database_integrity_ok(database, cancel_check=cancel_check)
        if require_integrity_check
        else True
    )
    if _lock_held:
        state = _load_state(database.parent, missing_ok=True)
        discovered = _discover_backups(database.parent)
    else:
        try:
            with migration_backup_lock(
                database.parent,
                exclusive=False,
                create=False,
            ):
                state = _load_state(database.parent, missing_ok=True)
                discovered = _discover_backups(database.parent)
        except FileNotFoundError:
            state = _empty_state()
            discovered = _discover_backups(database.parent)

    records = _state_records(state)
    total_bytes = sum(metadata.st_size for _, _, metadata in discovered)
    awaiting = 0
    mismatches = 0
    recent = 0
    provisional: list[tuple[str, int, datetime]] = []
    verification_current = True
    for backup, source_version, metadata in discovered:
        record = records.get(backup.name)
        if record is None:
            awaiting += 1
            verification_current = False
            continue
        if not _record_matches_file(record, metadata, source_version):
            mismatches += 1
            verification_current = False
            continue
        if not _record_is_verified(record, metadata, database_stat=database_stat):
            awaiting += 1
            verification_current = False
            continue
        created_at = _parse_time(record.get("created_at"))
        verified_at = _parse_time(record.get("verified_at"))
        if created_at is None or verified_at is None:
            mismatches += 1
            verification_current = False
            continue
        eligible_after = max(created_at, verified_at) + timedelta(
            days=MIGRATION_BACKUP_RETENTION_DAYS
        )
        if observed < eligible_after:
            recent += 1
            continue
        provisional.append((backup.name, metadata.st_size, eligible_after))

    cleanup_blocked = bool(awaiting or mismatches or not integrity_ok)
    eligible = () if cleanup_blocked else tuple(
        name
        for name, _size, _eligible_after in sorted(
            provisional,
            key=lambda item: (item[2], os.fsencode(item[0])),
        )
    )
    eligible_bytes = 0 if cleanup_blocked else sum(
        size for _name, size, _eligible_after in provisional
    )
    digest_payload = {
        "database_device": database_stat.st_dev,
        "database_inode": database_stat.st_ino,
        "database_schema_version": CURRENT_SCHEMA_VERSION,
        "integrity_ok": integrity_ok,
        "records": [
            {
                "name": backup.name,
                "source_schema_version": source_version,
                "device": metadata.st_dev,
                "inode": metadata.st_ino,
                "size": metadata.st_size,
                "mtime_ns": metadata.st_mtime_ns,
                "state": records.get(backup.name),
            }
            for backup, source_version, metadata in discovered
        ],
        "eligible": eligible,
    }
    return MigrationBackupInventory(
        total_count=len(discovered),
        total_bytes=total_bytes,
        eligible_count=len(eligible),
        eligible_bytes=eligible_bytes,
        recent_count=recent,
        awaiting_verification_count=awaiting,
        identity_mismatch_count=mismatches,
        current_database_integrity_ok=integrity_ok,
        verification_current=verification_current,
        cleanup_blocked=cleanup_blocked,
        eligible_names=eligible,
        inventory_digest=_digest(digest_payload),
    )


def delete_verified_migration_backups(
    db_path: Path,
    *,
    now: datetime,
    expected_inventory_digest: str,
    limit: int,
    cancel_check: Callable[[], bool] | None = None,
) -> MigrationBackupDeleteResult:
    """Delete a bounded, unchanged set of verified backup files."""

    if type(limit) is not int or limit < 0:
        raise MigrationBackupError("migration_backup_delete_limit_invalid")
    database = _regular_database_path(db_path)
    with migration_backup_lock(database.parent, exclusive=True, create=True):
        inventory = inventory_migration_backups(
            database,
            now=now,
            require_integrity_check=True,
            cancel_check=cancel_check,
            _lock_held=True,
        )
        if inventory.inventory_digest != expected_inventory_digest:
            raise MigrationBackupError("migration_backup_inventory_changed")
        deleted_count = 0
        deleted_bytes = 0
        state = _load_state(database.parent, missing_ok=True)
        records = _state_records(state)
        completed = True
        for name in inventory.eligible_names[:limit]:
            if cancel_check is not None and cancel_check():
                raise MigrationBackupError("migration_backup_cleanup_cancelled")
            backup = database.parent / name
            try:
                metadata = backup.stat()
            except OSError:
                completed = False
                break
            source_version = _source_version_from_name(name)
            if source_version is None or not _record_matches_file(
                records.get(name), metadata, source_version
            ):
                raise MigrationBackupError("migration_backup_inventory_changed")
            try:
                _unlink_backup(backup)
            except OSError:
                completed = False
                break
            deleted_count += 1
            deleted_bytes += metadata.st_size
            records.pop(name, None)
            # Persist every completed deletion so an interrupted process can
            # safely resume from the remaining files on its next run.
            _write_state(database.parent, state)
        return MigrationBackupDeleteResult(
            deleted_count=deleted_count,
            deleted_bytes=deleted_bytes,
            completed=completed,
        )


@contextmanager
def migration_backup_lock(
    data_dir: Path,
    *,
    exclusive: bool,
    create: bool,
) -> Iterator[None]:
    """Coordinate backup creation, verification, inventory, and deletion."""

    path = data_dir / MIGRATION_BACKUP_LOCK_FILENAME
    flags = os.O_RDWR | (os.O_CREAT if create else 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o600)
    except FileNotFoundError:
        if not create:
            raise
        raise MigrationBackupError("migration_backup_lock_unavailable")
    except OSError as exc:
        raise MigrationBackupError("migration_backup_lock_unavailable") from exc
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise MigrationBackupError("migration_backup_lock_invalid")
        if os.name == "posix":
            os.fchmod(descriptor, 0o600)
        try:
            fcntl.flock(
                descriptor,
                fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH,
            )
        except OSError as exc:
            raise MigrationBackupError(
                "migration_backup_lock_unavailable"
            ) from exc
        yield
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        except OSError:
            pass
        os.close(descriptor)


def _discover_backups(data_dir: Path) -> list[tuple[Path, int, os.stat_result]]:
    discovered: list[tuple[Path, int, os.stat_result]] = []
    try:
        entries = list(data_dir.iterdir())
    except OSError as exc:
        raise MigrationBackupError("migration_backup_inventory_failed") from exc
    for entry in entries:
        source_version = _source_version_from_name(entry.name)
        if source_version is None:
            continue
        if entry.is_symlink():
            raise MigrationBackupError("migration_backup_symlink")
        try:
            metadata = entry.stat()
        except OSError as exc:
            raise MigrationBackupError("migration_backup_inventory_failed") from exc
        if not stat.S_ISREG(metadata.st_mode):
            continue
        discovered.append((entry, source_version, metadata))
    return sorted(discovered, key=lambda item: os.fsencode(item[0].name))


def _unlink_backup(path: Path) -> None:
    path.unlink()


def _regular_backup_path(path: Path) -> Path:
    source_version = _source_version_from_name(path.name)
    if source_version is None or path.is_symlink() or not path.is_file():
        raise MigrationBackupError("migration_backup_invalid")
    return Path(os.path.abspath(os.fspath(path)))


def _regular_database_path(path: Path) -> Path:
    requested = Path(os.path.abspath(os.fspath(path)))
    if requested.is_symlink() or not requested.is_file():
        raise MigrationBackupError("migration_current_database_unavailable")
    try:
        with sqlite3.connect(
            f"{requested.resolve().as_uri()}?mode=ro", uri=True
        ) as conn:
            version_row = conn.execute("PRAGMA user_version").fetchone()
    except sqlite3.Error as exc:
        raise MigrationBackupError(
            "migration_current_database_unavailable"
        ) from exc
    version = 0 if version_row is None else int(version_row[0])
    if version != CURRENT_SCHEMA_VERSION:
        raise MigrationBackupError("migration_current_database_schema_incompatible")
    return requested


def _database_integrity_ok(
    path: Path,
    *,
    cancel_check: Callable[[], bool] | None = None,
) -> bool:
    try:
        with sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True) as conn:
            if cancel_check is not None:
                conn.set_progress_handler(lambda: int(cancel_check()), 1000)
            row = conn.execute("PRAGMA quick_check").fetchone()
    except sqlite3.Error as exc:
        if cancel_check is not None and cancel_check():
            raise MigrationBackupError("migration_backup_cleanup_cancelled") from exc
        return False
    return row is not None and row[0] == "ok"


def _record_matches_file(
    record: Any,
    metadata: os.stat_result,
    source_version: int,
) -> bool:
    return bool(
        isinstance(record, dict)
        and record.get("source_schema_version") == source_version
        and record.get("device") == metadata.st_dev
        and record.get("inode") == metadata.st_ino
        and record.get("size") == metadata.st_size
        and record.get("mtime_ns") == metadata.st_mtime_ns
    )


def _record_is_verified(
    record: Any,
    metadata: os.stat_result,
    *,
    database_stat: os.stat_result,
) -> bool:
    return bool(
        _record_matches_file(
            record,
            metadata,
            int(record.get("source_schema_version", -1))
            if isinstance(record, dict)
            else -1,
        )
        and record.get("verified_at") is not None
        and type(record.get("target_schema_version")) is int
        and type(record.get("source_schema_version")) is int
        and 0 <= record.get("source_schema_version")
        <= record.get("target_schema_version")
        == CURRENT_SCHEMA_VERSION
        and record.get("verified_database_schema_version") == CURRENT_SCHEMA_VERSION
        and record.get("verified_database_device") == database_stat.st_dev
        and record.get("verified_database_inode") == database_stat.st_ino
    )


def _load_state(data_dir: Path, *, missing_ok: bool) -> dict[str, Any]:
    path = data_dir / MIGRATION_BACKUP_STATE_FILENAME
    if path.is_symlink():
        raise MigrationBackupError("migration_backup_state_symlink")
    if not path.exists():
        if missing_ok:
            return _empty_state()
        raise MigrationBackupError("migration_backup_state_missing")
    try:
        if path.stat().st_size > _MAX_STATE_BYTES:
            raise MigrationBackupError("migration_backup_state_invalid")
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise MigrationBackupError("migration_backup_state_invalid") from exc
    if (
        not isinstance(payload, dict)
        or payload.get("schema_version") != MIGRATION_BACKUP_STATE_SCHEMA_VERSION
        or not isinstance(payload.get("backups"), dict)
    ):
        raise MigrationBackupError("migration_backup_state_invalid")
    return payload


def _write_state(data_dir: Path, state: dict[str, Any]) -> None:
    encoded = (
        json.dumps(state, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    if len(encoded) > _MAX_STATE_BYTES:
        raise MigrationBackupError("migration_backup_state_too_large")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".migration-backups.",
        suffix=".tmp",
        dir=data_dir,
    )
    temporary = Path(temporary_name)
    try:
        if os.name == "posix":
            os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            descriptor = -1
            output.write(encoded)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, data_dir / MIGRATION_BACKUP_STATE_FILENAME)
        directory_fd = os.open(data_dir, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except Exception as exc:
        if descriptor >= 0:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)
        if isinstance(exc, MigrationBackupError):
            raise
        raise MigrationBackupError("migration_backup_state_write_failed") from exc


def _empty_state() -> dict[str, Any]:
    return {
        "schema_version": MIGRATION_BACKUP_STATE_SCHEMA_VERSION,
        "backups": {},
    }


def _state_records(state: dict[str, Any]) -> dict[str, dict[str, Any]]:
    records = state.get("backups")
    if not isinstance(records, dict):
        raise MigrationBackupError("migration_backup_state_invalid")
    return records


def _discard_absent_records(
    records: dict[str, dict[str, Any]],
    discovered_names: set[str],
) -> None:
    for name in tuple(records):
        if name not in discovered_names:
            records.pop(name, None)


def _source_version_from_name(name: str) -> int | None:
    match = _BACKUP_PATTERN.fullmatch(name)
    return None if match is None else int(match.group("version"))


def _utc_now(value: datetime | None) -> datetime:
    observed = value or datetime.now(UTC)
    if observed.tzinfo is None:
        raise MigrationBackupError("migration_backup_time_timezone_required")
    return observed.astimezone(UTC)


def _format_time(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def _parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str) or re.fullmatch(
        r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
        r"(?:\.[0-9]{1,6})?Z",
        value,
    ) is None:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC)
    except ValueError:
        return None


def _digest(payload: dict[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def _runtime_version_is_safe(value: Any) -> bool:
    return bool(
        isinstance(value, str)
        and re.fullmatch(r"[0-9A-Za-z][0-9A-Za-z.+_-]{0,63}", value)
    )
