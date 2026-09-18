"""Project lifecycle boundaries for shared-database retention."""
from __future__ import annotations

import sqlite3
from contextlib import ExitStack, contextmanager
from dataclasses import replace
from pathlib import Path
from typing import Iterator

from tooluseproxy import authority_state
from tooluseproxy.integrations.authority import registered_workspace_authority_lease
from tooluseproxy.migration_backups import MigrationBackupInventory


def authority_installed() -> bool:
    directory = authority_state.AUTHORITY_DIRECTORY
    return directory.exists() or directory.is_symlink()


@contextmanager
def cleanup_authority_leases(database: Path, conn: sqlite3.Connection) -> Iterator[None]:
    if not authority_installed():
        conn.create_function("authority_cleanup_allowed", 1, lambda _: 1, deterministic=True)
        yield
        return
    allowed: set[str] = set()
    with ExitStack() as leases:
        for (identity,) in conn.execute("SELECT workspace_id FROM workspaces ORDER BY workspace_id"):
            with ExitStack() as candidate:
                state = candidate.enter_context(
                    registered_workspace_authority_lease(database, conn, identity)
                )
                if state is not None and state.phase != "active":
                    continue
                allowed.add(identity)
                leases.enter_context(candidate.pop_all())
        # Unknown and unscoped history has no proven project ownership. Keep it.
        conn.create_function("authority_cleanup_allowed", 1,
                             lambda identity: int(identity in allowed), deterministic=True)
        yield


def preserve_shared_backups(inventory: MigrationBackupInventory) -> MigrationBackupInventory:
    if not authority_installed():
        return inventory
    # A historical whole-database backup may contain a stopped project no longer
    # present in the current database. Its project ownership is not recorded.
    return replace(inventory, eligible_count=0, eligible_bytes=0, eligible_names=(),
                   cleanup_blocked=True)
