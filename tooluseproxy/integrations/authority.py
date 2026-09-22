"""Hold a project lease for the full Hook invocation when administratively enrolled."""
from __future__ import annotations

import os
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from tooluseproxy.engine.workspace import make_workspace_id, resolve_workspace
from tooluseproxy import authority_state
from tooluseproxy.authority_state import AuthorityError, State, Target, _Store


@contextmanager
def registered_workspace_authority_lease(
    database: Path, connection: sqlite3.Connection, workspace_id: str,
) -> Iterator[State | None]:
    """Lease an already registered worker target without scanning its sources."""
    directory = authority_state.AUTHORITY_DIRECTORY
    if not directory.exists() and not directory.is_symlink():
        yield None
        return
    if database.name != "events.db":
        raise AuthorityError("authority_database_identity_unsupported")
    row = connection.execute(
        "SELECT canonical_root FROM workspaces WHERE workspace_id = ?", (workspace_id,)
    ).fetchone()
    if row is None or not isinstance(row[0], str) or make_workspace_id(row[0]) != workspace_id:
        raise AuthorityError("authority_workspace_unresolved")
    target = Target(os.getuid(), row[0], str(database.parent.resolve()))
    with _Store(directory).lease(target) as state:
        yield state


@contextmanager
def workspace_authority_lease(database: Path, cwd: str | None) -> Iterator[State | None]:
    directory = authority_state.AUTHORITY_DIRECTORY
    # No installation means legacy behavior, not a claim of independent
    # authorization. Once installed, malformed storage must fail closed.
    if not directory.exists() and not directory.is_symlink():
        yield None
        return
    if database.name != "events.db":
        raise AuthorityError("authority_database_identity_unsupported")
    execution = resolve_workspace(cwd)
    if not execution.ready:
        execution = resolve_workspace(os.getcwd())
    if not execution.ready or execution.canonical_root is None:
        raise AuthorityError("authority_workspace_unresolved")
    store = _Store(directory)
    candidate = Path(execution.canonical_root)
    data_dir = str(database.parent.resolve())
    while True:
        target = Target(os.getuid(), str(candidate), data_dir)
        with store.lease(target) as state:
            if state is not None:
                yield state
                return
        # Match the activation boundary: an independent nested repository must
        # never inherit its parent's administrative deactivation.
        if (candidate / ".git").exists() or (candidate / ".git").is_symlink():
            break
        if candidate.parent == candidate:
            break
        candidate = candidate.parent
    yield None
