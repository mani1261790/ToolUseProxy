"""Hold a project lease for the full Hook invocation when administratively enrolled."""
from __future__ import annotations

import os
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from hook_monitor.runtime.workspace import resolve_workspace
from tooluseproxy import authority_state
from tooluseproxy.authority_state import AuthorityError, State, Target, _Store


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
