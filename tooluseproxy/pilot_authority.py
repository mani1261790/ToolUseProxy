"""Bind a multi-project comparison to every participant's lifecycle lease."""
from __future__ import annotations

import json
import re
import sqlite3
from contextlib import ExitStack, contextmanager
from pathlib import Path
from typing import Iterator

from tooluseproxy import authority_state
from tooluseproxy.authority_state import AuthorityError
from tooluseproxy.integrations.authority import registered_workspace_authority_lease


@contextmanager
def comparison_authority_lease(
    database: Path, connection: sqlite3.Connection, comparison_id: str,
) -> Iterator[bool]:
    directory = authority_state.AUTHORITY_DIRECTORY
    if not directory.exists() and not directory.is_symlink():
        yield True
        return
    row = connection.execute(
        "SELECT report_json FROM pilot_comparisons WHERE comparison_id = ?", (comparison_id,),
    ).fetchone()
    try:
        projects = json.loads(row[0])["projects"] if row is not None else None
        if not isinstance(projects, list) or len(projects) < 2:
            raise ValueError("missing participants")
        aliases = [item["project"] for item in projects]
        if any(not isinstance(alias, str) or not re.fullmatch(r"project_[1-9][0-9]{0,8}", alias)
               for alias in aliases) or len(set(aliases)) != len(aliases):
            raise ValueError("invalid participants")
    except (ValueError, TypeError, KeyError, RecursionError) as exc:
        raise AuthorityError("authority_comparison_unresolved") from exc
    with ExitStack() as leases:
        for alias in sorted(aliases):
            row = connection.execute(
                "SELECT workspace_id FROM pilot_project_aliases WHERE alias_number = ?",
                (int(alias.removeprefix("project_")),),
            ).fetchone()
            if row is None:
                raise AuthorityError("authority_comparison_unresolved")
            state = leases.enter_context(
                registered_workspace_authority_lease(database, connection, str(row[0]))
            )
            if state is not None and state.phase != "active":
                yield False
                return
        yield True
