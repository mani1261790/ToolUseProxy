#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


from hook_monitor.analysis.query import (  # noqa: E402
    AnalysisScopeError,
    resolve_registered_workspace,
)
from hook_monitor.runtime.storage import EventStore  # noqa: E402


_RFC3339_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"
    r"(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$"
)


def main() -> int:
    args = _parse_args()
    if not args.db.is_file():
        print(f"Database not found: {args.db}", file=sys.stderr)
        return 1

    store = EventStore(args.db)
    try:
        workspace = resolve_registered_workspace(store, args.workspace_root)
        assert workspace.workspace_id is not None
        assert workspace.canonical_root is not None
        result = store.cleanup_redaction_audits(
            workspace_id=workspace.workspace_id,
            before=args.before,
            session_id=args.session,
            execute=args.execute,
        )
    except (
        AnalysisScopeError,
        OSError,
        RuntimeError,
        sqlite3.Error,
        ValueError,
    ) as exc:
        print(str(exc), file=sys.stderr)
        return 1

    print(
        json.dumps(
            {
                "mode": "execute" if result.executed else "dry-run",
                "workspace": workspace.canonical_root,
                "before": result.before,
                "session": result.session_id,
                "plans": result.plan_count,
                "targets": result.target_count,
                "decision_links": result.decision_link_count,
                "orphans": result.orphan_plan_count,
            },
            ensure_ascii=False,
            separators=(",", ":"),
        )
    )
    return 0


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Count or delete redaction audits selected by their owning "
            "PreToolUse event scope."
        )
    )
    parser.add_argument(
        "--db",
        type=Path,
        required=True,
        help="Existing SQLite database path.",
    )
    parser.add_argument(
        "--workspace-root",
        type=Path,
        required=True,
        help="Exact registered workspace root to clean.",
    )
    parser.add_argument(
        "--before",
        type=_canonical_utc_cutoff,
        required=True,
        help=(
            "Timezone-aware RFC3339 event cutoff. It is converted to UTC "
            "seconds; fractional seconds are truncated."
        ),
    )
    parser.add_argument(
        "--session",
        type=_non_empty_session,
        help="Optionally restrict cleanup to one session.",
    )
    parser.add_argument(
        "--execute",
        action="store_true",
        help="Delete matching audits. Without this flag, only count them.",
    )
    return parser.parse_args()


def _canonical_utc_cutoff(value: str) -> str:
    if not _RFC3339_RE.fullmatch(value) or value.endswith("-00:00"):
        raise argparse.ArgumentTypeError(
            "--before must be timezone-aware RFC3339 with Z or a numeric offset"
        )
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
        if parsed.utcoffset() is None:
            raise ValueError
        utc = parsed.astimezone(timezone.utc).replace(microsecond=0)
    except (OverflowError, ValueError) as exc:
        raise argparse.ArgumentTypeError(
            "--before must be a valid timezone-aware RFC3339 timestamp"
        ) from exc
    return utc.strftime("%Y-%m-%d %H:%M:%S")


def _non_empty_session(value: str) -> str:
    if not value:
        raise argparse.ArgumentTypeError("--session must not be empty")
    return value


if __name__ == "__main__":
    raise SystemExit(main())
