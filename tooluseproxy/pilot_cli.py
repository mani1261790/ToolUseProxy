"""Local feedback commands with no free-text payload option."""

from __future__ import annotations

import argparse
import json
import sqlite3
import os
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path

from hook_monitor.runtime.pilot_models import CauseCategory, ReviewState
from hook_monitor.runtime.pilot_review import (
    REVIEW_CHOICES, PilotReview, problem_history, review_history,
    reviewed_observations, save_miss, save_review,
)


def add_pilot_parser(subparsers) -> None:
    pilot = subparsers.add_parser("pilot", help="操作評価の確認・訂正をローカルに保存する")
    commands = pilot.add_subparsers(dest="pilot_command", required=True)
    for name in ("pending", "recent", "history", "comparisons", "outbox", "sync", "configure-sync", "review", "amend", "report-miss", "reproduce-miss"):
        parser = commands.add_parser(name)
        parser.add_argument("--workspace", type=Path, default=Path.cwd())
        paths = parser.add_mutually_exclusive_group()
        paths.add_argument("--db", type=Path)
        paths.add_argument("--data-dir", type=Path)
        parser.add_argument("--json", action="store_true")
        if name in ("pending", "recent", "history", "comparisons", "outbox", "sync"):
            parser.add_argument("--limit", type=int, default=20)
        elif name != "configure-sync":
            parser.add_argument("observation_id")
            parser.add_argument("--request-id", required=True,
                                help="再実行でも同じ識別子を使用する")
            parser.add_argument("--cause", choices=[str(item) for item in CauseCategory],
                                default=str(CauseCategory.UNIDENTIFIED))
        if name in ("review", "amend"):
            parser.add_argument("choice", choices=[str(item) for item in REVIEW_CHOICES])
        if name in ("amend", "reproduce-miss"):
            parser.add_argument("--previous-id", required=True)
        if name == "report-miss":
            parser.add_argument("--previous-id")
        if name == "reproduce-miss":
            parser.add_argument("--artificial-reproduction-confirmed", action="store_true",
                                required=True, help="人工データでの再現を確認した場合だけ指定する")
        if name == "sync":
            parser.add_argument("--repository", default=os.environ.get("TOOLUSEPROXY_PILOT_ISSUE_REPOSITORY"))
        if name == "configure-sync":
            parser.add_argument("--repository", required=True)
            parser.add_argument("--enabled", required=True, choices=("on", "off"))


def run_pilot(args: argparse.Namespace) -> int:
    from tooluseproxy.cli import _resolve_config_context

    try:
        store, workspace, _ = _resolve_config_context(args)
        workspace_id = workspace.workspace_id
        assert workspace_id is not None
        command = args.pilot_command
        if command == "configure-sync":
            from hook_monitor.runtime.pilot_outbox import configure_sync

            configure_sync(store.db_path, repository=args.repository, enabled=args.enabled == "on")
            print(json.dumps({"status": "ok", "enabled": args.enabled == "on"}))
            return 0
        if command == "sync":
            from tooluseproxy.pilot_worker import SyncFailure, sync_pending
            from hook_monitor.runtime.pilot_outbox import sync_configuration

            try:
                repository = args.repository or sync_configuration(store.db_path)[0]
                payload = sync_pending(store.db_path, repository=repository, limit=args.limit)
            except SyncFailure as error:
                payload = {"status": "pending", "error": error.code}
            print(json.dumps(payload, ensure_ascii=False))
            return 0 if payload["status"] == "ok" else 1
        if command in ("pending", "recent", "history", "comparisons", "outbox"):
            if not 1 <= args.limit <= 100:
                raise ValueError("limit must be between 1 and 100")
            if command == "outbox":
                with sqlite3.connect(store.db_path.resolve().as_uri() + "?mode=ro", uri=True) as conn:
                    conn.row_factory = sqlite3.Row
                    payload = {"outbox": [dict(row) for row in conn.execute(
                        "SELECT delivery_key, state, issue_number, last_error FROM pilot_issue_outbox "
                        "ORDER BY rowid DESC LIMIT ?", (args.limit,))]}
                    payload["preparations"] = {row[0]: row[1] for row in conn.execute(
                        "SELECT state, COUNT(*) FROM pilot_issue_preparations GROUP BY state")}
            elif command == "comparisons":
                from hook_monitor.runtime.pilot_stop import list_comparisons

                payload = {"comparisons": list_comparisons(store.db_path)[-args.limit:]}
            elif command == "history":
                payload = {
                    "reviews": [asdict(item) for item in review_history(
                        store.db_path, workspace_id=workspace_id)[-args.limit:]],
                    "problems": [asdict(item) for item in problem_history(
                        store.db_path, workspace_id=workspace_id)[-args.limit:]],
                }
            else:
                items = reviewed_observations(store.db_path, workspace_id=workspace_id)
                if command == "pending":
                    items = tuple(item for item in items if item.review_state == ReviewState.PENDING)
                payload = {"observations": [asdict(item) for item in items[-args.limit:]]}
        elif command in ("review", "amend"):
            item = PilotReview(
                args.request_id, args.observation_id, ReviewState(args.choice),
                CauseCategory(args.cause), args.previous_id if command == "amend" else None,
                datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            )
            save_review(store.db_path, workspace_id=workspace_id, review=item)
            payload = {"review_id": item.review_id, "choice": item.choice}
        else:
            item = save_miss(
                store.db_path, workspace_id=workspace_id, observation_id=args.observation_id,
                request_id=args.request_id, cause=CauseCategory(args.cause),
                previous_id=args.previous_id,
                reproduced=command == "reproduce-miss",
                artificial_reproduction_confirmed=command == "reproduce-miss",
            )
            payload = {"problem_event_id": item.problem_event_id, "symptom": item.symptom}
    except (ValueError, OSError, sqlite3.Error) as error:
        # Context errors can include paths; do not include them in feedback output.
        print(json.dumps({"status": "failed", "error_type": type(error).__name__}))
        return 1
    print(json.dumps({"status": "ok", **payload}, ensure_ascii=False))
    return 0
