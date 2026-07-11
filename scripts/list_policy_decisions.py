#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from hook_monitor.runtime.models import StoredPolicyDecision  # noqa: E402
from hook_monitor.runtime.storage import DEFAULT_DB_PATH, EventStore  # noqa: E402


def main() -> int:
    args = _parse_args()
    store = EventStore(args.db)
    store.initialize()

    if args.decision:
        decision = store.get_policy_decision(args.decision)
        if decision is None:
            print(f"Policy decision not found: {args.decision}", file=sys.stderr)
            return 1
        decisions = [decision]
    else:
        decisions = store.list_policy_decisions(args.limit)

    if args.format == "json":
        print(
            json.dumps(
                {"decisions": [_to_dict(decision) for decision in decisions]},
                ensure_ascii=False,
                indent=2,
            )
        )
    else:
        print(_render_text(decisions))
    return 0


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="List stored policy decisions emitted by hook runtime."
    )
    parser.add_argument(
        "--db",
        type=Path,
        default=REPO_ROOT / DEFAULT_DB_PATH,
        help="SQLite database path. Defaults to .tooluseproxy/events.db.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=20,
        help="Maximum decisions to list.",
    )
    parser.add_argument(
        "--decision",
        help="Show one policy decision by decision id.",
    )
    parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="Output format.",
    )
    return parser.parse_args()


def _render_text(decisions: list[StoredPolicyDecision]) -> str:
    if not decisions:
        return "policy_decisions=0"

    lines = [f"policy_decisions={len(decisions)}", ""]
    for decision in decisions:
        lines.extend(
            [
                f"decision_id={decision.decision_id}",
                f"created_at={decision.created_at or '-'}",
                (
                    f"action={decision.action} severity={decision.severity} "
                    f"hook_event={decision.hook_event or '-'}"
                ),
                f"analysis_run_id={decision.analysis_run_id}",
                f"source={decision.source_node_kind}:{decision.source_node_id}",
                f"sink={decision.sink_type} sink_candidate:{decision.sink_node_id}",
                f"score={decision.path_score:.2f}",
                f"message={decision.user_message}",
                f"trace={decision.trace_command}",
                "",
            ]
        )
    return "\n".join(lines).rstrip()


def _to_dict(decision: StoredPolicyDecision) -> dict[str, object]:
    return {
        "decision_id": decision.decision_id,
        "finding_id": decision.finding_id,
        "analysis_run_id": decision.analysis_run_id,
        "hook_event": decision.hook_event,
        "action": decision.action,
        "severity": decision.severity,
        "sink_type": decision.sink_type,
        "source": {
            "kind": decision.source_node_kind,
            "id": decision.source_node_id,
        },
        "sink": {
            "id": decision.sink_node_id,
        },
        "path_score": decision.path_score,
        "reason": decision.reason,
        "user_message": decision.user_message,
        "technical_summary": decision.technical_summary,
        "trace_command": decision.trace_command,
        "path_summary": list(decision.path_summary),
        "created_at": decision.created_at,
    }


if __name__ == "__main__":
    raise SystemExit(main())
