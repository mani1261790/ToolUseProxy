#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import shlex
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from hook_monitor.analysis.leak_detection import detect_leaks  # noqa: E402
from hook_monitor.analysis.query import (  # noqa: E402
    AnalysisRunScope,
    AnalysisScopeError,
    matching_source_keys,
    select_analysis_run_scope,
)
from hook_monitor.policy.codex_output import render_codex_hook_output, select_strongest_decision  # noqa: E402
from hook_monitor.policy.engine import evaluate_policy  # noqa: E402
from hook_monitor.policy.models import PolicyDecision  # noqa: E402
from hook_monitor.runtime.models import AnalysisRun, LineageAssignment  # noqa: E402
from hook_monitor.runtime.storage import DEFAULT_DB_PATH, EventStore  # noqa: E402


NodeKey = tuple[str, str]


def main() -> int:
    args = _parse_args()
    store = EventStore(args.db)
    store.initialize()
    try:
        scope = select_analysis_run_scope(
            store,
            analysis_run_id=args.analysis_run,
            workspace_root=args.workspace_root,
            latest=args.latest,
        )
    except AnalysisScopeError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    analysis_run = scope.analysis_run

    assignments = store.list_lineage_assignments(analysis_run.analysis_run_id)
    source_filter = _source_filter(store, scope, assignments, args.source)
    if args.source and not source_filter:
        print(f"No lineage source matched: {args.source}", file=sys.stderr)
        return 1

    findings = detect_leaks(
        analysis_run=analysis_run,
        assignments=assignments,
        sink_candidates=scope.list_sink_candidates(store),
        min_score=args.min_score,
        sink_types=set(args.sink_type or []) or None,
        included_sink_types=_included_sink_types(args),
        source_filter=source_filter,
    )
    decisions = evaluate_policy(findings)
    if args.hook_output:
        selected = select_strongest_decision(decisions, args.hook_output)
        print(
            json.dumps(
                render_codex_hook_output(
                    selected,
                    args.hook_output,
                    db_path=args.db,
                    analysis_run_id=analysis_run.analysis_run_id,
                ),
                ensure_ascii=False,
                indent=2,
            )
        )
        return 0

    if args.format == "json":
        print(_render_json(analysis_run, findings_count=len(findings), decisions=decisions, args=args))
    elif args.format == "text":
        print(_render_text(analysis_run, findings_count=len(findings), decisions=decisions, args=args))
    else:
        raise AssertionError(f"unsupported format: {args.format}")
    return 0


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Evaluate policy decisions for protected source leak findings."
    )
    parser.add_argument(
        "--db",
        type=Path,
        default=REPO_ROOT / DEFAULT_DB_PATH,
        help="SQLite database path. Defaults to .tooluseproxy/events.db.",
    )
    parser.add_argument(
        "--analysis-run",
        help="Completed workspace-scoped analysis run id to inspect.",
    )
    parser.add_argument(
        "--workspace-root",
        type=Path,
        help="Registered workspace root. Requires --latest.",
    )
    parser.add_argument(
        "--latest",
        action="store_true",
        help="Inspect the latest completed offline run for --workspace-root.",
    )
    parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="Output format.",
    )
    parser.add_argument(
        "--min-score",
        type=float,
        default=0.3,
        help="Minimum lineage path score to evaluate.",
    )
    parser.add_argument(
        "--source",
        help="Limit findings to a source id, source chunk id, or source node id.",
    )
    parser.add_argument(
        "--sink-type",
        action="append",
        help="Limit findings to a sink type. Can be provided multiple times.",
    )
    parser.add_argument(
        "--include-final-answer",
        action="store_true",
        help="Include final_answer sink candidates in addition to external_* sinks.",
    )
    parser.add_argument(
        "--hook-output",
        choices=("PreToolUse", "PermissionRequest", "PostToolUse", "Stop"),
        help="Render the strongest matching decision as Codex hook stdout JSON.",
    )
    return parser.parse_args()


def _included_sink_types(args: argparse.Namespace) -> set[str] | None:
    included = set()
    if args.include_final_answer:
        included.add("final_answer")
    return included or None


def _source_filter(
    store: EventStore,
    scope: AnalysisRunScope,
    assignments: list[LineageAssignment],
    source: str | None,
) -> set[NodeKey] | None:
    if source is None:
        return None
    return set(
        matching_source_keys(
            source_keys={
                (assignment.source_node_kind, assignment.source_node_id)
                for assignment in assignments
            },
            protected_sources={
                protected.source_id: protected
                for protected in scope.list_protected_sources(store)
            },
            source_chunks={
                chunk.chunk_id: chunk
                for chunk in scope.list_source_chunks(store)
            },
            source=source,
        )
    )


def _render_text(
    analysis_run: AnalysisRun,
    *,
    findings_count: int,
    decisions: list[PolicyDecision],
    args: argparse.Namespace,
) -> str:
    lines = [
        f"analysis_run_id={analysis_run.analysis_run_id}",
        f"workspace_id={analysis_run.workspace_id}",
        f"session_id={analysis_run.session_id or '-'}",
        f"scope_kind={'session' if analysis_run.session_id else 'workspace'}",
        f"detector_version={analysis_run.detector_version}",
        f"min_score={args.min_score:.2f}",
        f"findings={findings_count}",
        f"decisions={len(decisions)}",
    ]
    if not decisions:
        return "\n".join(lines)

    lines.append("")
    for decision in decisions:
        lines.extend(
            [
                f"[{decision.action.upper()}] {decision.sink_type} "
                f"severity={decision.severity} score={decision.path_score:.2f}",
                f"source: {decision.source_node_kind}:{decision.source_node_id}",
                f"sink: sink_candidate:{decision.sink_node_id}",
                f"reason: {decision.reason}",
                f"hook_event: {decision.hook_event or '-'}",
                f"trace: {_trace_command(args.db, analysis_run.analysis_run_id, decision)}",
                "",
            ]
        )
    return "\n".join(lines).rstrip()


def _render_json(
    analysis_run: AnalysisRun,
    *,
    findings_count: int,
    decisions: list[PolicyDecision],
    args: argparse.Namespace,
) -> str:
    payload = {
        "analysis_run": {
            "analysis_run_id": analysis_run.analysis_run_id,
            "detector_version": analysis_run.detector_version,
            "started_at": analysis_run.started_at,
            "completed_at": analysis_run.completed_at,
            "workspace_id": analysis_run.workspace_id,
            "session_id": analysis_run.session_id,
            "scope_kind": "session" if analysis_run.session_id else "workspace",
        },
        "summary": {
            "findings": findings_count,
            "decisions": len(decisions),
            "min_score": args.min_score,
            "source": args.source,
            "sink_types": args.sink_type or [],
            "include_final_answer": args.include_final_answer,
        },
        "decisions": [
            _decision_to_dict(decision, args.db, analysis_run.analysis_run_id)
            for decision in decisions
        ],
    }
    return json.dumps(payload, ensure_ascii=False, indent=2)


def _decision_to_dict(
    decision: PolicyDecision,
    db_path: Path,
    analysis_run_id: str,
) -> dict[str, object]:
    return {
        "decision_id": decision.decision_id,
        "action": decision.action,
        "severity": decision.severity,
        "finding_id": decision.finding_id,
        "sink_type": decision.sink_type,
        "source": {
            "kind": decision.source_node_kind,
            "id": decision.source_node_id,
        },
        "sink": {
            "id": decision.sink_node_id,
        },
        "path_score": decision.path_score,
        "hook_event": decision.hook_event,
        "reason": decision.reason,
        "trace_command": _trace_command(db_path, analysis_run_id, decision),
    }


def _trace_command(
    db_path: Path,
    analysis_run_id: str,
    decision: PolicyDecision,
) -> str:
    return shlex.join(
        (
            "python3",
            "scripts/trace_lineage.py",
            "--db",
            str(db_path),
            "--analysis-run",
            analysis_run_id,
            "--node",
            f"sink_candidate:{decision.sink_node_id}",
        )
    )


if __name__ == "__main__":
    raise SystemExit(main())
