#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from hook_monitor.analysis.leak_detection import detect_leaks  # noqa: E402
from hook_monitor.policy.codex_output import render_codex_hook_output, select_strongest_decision  # noqa: E402
from hook_monitor.policy.engine import evaluate_policy  # noqa: E402
from hook_monitor.policy.models import PolicyDecision  # noqa: E402
from hook_monitor.runtime.models import AnalysisRun, LineageAssignment, ProtectedSource, SourceChunk  # noqa: E402
from hook_monitor.runtime.storage import DEFAULT_DB_PATH, EventStore  # noqa: E402


NodeKey = tuple[str, str]


def main() -> int:
    args = _parse_args()
    store = EventStore(args.db)
    store.initialize()
    analysis_run = _select_analysis_run(store, args.analysis_run)
    if analysis_run is None:
        if args.analysis_run:
            print(f"Analysis run not found: {args.analysis_run}", file=sys.stderr)
        else:
            print(
                "No analysis runs found. Run scripts/rebuild_lineage.py first.",
                file=sys.stderr,
            )
        return 1

    assignments = store.list_lineage_assignments(analysis_run.analysis_run_id)
    source_filter = _source_filter(store, assignments, args.source)
    if args.source and not source_filter:
        print(f"No lineage source matched: {args.source}", file=sys.stderr)
        return 1

    findings = detect_leaks(
        analysis_run=analysis_run,
        assignments=assignments,
        sink_candidates=store.list_sink_candidates(),
        min_score=args.min_score,
        sink_types=set(args.sink_type or []) or None,
        included_sink_types=_included_sink_types(args),
        source_filter=source_filter,
    )
    decisions = evaluate_policy(findings)
    if args.hook_output:
        selected = select_strongest_decision(decisions, args.hook_output)
        print(json.dumps(render_codex_hook_output(selected, args.hook_output), ensure_ascii=False, indent=2))
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
        help="Analysis run id to inspect. Defaults to the latest completed run.",
    )
    parser.add_argument(
        "--latest",
        action="store_true",
        help="Inspect the latest completed analysis run. This is the default.",
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


def _select_analysis_run(
    store: EventStore,
    analysis_run_id: str | None,
) -> AnalysisRun | None:
    runs = store.list_analysis_runs()
    if analysis_run_id is not None:
        return next((run for run in runs if run.analysis_run_id == analysis_run_id), None)
    completed = [run for run in runs if run.completed_at is not None]
    return completed[0] if completed else (runs[0] if runs else None)


def _source_filter(
    store: EventStore,
    assignments: list[LineageAssignment],
    source: str | None,
) -> set[NodeKey] | None:
    if source is None:
        return None
    return set(
        _matching_source_keys(
            assignments=assignments,
            protected_sources={
                protected.source_id: protected
                for protected in store.list_protected_sources()
            },
            source_chunks={
                chunk.chunk_id: chunk
                for chunk in store.list_source_chunks()
            },
            source=source,
        )
    )


def _matching_source_keys(
    *,
    assignments: list[LineageAssignment],
    protected_sources: dict[str, ProtectedSource],
    source_chunks: dict[str, SourceChunk],
    source: str,
) -> list[NodeKey]:
    all_keys = {
        (assignment.source_node_kind, assignment.source_node_id)
        for assignment in assignments
    }
    matches: set[NodeKey] = set()
    for key in all_keys:
        kind, node_id = key
        if node_id == source or f"{kind}:{node_id}" == source:
            matches.add(key)
            continue
        if kind == "source_chunk":
            chunk = source_chunks.get(node_id)
            if chunk and chunk.source_id == source:
                matches.add(key)
    if source in protected_sources and ("protected_source", source) in all_keys:
        matches.add(("protected_source", source))
    return sorted(matches)


def _render_text(
    analysis_run: AnalysisRun,
    *,
    findings_count: int,
    decisions: list[PolicyDecision],
    args: argparse.Namespace,
) -> str:
    lines = [
        f"analysis_run_id={analysis_run.analysis_run_id}",
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
                f"trace: {_trace_command(args.db, decision)}",
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
        },
        "summary": {
            "findings": findings_count,
            "decisions": len(decisions),
            "min_score": args.min_score,
            "source": args.source,
            "sink_types": args.sink_type or [],
            "include_final_answer": args.include_final_answer,
        },
        "decisions": [_decision_to_dict(decision, args.db) for decision in decisions],
    }
    return json.dumps(payload, ensure_ascii=False, indent=2)


def _decision_to_dict(decision: PolicyDecision, db_path: Path) -> dict[str, object]:
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
        "trace_command": _trace_command(db_path, decision),
    }


def _trace_command(db_path: Path, decision: PolicyDecision) -> str:
    return (
        "python3 scripts/trace_lineage.py "
        f"--db {db_path} "
        f"--node sink_candidate:{decision.sink_node_id}"
    )


if __name__ == "__main__":
    raise SystemExit(main())
