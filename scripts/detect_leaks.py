#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from hook_monitor.analysis.leak_detection import LeakFinding, detect_leaks  # noqa: E402
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

    if args.format == "json":
        print(_render_json(analysis_run, findings, args))
    elif args.format == "text":
        print(_render_text(analysis_run, findings, args))
    else:
        raise AssertionError(f"unsupported format: {args.format}")
    return 0


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Detect protected source lineage that reaches external sink candidates."
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
        help="Minimum lineage path score to report as a finding.",
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
    findings: list[LeakFinding],
    args: argparse.Namespace,
) -> str:
    lines = [
        f"analysis_run_id={analysis_run.analysis_run_id}",
        f"detector_version={analysis_run.detector_version}",
        f"min_score={args.min_score:.2f}",
        f"findings={len(findings)}",
    ]
    if not findings:
        return "\n".join(lines)

    lines.append("")
    for finding in findings:
        lines.extend(
            [
                f"[{finding.severity.upper()}] {finding.sink_type} "
                f"path_score={finding.path_score:.2f} hops={finding.hop_count}",
                f"source: {finding.source_node_kind}:{finding.source_node_id}",
                f"sink: sink_candidate:{finding.sink_node_id} {finding.sink_label}",
                f"reason: {finding.reason}",
                f"trace: {_trace_command(args.db, finding)}",
                "",
            ]
        )
    return "\n".join(lines).rstrip()


def _render_json(
    analysis_run: AnalysisRun,
    findings: list[LeakFinding],
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
            "findings": len(findings),
            "min_score": args.min_score,
            "source": args.source,
            "sink_types": args.sink_type or [],
            "include_final_answer": args.include_final_answer,
        },
        "findings": [_finding_to_dict(finding, args.db) for finding in findings],
    }
    return json.dumps(payload, ensure_ascii=False, indent=2)


def _finding_to_dict(finding: LeakFinding, db_path: Path) -> dict[str, object]:
    return {
        "finding_id": finding.finding_id,
        "severity": finding.severity,
        "source": {
            "kind": finding.source_node_kind,
            "id": finding.source_node_id,
        },
        "sink": {
            "id": finding.sink_node_id,
            "sink_type": finding.sink_type,
            "label": finding.sink_label,
        },
        "path_score": finding.path_score,
        "hop_count": finding.hop_count,
        "predecessor_edge_id": finding.predecessor_edge_id,
        "reason": finding.reason,
        "trace_command": _trace_command(db_path, finding),
    }


def _trace_command(db_path: Path, finding: LeakFinding) -> str:
    return (
        "python3 scripts/trace_lineage.py "
        f"--db {db_path} "
        f"--node sink_candidate:{finding.sink_node_id}"
    )


if __name__ == "__main__":
    raise SystemExit(main())
