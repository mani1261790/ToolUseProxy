#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

from hook_monitor.analysis.query import (
    AnalysisRunScope,
    AnalysisScopeError,
    matching_source_keys,
    select_analysis_run_scope,
)
from hook_monitor.runtime.models import (
    AnalysisRun,
    ArtifactContext,
    FlowEdge,
    LineageAssignment,
    ProtectedSource,
    ResourceVersion,
    SinkCandidate,
    SourceChunk,
    StoredPolicyDecision,
)
from hook_monitor.runtime.storage import DEFAULT_DB_PATH, EventStore


NodeKey = tuple[str, str]


@dataclass(frozen=True)
class TraceData:
    analysis_run: AnalysisRun
    edges_by_id: dict[str, FlowEdge]
    artifact_contexts: dict[str, ArtifactContext]
    protected_sources: dict[str, ProtectedSource]
    source_chunks: dict[str, SourceChunk]
    resource_versions: dict[str, ResourceVersion]
    sink_candidates: dict[str, SinkCandidate]
    assignments: list[LineageAssignment]


def main(
    argv: list[str] | None = None,
    *,
    default_db_path: Path | None = None,
    allow_schema_migration: bool = True,
) -> int:
    args = _parse_args(argv, default_db_path=default_db_path)
    store = EventStore(args.db)
    if allow_schema_migration:
        store.initialize()
    else:
        store.require_runtime_schema()
    decision = _load_policy_decision(store, args.decision)
    if args.decision and decision is None:
        print(f"Policy decision not found: {args.decision}", file=sys.stderr)
        return 1

    if decision is not None:
        if args.workspace_root is not None or args.latest:
            print(
                "--decision cannot be combined with --workspace-root or --latest",
                file=sys.stderr,
            )
            return 1
        if (
            args.analysis_run is not None
            and args.analysis_run != decision.analysis_run_id
        ):
            print(
                "Policy decision analysis run does not match --analysis-run: "
                f"{decision.analysis_run_id} != {args.analysis_run}",
                file=sys.stderr,
            )
            return 1
        selected_run_id = decision.analysis_run_id
    else:
        selected_run_id = args.analysis_run
    try:
        scope = select_analysis_run_scope(
            store,
            analysis_run_id=selected_run_id,
            workspace_root=args.workspace_root,
            latest=args.latest,
        )
    except AnalysisScopeError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    data = _load_trace_data(store, scope)
    if decision is not None:
        if not _decision_matches_run(data, decision):
            print(
                "Policy decision source and sink are not present in its analysis run",
                file=sys.stderr,
            )
            return 1
        return _print_decision_trace(data, args, decision)
    if args.node:
        return _print_node_trace(data, args)
    if args.source:
        return _print_source_tree(data, args)
    return _print_summary(data)


def _parse_args(
    argv: list[str] | None = None,
    *,
    default_db_path: Path | None = None,
) -> argparse.Namespace:
    effective_default_db = (
        DEFAULT_DB_PATH if default_db_path is None else default_db_path
    )
    parser = argparse.ArgumentParser(
        description="Show source lineage as a tree-like projection of the information-flow graph."
    )
    parser.add_argument(
        "--db",
        type=Path,
        default=effective_default_db,
        help=f"SQLite database path. Defaults to {effective_default_db}.",
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
        "--source",
        help="Show downstream tree for a source id, source chunk id, or protected source id.",
    )
    parser.add_argument(
        "--node",
        help="Show source-to-node paths for a node, formatted as kind:id.",
    )
    parser.add_argument(
        "--decision",
        help="Show source-to-sink paths for a stored policy decision id.",
    )
    parser.add_argument(
        "--max-depth",
        type=int,
        default=8,
        help="Maximum tree depth for --source output.",
    )
    parser.add_argument(
        "--min-score",
        type=float,
        default=0.0,
        help="Minimum lineage path score to display.",
    )
    parser.add_argument(
        "--preview-chars",
        type=int,
        default=120,
        help="Maximum preview length for text nodes.",
    )
    parser.add_argument(
        "--no-preview",
        action="store_true",
        help="Hide artifact/source text previews.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Show ids, edge reasons, and full metadata.",
    )
    return parser.parse_args(argv)


def _load_policy_decision(
    store: EventStore,
    decision_id: str | None,
) -> StoredPolicyDecision | None:
    if decision_id is None:
        return None
    return store.get_policy_decision(decision_id)


def _load_trace_data(store: EventStore, scope: AnalysisRunScope) -> TraceData:
    analysis_run = scope.analysis_run
    edges = scope.list_information_flow_edges(store)
    return TraceData(
        analysis_run=analysis_run,
        edges_by_id={edge.edge_id: edge for edge in edges},
        artifact_contexts={
            context.fragment.fragment_id: context
            for context in scope.list_artifact_contexts(store)
        },
        protected_sources={
            source.source_id: source for source in scope.list_protected_sources(store)
        },
        source_chunks={
            chunk.chunk_id: chunk for chunk in scope.list_source_chunks(store)
        },
        resource_versions={
            resource.node_id: resource
            for resource in scope.list_resource_versions(store)
        },
        sink_candidates={
            sink.node_id: sink for sink in scope.list_sink_candidates(store)
        },
        assignments=store.list_lineage_assignments(analysis_run.analysis_run_id),
    )


def _decision_matches_run(
    data: TraceData,
    decision: StoredPolicyDecision,
) -> bool:
    return any(
        assignment.source_node_kind == decision.source_node_kind
        and assignment.source_node_id == decision.source_node_id
        and assignment.node_kind == "sink_candidate"
        and assignment.node_id == decision.sink_node_id
        for assignment in data.assignments
    )


def _print_summary(data: TraceData) -> int:
    source_keys = {
        (assignment.source_node_kind, assignment.source_node_id)
        for assignment in data.assignments
    }
    reached_nodes = {
        (assignment.node_kind, assignment.node_id) for assignment in data.assignments
    }
    print(f"analysis_run_id={data.analysis_run.analysis_run_id}")
    print(f"workspace_id={data.analysis_run.workspace_id}")
    print(f"session_id={data.analysis_run.session_id or '-'}")
    print(
        f"scope_kind={'session' if data.analysis_run.session_id else 'workspace'}"
    )
    print(f"detector_version={data.analysis_run.detector_version}")
    print(f"started_at={data.analysis_run.started_at}")
    print(f"completed_at={data.analysis_run.completed_at or '-'}")
    print(f"sources_with_lineage={len(source_keys)}")
    print(f"reached_nodes={len(reached_nodes)}")
    print(f"edges_loaded={len(data.edges_by_id)}")
    print("")
    print("Sources:")
    if not source_keys:
        print("  (none)")
        return 0
    for source_key in sorted(source_keys):
        reached = sum(
            1
            for assignment in data.assignments
            if (
                assignment.source_node_kind,
                assignment.source_node_id,
            )
            == source_key
        )
        print(f"  {_node_label(source_key, data, preview_chars=0)} reached_nodes={reached}")
    return 0


def _print_source_tree(data: TraceData, args: argparse.Namespace) -> int:
    source_keys = _matching_source_keys(data, args.source)
    if not source_keys:
        print(f"No lineage source matched: {args.source}", file=sys.stderr)
        return 1

    for index, source_key in enumerate(source_keys):
        if index:
            print("")
        print(_node_label(source_key, data, args.preview_chars, args.no_preview))
        children = _children_for_source(data, source_key, args.min_score)
        _print_children(
            data=data,
            children=children,
            node=source_key,
            prefix="",
            depth=0,
            max_depth=args.max_depth,
            preview_chars=args.preview_chars,
            no_preview=args.no_preview,
            verbose=args.verbose,
            visited={source_key},
        )
    return 0


def _print_node_trace(data: TraceData, args: argparse.Namespace) -> int:
    try:
        target = _parse_node(args.node)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    assignments = [
        assignment
        for assignment in data.assignments
        if (assignment.node_kind, assignment.node_id) == target
        and assignment.best_path_score >= args.min_score
    ]
    if not assignments:
        print(f"No lineage assignment found for node: {args.node}", file=sys.stderr)
        return 1

    for index, assignment in enumerate(assignments):
        if index:
            print("")
        source_key = (assignment.source_node_kind, assignment.source_node_id)
        print(f"path_score={assignment.best_path_score:.3f} hops={assignment.hop_count}")
        path = _path_to_assignment(data, assignment)
        for step_index, (node, edge) in enumerate(path):
            connector = "  " if step_index == 0 else "->"
            print(f"{connector} {_node_label(node, data, args.preview_chars, args.no_preview)}")
            if edge is not None:
                print(f"   via {_edge_label(edge, args.verbose)}")
        if path and path[0][0] != source_key:
            print(f"   source={_node_label(source_key, data, args.preview_chars, args.no_preview)}")
    return 0


def _print_decision_trace(
    data: TraceData,
    args: argparse.Namespace,
    decision: StoredPolicyDecision,
) -> int:
    print(f"decision_id={decision.decision_id}")
    print(f"action={decision.action} severity={decision.severity}")
    print(f"analysis_run_id={decision.analysis_run_id}")
    print(f"workspace_id={data.analysis_run.workspace_id}")
    print(f"session_id={data.analysis_run.session_id or '-'}")
    print(f"sink={decision.sink_type} sink_candidate:{decision.sink_node_id}")
    print("")
    args.node = f"sink_candidate:{decision.sink_node_id}"
    return _print_node_trace(data, args)


def _matching_source_keys(data: TraceData, source: str) -> list[NodeKey]:
    return matching_source_keys(
        source_keys={
        (assignment.source_node_kind, assignment.source_node_id)
        for assignment in data.assignments
        },
        protected_sources=data.protected_sources,
        source_chunks=data.source_chunks,
        source=source,
    )


def _children_for_source(
    data: TraceData,
    source_key: NodeKey,
    min_score: float,
) -> dict[NodeKey, list[LineageAssignment]]:
    children: dict[NodeKey, list[LineageAssignment]] = defaultdict(list)
    relevant = [
        assignment
        for assignment in data.assignments
        if (assignment.source_node_kind, assignment.source_node_id) == source_key
        and assignment.best_path_score >= min_score
        and assignment.predecessor_edge_id is not None
    ]
    for assignment in relevant:
        edge = data.edges_by_id.get(assignment.predecessor_edge_id)
        if edge is None:
            continue
        children[(edge.src_node_kind, edge.src_node_id)].append(assignment)
    for siblings in children.values():
        siblings.sort(key=lambda item: (item.hop_count, item.node_kind, item.node_id))
    return children


def _print_children(
    *,
    data: TraceData,
    children: dict[NodeKey, list[LineageAssignment]],
    node: NodeKey,
    prefix: str,
    depth: int,
    max_depth: int,
    preview_chars: int,
    no_preview: bool,
    verbose: bool,
    visited: set[NodeKey],
) -> None:
    if depth >= max_depth:
        if children.get(node):
            print(f"{prefix}`- ... max depth reached")
        return

    siblings = children.get(node, [])
    for index, assignment in enumerate(siblings):
        child = (assignment.node_kind, assignment.node_id)
        edge = data.edges_by_id.get(assignment.predecessor_edge_id or "")
        is_last = index == len(siblings) - 1
        branch = "`- " if is_last else "|- "
        next_prefix = prefix + ("   " if is_last else "|  ")
        already_seen = child in visited
        suffix = " (already shown)" if already_seen else ""
        print(
            f"{prefix}{branch}{_node_label(child, data, preview_chars, no_preview)} "
            f"path_score={assignment.best_path_score:.3f}{suffix}"
        )
        if edge is not None:
            print(f"{next_prefix}via {_edge_label(edge, verbose)}")
        if already_seen:
            continue
        _print_children(
            data=data,
            children=children,
            node=child,
            prefix=next_prefix,
            depth=depth + 1,
            max_depth=max_depth,
            preview_chars=preview_chars,
            no_preview=no_preview,
            verbose=verbose,
            visited=visited | {child},
        )


def _path_to_assignment(
    data: TraceData,
    target: LineageAssignment,
) -> list[tuple[NodeKey, FlowEdge | None]]:
    source_key = (target.source_node_kind, target.source_node_id)
    assignment_by_node = {
        (assignment.node_kind, assignment.node_id): assignment
        for assignment in data.assignments
        if (
            assignment.source_node_kind,
            assignment.source_node_id,
        )
        == source_key
    }
    path: list[tuple[NodeKey, FlowEdge | None]] = []
    current = (target.node_kind, target.node_id)
    seen: set[NodeKey] = set()
    while current not in seen:
        seen.add(current)
        assignment = assignment_by_node.get(current)
        if assignment is None or assignment.predecessor_edge_id is None:
            path.append((current, None))
            break
        edge = data.edges_by_id.get(assignment.predecessor_edge_id)
        if edge is None:
            path.append((current, None))
            break
        path.append((current, edge))
        current = (edge.src_node_kind, edge.src_node_id)
        if current == source_key:
            path.append((source_key, None))
            break
    return list(reversed(path))


def _parse_node(raw: str) -> NodeKey:
    if ":" not in raw:
        raise ValueError("Node must be formatted as kind:id")
    kind, node_id = raw.split(":", 1)
    if not kind or not node_id:
        raise ValueError("Node must be formatted as kind:id")
    return kind, node_id


def _node_label(
    node: NodeKey,
    data: TraceData,
    preview_chars: int,
    no_preview: bool = False,
) -> str:
    kind, node_id = node
    if kind == "protected_source":
        source = data.protected_sources.get(node_id)
        if source is None:
            return f"protected_source:{_short_id(node_id)}"
        source_label = source.source_key or source.source_id
        return (
            f"protected_source:{source_label} path={source.path} "
            f"sensitivity={source.sensitivity}"
        )
    if kind == "source_chunk":
        chunk = data.source_chunks.get(node_id)
        if chunk is None:
            return f"source_chunk:{_short_id(node_id)}"
        source = data.protected_sources.get(chunk.source_id)
        source_label = (
            source.source_key
            if source is not None and source.source_key is not None
            else chunk.source_id
        )
        label = f"source_chunk:{source_label}#{chunk.ordinal}"
        preview = _preview(chunk.text, preview_chars, no_preview)
        return f"{label} {preview}".rstrip()
    if kind == "resource_version":
        resource = data.resource_versions.get(node_id)
        if resource is None:
            return f"resource_version:{_short_id(node_id)}"
        content_hash = _short_id(resource.content_hash or "-")
        return f"file:{resource.path} seq={resource.sequence_no} hash={content_hash}"
    if kind == "sink_candidate":
        sink = data.sink_candidates.get(node_id)
        if sink is None:
            return f"sink:{_short_id(node_id)}"
        return f"sink:{sink.sink_type} {sink.label} seq={sink.sequence_no}"
    if kind == "artifact_fragment":
        context = data.artifact_contexts.get(node_id)
        if context is None:
            return f"artifact_fragment:{_short_id(node_id)}"
        label = (
            f"{context.tool_name or '-'} {context.phase} "
            f"{context.fragment.semantic_role} seq={context.sequence_no}"
        )
        preview = _preview(context.fragment.text, preview_chars, no_preview)
        return f"{label} {preview}".rstrip()
    return f"{kind}:{_short_id(node_id)}"


def _edge_label(edge: FlowEdge, verbose: bool) -> str:
    label = (
        f"{edge.relation}/{edge.method} "
        f"evidence={edge.evidence_level} edge_score={edge.score:.3f}"
    )
    if verbose:
        return f"{label} edge_id={_short_id(edge.edge_id)} reason={edge.reason}"
    return label


def _preview(text: str, preview_chars: int, no_preview: bool) -> str:
    if no_preview or preview_chars <= 0:
        return ""
    normalized = " ".join(text.replace("\n", "\\n").split())
    if len(normalized) > preview_chars:
        normalized = normalized[: max(0, preview_chars - 3)] + "..."
    return f'preview="{normalized}"'


def _short_id(value: str) -> str:
    if len(value) <= 12:
        return value
    return value[:12]


if __name__ == "__main__":
    raise SystemExit(main())
