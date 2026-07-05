#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from hook_monitor.runtime.models import (  # noqa: E402
    AnalysisRun,
    ArtifactContext,
    FlowEdge,
    LineageAssignment,
    ProtectedSource,
    ResourceVersion,
    SinkCandidate,
    SourceChunk,
)
from hook_monitor.runtime.storage import DEFAULT_DB_PATH, EventStore  # noqa: E402


NodeKey = tuple[str, str]


@dataclass(frozen=True)
class GraphData:
    analysis_run: AnalysisRun
    edges: list[FlowEdge]
    artifact_contexts: dict[str, ArtifactContext]
    protected_sources: dict[str, ProtectedSource]
    source_chunks: dict[str, SourceChunk]
    resource_versions: dict[str, ResourceVersion]
    sink_candidates: dict[str, SinkCandidate]
    assignments: list[LineageAssignment]


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

    data = _load_graph_data(store, analysis_run)
    selected_nodes, selected_edges = _select_graph(data, args)
    if args.format == "mermaid":
        output = _render_mermaid(
            data,
            selected_nodes,
            selected_edges,
            args.preview_chars,
            args.no_preview,
        )
    elif args.format == "dot":
        output = _render_dot(
            data,
            selected_nodes,
            selected_edges,
            args.preview_chars,
            args.no_preview,
        )
    elif args.format == "json":
        output = _render_json(
            data,
            selected_nodes,
            selected_edges,
            args.preview_chars,
            args.no_preview,
        )
    else:
        raise AssertionError(f"unsupported format: {args.format}")
    _write_output(output, args.output)
    return 0


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Export the information-flow graph to Mermaid, DOT, or JSON."
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
        choices=("mermaid", "dot", "json"),
        default="mermaid",
        help="Output format.",
    )
    parser.add_argument(
        "--lineage-only",
        action="store_true",
        default=True,
        help="Export only nodes and edges used by lineage assignments. This is the default.",
    )
    parser.add_argument(
        "--all-edges",
        action="store_true",
        help="Export all information-flow and source-binding edges for the run.",
    )
    parser.add_argument(
        "--source",
        help="Limit output to a source id, source chunk id, or protected source id.",
    )
    parser.add_argument(
        "--min-score",
        type=float,
        default=0.0,
        help="Minimum lineage path score to include.",
    )
    parser.add_argument(
        "--preview-chars",
        type=int,
        default=56,
        help="Maximum preview length in node labels.",
    )
    parser.add_argument(
        "--no-preview",
        action="store_true",
        help="Hide source and artifact text previews from labels.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Write output to this path instead of stdout.",
    )
    return parser.parse_args()


def _select_analysis_run(
    store: EventStore,
    analysis_run_id: str | None,
) -> AnalysisRun | None:
    runs = store.list_analysis_runs()
    if analysis_run_id is not None:
        return next((run for run in runs if run.analysis_run_id == analysis_run_id), None)
    completed = [run for run in runs if run.completed_at is not None]
    return completed[0] if completed else (runs[0] if runs else None)


def _load_graph_data(store: EventStore, analysis_run: AnalysisRun) -> GraphData:
    artifact_edges = store.list_information_flow_edges()
    source_edges = store.list_source_binding_edges(analysis_run.analysis_run_id)
    return GraphData(
        analysis_run=analysis_run,
        edges=source_edges + artifact_edges,
        artifact_contexts={
            context.fragment.fragment_id: context
            for context in store.list_artifact_contexts()
        },
        protected_sources={
            source.source_id: source for source in store.list_protected_sources()
        },
        source_chunks={chunk.chunk_id: chunk for chunk in store.list_source_chunks()},
        resource_versions={
            resource.node_id: resource for resource in store.list_resource_versions()
        },
        sink_candidates={sink.node_id: sink for sink in store.list_sink_candidates()},
        assignments=store.list_lineage_assignments(analysis_run.analysis_run_id),
    )


def _select_graph(
    data: GraphData,
    args: argparse.Namespace,
) -> tuple[set[NodeKey], list[FlowEdge]]:
    edges_by_id = {edge.edge_id: edge for edge in data.edges}
    source_filter = _matching_source_keys(data, args.source) if args.source else None
    if args.source and not source_filter:
        raise SystemExit(f"No lineage source matched: {args.source}")
    source_filter_set = set(source_filter or [])
    assignments = [
        assignment
        for assignment in data.assignments
        if assignment.best_path_score >= args.min_score
        and (
            source_filter is None
            or (
                assignment.source_node_kind,
                assignment.source_node_id,
            )
            in source_filter_set
        )
    ]

    if args.all_edges:
        lineage_nodes = _lineage_nodes(assignments)
        if source_filter is None:
            selected_edges = list(data.edges)
        else:
            selected_edges = [
                edge
                for edge in data.edges
                if (edge.src_node_kind, edge.src_node_id) in lineage_nodes
                or (edge.dst_node_kind, edge.dst_node_id) in lineage_nodes
            ]
        nodes: set[NodeKey] = set(lineage_nodes)
        for edge in selected_edges:
            nodes.add((edge.src_node_kind, edge.src_node_id))
            nodes.add((edge.dst_node_kind, edge.dst_node_id))
        selected_edges.sort(
            key=lambda edge: (
                _node_sort_key((edge.src_node_kind, edge.src_node_id), data),
                _node_sort_key((edge.dst_node_kind, edge.dst_node_id), data),
                edge.relation,
                edge.method,
            )
        )
        return nodes, selected_edges

    nodes = _lineage_nodes(assignments)
    edge_ids = {
        assignment.predecessor_edge_id
        for assignment in assignments
        if assignment.predecessor_edge_id is not None
    }
    selected_edges = [
        edges_by_id[edge_id] for edge_id in edge_ids if edge_id in edges_by_id
    ]
    selected_edges.sort(
        key=lambda edge: (
            _node_sort_key((edge.src_node_kind, edge.src_node_id), data),
            _node_sort_key((edge.dst_node_kind, edge.dst_node_id), data),
            edge.relation,
            edge.method,
        )
    )
    return nodes, selected_edges


def _lineage_nodes(assignments: list[LineageAssignment]) -> set[NodeKey]:
    nodes = {
        (assignment.source_node_kind, assignment.source_node_id)
        for assignment in assignments
    }
    nodes.update((assignment.node_kind, assignment.node_id) for assignment in assignments)
    return nodes


def _matching_source_keys(data: GraphData, source: str) -> list[NodeKey]:
    all_keys = {
        (assignment.source_node_kind, assignment.source_node_id)
        for assignment in data.assignments
    }
    matches: set[NodeKey] = set()
    for key in all_keys:
        kind, node_id = key
        if node_id == source or f"{kind}:{node_id}" == source:
            matches.add(key)
            continue
        if kind == "source_chunk":
            chunk = data.source_chunks.get(node_id)
            if chunk and chunk.source_id == source:
                matches.add(key)
    if source in data.protected_sources and ("protected_source", source) in all_keys:
        matches.add(("protected_source", source))
    return sorted(matches)


def _render_mermaid(
    data: GraphData,
    nodes: set[NodeKey],
    edges: list[FlowEdge],
    preview_chars: int,
    no_preview: bool,
) -> str:
    lines = [
        "flowchart TD",
        "  classDef protected fill:#ffd6d6,stroke:#b91c1c,color:#111827;",
        "  classDef source fill:#ffe4e6,stroke:#e11d48,color:#111827;",
        "  classDef resource fill:#dbeafe,stroke:#2563eb,color:#111827;",
        "  classDef artifact fill:#dcfce7,stroke:#16a34a,color:#111827;",
        "  classDef sink fill:#ffedd5,stroke:#f97316,color:#111827;",
        "  classDef unknown fill:#f3f4f6,stroke:#6b7280,color:#111827;",
    ]
    for node in sorted(nodes, key=lambda item: _node_sort_key(item, data)):
        lines.append(
            f"  {_node_id(node)}[{_quote_mermaid_label(_node_label(node, data, preview_chars, no_preview))}]"
        )
        lines.append(f"  class {_node_id(node)} {_node_class(node[0])};")
    for edge in edges:
        src = _node_id((edge.src_node_kind, edge.src_node_id))
        dst = _node_id((edge.dst_node_kind, edge.dst_node_id))
        label = _quote_mermaid_edge_label(_edge_label(edge))
        lines.append(f"  {src} -->|{label}| {dst}")
    return "\n".join(lines)


def _render_dot(
    data: GraphData,
    nodes: set[NodeKey],
    edges: list[FlowEdge],
    preview_chars: int,
    no_preview: bool,
) -> str:
    lines = [
        "digraph information_flow {",
        '  rankdir="LR";',
        '  graph [fontname="Helvetica"];',
        '  node [shape=box, style="rounded,filled", fontname="Helvetica"];',
        '  edge [fontname="Helvetica"];',
    ]
    for node in sorted(nodes, key=lambda item: _node_sort_key(item, data)):
        attrs = {
            "label": _node_label(node, data, preview_chars, no_preview),
            "fillcolor": _dot_fill(node[0]),
            "color": _dot_color(node[0]),
        }
        lines.append(f"  {_node_id(node)} [{_dot_attrs(attrs)}];")
    for edge in edges:
        attrs = {
            "label": _edge_label(edge),
            "color": _edge_color(edge.evidence_level),
            "style": _edge_style(edge.evidence_level),
        }
        src = _node_id((edge.src_node_kind, edge.src_node_id))
        dst = _node_id((edge.dst_node_kind, edge.dst_node_id))
        lines.append(f"  {src} -> {dst} [{_dot_attrs(attrs)}];")
    lines.append("}")
    return "\n".join(lines)


def _render_json(
    data: GraphData,
    nodes: set[NodeKey],
    edges: list[FlowEdge],
    preview_chars: int,
    no_preview: bool,
) -> str:
    payload = {
        "analysis_run": {
            "analysis_run_id": data.analysis_run.analysis_run_id,
            "detector_version": data.analysis_run.detector_version,
            "started_at": data.analysis_run.started_at,
            "completed_at": data.analysis_run.completed_at,
        },
        "nodes": [
            {
                "kind": kind,
                "id": node_id,
                "label": _node_label((kind, node_id), data, preview_chars, no_preview),
            }
            for kind, node_id in sorted(nodes, key=lambda item: _node_sort_key(item, data))
        ],
        "edges": [
            {
                "edge_id": edge.edge_id,
                "src": {
                    "kind": edge.src_node_kind,
                    "id": edge.src_node_id,
                },
                "dst": {
                    "kind": edge.dst_node_kind,
                    "id": edge.dst_node_id,
                },
                "relation": edge.relation,
                "evidence_level": edge.evidence_level,
                "method": edge.method,
                "score": edge.score,
                "reason": edge.reason,
            }
            for edge in edges
        ],
    }
    return json.dumps(payload, ensure_ascii=False, indent=2)


def _node_label(
    node: NodeKey,
    data: GraphData,
    preview_chars: int,
    no_preview: bool,
) -> str:
    kind, node_id = node
    if kind == "protected_source":
        source = data.protected_sources.get(node_id)
        if source is None:
            return f"protected_source:{_short_id(node_id)}"
        return f"protected_source:{source.source_id}\\n{source.path}"
    if kind == "source_chunk":
        chunk = data.source_chunks.get(node_id)
        if chunk is None:
            return f"source_chunk:{_short_id(node_id)}"
        return _join_label_parts(
            f"source_chunk:{chunk.source_id}#{chunk.ordinal}",
            _preview(chunk.text, preview_chars, no_preview),
        )
    if kind == "resource_version":
        resource = data.resource_versions.get(node_id)
        if resource is None:
            return f"resource_version:{_short_id(node_id)}"
        return f"file\\n{resource.path}\\nseq={resource.sequence_no}"
    if kind == "sink_candidate":
        sink = data.sink_candidates.get(node_id)
        if sink is None:
            return f"sink:{_short_id(node_id)}"
        return f"sink:{sink.sink_type}\\n{sink.label}\\nseq={sink.sequence_no}"
    if kind == "artifact_fragment":
        context = data.artifact_contexts.get(node_id)
        if context is None:
            return f"artifact_fragment:{_short_id(node_id)}"
        return _join_label_parts(
            f"{context.tool_name or '-'} {context.phase}",
            f"{context.fragment.semantic_role} seq={context.sequence_no}",
            _preview(context.fragment.text, preview_chars, no_preview),
        )
    return f"{kind}:{_short_id(node_id)}"


def _edge_label(edge: FlowEdge) -> str:
    return f"{edge.relation}/{edge.method} {edge.score:.2f}"


def _node_sort_key(node: NodeKey, data: GraphData) -> tuple[int, int, str, str]:
    kind, node_id = node
    kind_order = {
        "protected_source": 0,
        "source_chunk": 1,
        "resource_version": 2,
        "artifact_fragment": 3,
        "sink_candidate": 4,
    }.get(kind, 9)
    sequence = 0
    if kind == "resource_version":
        resource = data.resource_versions.get(node_id)
        sequence = resource.sequence_no if resource else 0
    elif kind == "artifact_fragment":
        context = data.artifact_contexts.get(node_id)
        sequence = context.sequence_no if context else 0
    elif kind == "sink_candidate":
        sink = data.sink_candidates.get(node_id)
        sequence = sink.sequence_no if sink else 0
    return (sequence, kind_order, kind, node_id)


def _node_id(node: NodeKey) -> str:
    raw = f"{node[0]}_{node[1]}"
    return "n_" + re.sub(r"[^A-Za-z0-9_]", "_", raw)


def _node_class(kind: str) -> str:
    return {
        "protected_source": "protected",
        "source_chunk": "source",
        "resource_version": "resource",
        "artifact_fragment": "artifact",
        "sink_candidate": "sink",
    }.get(kind, "unknown")


def _quote_mermaid_label(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _quote_mermaid_edge_label(value: str) -> str:
    return value.replace("|", "/").replace("\n", " ")


def _dot_attrs(attrs: dict[str, str]) -> str:
    return ", ".join(f'{key}="{_escape_dot(value)}"' for key, value in attrs.items())


def _escape_dot(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _dot_fill(kind: str) -> str:
    return {
        "protected_source": "#ffd6d6",
        "source_chunk": "#ffe4e6",
        "resource_version": "#dbeafe",
        "artifact_fragment": "#dcfce7",
        "sink_candidate": "#ffedd5",
    }.get(kind, "#f3f4f6")


def _dot_color(kind: str) -> str:
    return {
        "protected_source": "#b91c1c",
        "source_chunk": "#e11d48",
        "resource_version": "#2563eb",
        "artifact_fragment": "#16a34a",
        "sink_candidate": "#f97316",
    }.get(kind, "#6b7280")


def _edge_color(evidence_level: str) -> str:
    return {
        "structured": "#111827",
        "content_exact": "#7c3aed",
        "content_lexical": "#6b7280",
        "content_semantic": "#0891b2",
    }.get(evidence_level, "#9ca3af")


def _edge_style(evidence_level: str) -> str:
    return "dashed" if evidence_level == "content_lexical" else "solid"


def _join_label_parts(*parts: str) -> str:
    return "\\n".join(part for part in parts if part)


def _preview(text: str, preview_chars: int, no_preview: bool) -> str:
    if no_preview or preview_chars <= 0:
        return ""
    normalized = " ".join(text.replace("\n", "\\n").split())
    if len(normalized) > preview_chars:
        normalized = normalized[: max(0, preview_chars - 3)] + "..."
    return normalized


def _write_output(output: str, output_path: Path | None) -> None:
    if output_path is None:
        print(output)
        return
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(output + "\n", encoding="utf-8")


def _short_id(value: str) -> str:
    if len(value) <= 12:
        return value
    return value[:12]


if __name__ == "__main__":
    raise SystemExit(main())
