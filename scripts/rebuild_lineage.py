#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from hook_monitor.analysis.graph import (  # noqa: E402
    build_artifact_flow_edges,
    build_protected_source_resource_edges,
    build_source_binding_edges,
)
from hook_monitor.analysis.adapters.registry import run_adapters  # noqa: E402
from hook_monitor.analysis.adapters.mcp_profiles import (  # noqa: E402
    DEFAULT_MCP_PROFILE_REGISTRY,
)
from hook_monitor.analysis.lineage import propagate_lineage  # noqa: E402
from hook_monitor.analysis.query import (  # noqa: E402
    AnalysisScopeError,
    resolve_registered_workspace,
)
from hook_monitor.analysis.source_index import load_sources_and_chunks  # noqa: E402
from hook_monitor.runtime.fragments import build_artifact_fragments  # noqa: E402
from hook_monitor.runtime.source_config import DEFAULT_CONFIG_PATH  # noqa: E402
from hook_monitor.runtime.storage import EventStore  # noqa: E402


_MCP_PROFILE_GRAPH_VERSION = (
    DEFAULT_MCP_PROFILE_REGISTRY.registry_version.rsplit(":", 1)[-1][:12]
)
DETECTOR_VERSION = f"artifact-graph-v17-mcp-profiles-{_MCP_PROFILE_GRAPH_VERSION}"
GRAPH_IDENTITY_VERSION = "workspace-graph-v2"
GRAPH_FINGERPRINT_KEY = "artifact_graph_fingerprint"
GRAPH_VERSION_KEY = "artifact_graph_detector_version"


def main() -> int:
    args = _parse_args()
    store = EventStore(args.db)
    store.initialize()
    try:
        workspace = resolve_registered_workspace(store, args.workspace_root)
    except AnalysisScopeError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    assert workspace.workspace_id is not None
    assert workspace.canonical_root is not None
    workspace_id = workspace.workspace_id
    workspace_root = Path(workspace.canonical_root)

    # 旧ログにもfragmentを追加できるよう、artifactから毎回idempotentに補完する。
    artifacts = store.list_artifacts_for_workspace(workspace_id)
    fragments = [
        fragment
        for artifact in artifacts
        for fragment in build_artifact_fragments(artifact)
    ]
    store.upsert_artifact_fragments(fragments)
    contexts = store.list_artifact_contexts_for_workspace(workspace_id)
    operations = tuple(store.list_tool_operations_for_workspace(workspace_id))
    snapshots = tuple(store.list_resource_snapshots_for_workspace(workspace_id))
    adapter_result = run_adapters(
        contexts,
        workspace_root,
        operations=operations,
        snapshots=snapshots,
    )
    config_path = workspace_root / DEFAULT_CONFIG_PATH
    config_present = config_path.exists()
    if config_present:
        sources, chunks = load_sources_and_chunks(
            workspace_root,
            config_path,
            workspace_id=workspace_id,
        )
    else:
        sources = store.list_protected_sources_for_workspace(workspace_id)
        chunks = store.list_source_chunks_for_workspace(workspace_id)

    if config_present:
        store.replace_sources_for_workspace(workspace_id, sources, chunks)
    store.replace_resource_versions_for_workspace(
        workspace_id,
        list(adapter_result.resources),
    )
    store.replace_sink_candidates_for_workspace(
        workspace_id,
        list(adapter_result.sinks),
    )

    graph_fingerprint = _graph_fingerprint(contexts, operations, snapshots)
    graph_is_stale = (
        args.rebuild_graph
        or store.get_workspace_analysis_state(
            workspace_id,
            GRAPH_FINGERPRINT_KEY,
        )
        != graph_fingerprint
        or store.get_workspace_analysis_state(workspace_id, GRAPH_VERSION_KEY)
        != DETECTOR_VERSION
    )
    if graph_is_stale:
        similarity_edges = build_artifact_flow_edges(contexts)
        artifact_edges = list(similarity_edges) + list(adapter_result.edges)
        store.replace_information_flow_edges_for_workspace(
            workspace_id,
            artifact_edges,
        )
        store.set_workspace_analysis_state(
            workspace_id,
            GRAPH_FINGERPRINT_KEY,
            graph_fingerprint,
        )
        store.set_workspace_analysis_state(
            workspace_id,
            GRAPH_VERSION_KEY,
            DETECTOR_VERSION,
        )
        graph_status = "rebuilt"
    else:
        artifact_edges = store.list_information_flow_edges_for_workspace(workspace_id)
        graph_status = "reused"

    content_source_edges = build_source_binding_edges(chunks, contexts, artifact_edges)
    path_source_edges = build_protected_source_resource_edges(
        sources,
        list(adapter_result.resources),
        workspace_root,
    )
    source_edges = content_source_edges + path_source_edges

    analysis_run_id = store.start_workspace_analysis_run(
        detector_version=DETECTOR_VERSION,
        config={
            "minimum_path_score": args.minimum_path_score,
            "source_count": len(sources),
            "source_chunk_count": len(chunks),
            "graph_fingerprint": graph_fingerprint,
        },
        workspace_id=workspace_id,
    )
    store.replace_analysis_run_graph(
        analysis_run_id,
        source_edges + artifact_edges,
        coverage="full",
    )
    store.upsert_source_binding_edges(analysis_run_id, source_edges)
    assignments = propagate_lineage(
        analysis_run_id,
        source_edges + artifact_edges,
        minimum_path_score=args.minimum_path_score,
    )
    store.upsert_lineage_assignments(assignments)
    store.complete_analysis_run(analysis_run_id)

    print(
        " ".join(
            (
                f"analysis_run_id={analysis_run_id}",
                f"workspace_id={workspace_id}",
                f"graph={graph_status}",
                f"artifacts={len(artifacts)}",
                f"fragments={len(contexts)}",
                f"artifact_edges={len(artifact_edges)}",
                f"adapter_edges={len(adapter_result.edges)}",
                f"resource_versions={len(adapter_result.resources)}",
                f"sink_candidates={len(adapter_result.sinks)}",
                f"sources={len(sources)}",
                f"source_chunks={len(chunks)}",
                f"source_bindings={len(source_edges)}",
                f"lineage_assignments={len(assignments)}",
            )
        )
    )
    return 0


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="artifactグラフを構築し、protected sourceからlineageを再計算する"
    )
    parser.add_argument(
        "--db",
        type=Path,
        required=True,
        help="SQLite database path.",
    )
    parser.add_argument(
        "--workspace-root",
        type=Path,
        required=True,
        help="Registered workspace root to rebuild.",
    )
    parser.add_argument(
        "--rebuild-graph",
        action="store_true",
        help="artifactに変更がなくてもartifact間グラフを作り直す",
    )
    parser.add_argument(
        "--minimum-path-score",
        type=float,
        default=0.15,
        help="lineage伝播を継続する最小の経路score",
    )
    return parser.parse_args()


def _graph_fingerprint(contexts, operations=(), snapshots=()) -> str:
    digest = hashlib.sha256()
    digest.update(GRAPH_IDENTITY_VERSION.encode("ascii"))
    digest.update(b"\n")
    for context in contexts:
        digest.update(context.fragment.fragment_id.encode("utf-8"))
        digest.update(b"\0")
        digest.update(str(context.sequence_no).encode("ascii"))
        digest.update(b"\0")
        digest.update((context.workspace_id or "-").encode("utf-8"))
        digest.update(b"\0")
        digest.update((context.workspace_root or "-").encode("utf-8"))
        digest.update(b"\0")
        digest.update(context.workspace_status.encode("utf-8"))
        digest.update(b"\n")
    for operation in sorted(operations, key=lambda item: item.operation_id):
        for value in (
            operation.operation_id,
            operation.outcome,
            operation.outcome_evidence,
            operation.outcome_event_id,
            operation.content_fragment_id,
        ):
            digest.update((value or "-").encode("utf-8"))
            digest.update(b"\0")
        digest.update(b"\n")
    for snapshot in sorted(snapshots, key=lambda item: item.snapshot_id):
        for value in (
            snapshot.snapshot_id,
            snapshot.operation_id,
            snapshot.path_role,
            snapshot.lexical_path,
            snapshot.resource_state,
            snapshot.capture_status,
            snapshot.content_sha256,
            snapshot.error_code,
        ):
            digest.update((value or "-").encode("utf-8"))
            digest.update(b"\0")
        digest.update(b"\n")
    return digest.hexdigest()


if __name__ == "__main__":
    raise SystemExit(main())
