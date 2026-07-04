#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from hook_monitor.analysis.graph import (
    build_artifact_flow_edges,
    build_protected_source_resource_edges,
    build_source_binding_edges,
)
from hook_monitor.analysis.adapters.registry import run_adapters
from hook_monitor.analysis.lineage import propagate_lineage
from hook_monitor.analysis.source_index import load_sources_and_chunks
from hook_monitor.runtime.fragments import build_artifact_fragments
from hook_monitor.runtime.storage import DEFAULT_DB_PATH, EventStore


DETECTOR_VERSION = "artifact-graph-v2-filesystem-adapter"
GRAPH_FINGERPRINT_KEY = "artifact_graph_fingerprint"
GRAPH_VERSION_KEY = "artifact_graph_detector_version"


def main() -> int:
    args = _parse_args()
    store = EventStore(REPO_ROOT / DEFAULT_DB_PATH)
    store.initialize()

    # 旧ログにもfragmentを追加できるよう、artifactから毎回idempotentに補完する。
    artifacts = store.list_artifacts()
    fragments = [
        fragment
        for artifact in artifacts
        for fragment in build_artifact_fragments(artifact)
    ]
    store.upsert_artifact_fragments(fragments)
    contexts = store.list_artifact_contexts()
    adapter_result = run_adapters(contexts, REPO_ROOT)
    store.replace_resource_versions(list(adapter_result.resources))

    graph_fingerprint = _graph_fingerprint(contexts)
    graph_is_stale = (
        args.rebuild_graph
        or store.get_analysis_state(GRAPH_FINGERPRINT_KEY) != graph_fingerprint
        or store.get_analysis_state(GRAPH_VERSION_KEY) != DETECTOR_VERSION
    )
    if graph_is_stale:
        similarity_edges = build_artifact_flow_edges(contexts)
        artifact_edges = list(similarity_edges) + list(adapter_result.edges)
        store.replace_information_flow_edges(artifact_edges)
        store.set_analysis_state(GRAPH_FINGERPRINT_KEY, graph_fingerprint)
        store.set_analysis_state(GRAPH_VERSION_KEY, DETECTOR_VERSION)
        graph_status = "rebuilt"
    else:
        artifact_edges = store.list_information_flow_edges()
        graph_status = "reused"

    sources, chunks = load_sources_and_chunks(REPO_ROOT)
    store.upsert_sources(sources, chunks)
    content_source_edges = build_source_binding_edges(chunks, contexts, artifact_edges)
    path_source_edges = build_protected_source_resource_edges(
        sources,
        list(adapter_result.resources),
        REPO_ROOT,
    )
    source_edges = content_source_edges + path_source_edges

    analysis_run_id = store.start_analysis_run(
        detector_version=DETECTOR_VERSION,
        config={
            "minimum_path_score": args.minimum_path_score,
            "source_count": len(sources),
            "source_chunk_count": len(chunks),
            "graph_fingerprint": graph_fingerprint,
        },
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
                f"graph={graph_status}",
                f"artifacts={len(artifacts)}",
                f"fragments={len(contexts)}",
                f"artifact_edges={len(artifact_edges)}",
                f"adapter_edges={len(adapter_result.edges)}",
                f"resource_versions={len(adapter_result.resources)}",
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


def _graph_fingerprint(contexts) -> str:
    digest = hashlib.sha256()
    for context in contexts:
        digest.update(context.fragment.fragment_id.encode("utf-8"))
        digest.update(b"\0")
        digest.update(str(context.sequence_no).encode("ascii"))
        digest.update(b"\n")
    return digest.hexdigest()


if __name__ == "__main__":
    raise SystemExit(main())
