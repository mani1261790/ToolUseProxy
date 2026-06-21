#!/usr/bin/env python3
from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from hook_monitor.analysis.similarity import build_flow_edge, compare_source_chunk_to_artifact
from hook_monitor.analysis.source_index import load_sources_and_chunks
from hook_monitor.runtime.storage import DEFAULT_DB_PATH, EventStore


def main() -> int:
    store = EventStore(REPO_ROOT / DEFAULT_DB_PATH)
    store.initialize()

    sources, chunks = load_sources_and_chunks(REPO_ROOT)
    store.upsert_sources(sources, chunks)

    artifacts = store.list_artifacts()
    edges = []
    for chunk in chunks:
        for artifact in artifacts:
            decision = compare_source_chunk_to_artifact(chunk, artifact)
            if not decision.matched:
                continue
            edges.append(build_flow_edge(chunk, artifact, decision))

    store.upsert_flow_edges(edges)
    print(
        f"indexed_sources={len(sources)} indexed_chunks={len(chunks)} artifacts={len(artifacts)} flow_edges={len(edges)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
