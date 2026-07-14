from __future__ import annotations

import heapq
from collections import defaultdict

from hook_monitor.runtime.models import FlowEdge, LineageAssignment


def propagate_lineage(
    analysis_run_id: str,
    edges: list[FlowEdge],
    minimum_path_score: float = 0.15,
) -> list[LineageAssignment]:
    """source bindingから最大積経路を伝播し、各nodeの最良経路を保存する。"""
    outgoing: dict[tuple[str, str], list[FlowEdge]] = defaultdict(list)
    source_edges: dict[tuple[str, str], list[FlowEdge]] = defaultdict(list)
    for edge in edges:
        if edge.src_node_kind in {"source_chunk", "protected_source"}:
            source_edges[(edge.src_node_kind, edge.src_node_id)].append(edge)
        else:
            outgoing[(edge.src_node_kind, edge.src_node_id)].append(edge)

    assignments: list[LineageAssignment] = []
    for (source_node_kind, source_node_id), seed_edges in source_edges.items():
        best: dict[tuple[str, str], float] = {}
        predecessor: dict[tuple[str, str], str] = {}
        hops: dict[tuple[str, str], int] = {}
        queue: list[tuple[float, str, str]] = []

        for edge in seed_edges:
            node = (edge.dst_node_kind, edge.dst_node_id)
            if edge.score <= best.get(node, 0.0):
                continue
            best[node] = edge.score
            predecessor[node] = edge.edge_id
            hops[node] = 1
            heapq.heappush(queue, (-edge.score, node[0], node[1]))

        while queue:
            negative_score, node_kind, node_id = heapq.heappop(queue)
            path_score = -negative_score
            node = (node_kind, node_id)
            if path_score < best.get(node, 0.0):
                continue

            for edge in outgoing.get(node, []):
                next_node = (edge.dst_node_kind, edge.dst_node_id)
                next_score = path_score * edge.score
                if next_score < minimum_path_score:
                    continue
                if next_score <= best.get(next_node, 0.0):
                    continue
                best[next_node] = next_score
                predecessor[next_node] = edge.edge_id
                hops[next_node] = hops[node] + 1
                heapq.heappush(
                    queue,
                    (-next_score, next_node[0], next_node[1]),
                )

        assignments.extend(
            LineageAssignment(
                analysis_run_id=analysis_run_id,
                source_node_kind=source_node_kind,
                source_node_id=source_node_id,
                node_kind=node_kind,
                node_id=node_id,
                best_path_score=score,
                predecessor_edge_id=predecessor.get((node_kind, node_id)),
                hop_count=hops[(node_kind, node_id)],
            )
            for (node_kind, node_id), score in best.items()
        )
    return assignments


def propagate_lineage_incremental(
    analysis_run_id: str,
    existing_assignments: list[LineageAssignment],
    new_edges: list[FlowEdge],
    minimum_path_score: float = 0.15,
) -> list[LineageAssignment]:
    """既存の最良scoreをseedに、新しく追加されたedgeだけを伝播する。"""
    outgoing: dict[tuple[str, str], list[FlowEdge]] = defaultdict(list)
    source_edges: dict[tuple[str, str], list[FlowEdge]] = defaultdict(list)
    for edge in new_edges:
        if edge.src_node_kind in {"source_chunk", "protected_source"}:
            source_edges[(edge.src_node_kind, edge.src_node_id)].append(edge)
        else:
            outgoing[(edge.src_node_kind, edge.src_node_id)].append(edge)

    existing_by_source: dict[
        tuple[str, str],
        dict[tuple[str, str], LineageAssignment],
    ] = defaultdict(dict)
    for assignment in existing_assignments:
        existing_by_source[
            (assignment.source_node_kind, assignment.source_node_id)
        ][(assignment.node_kind, assignment.node_id)] = assignment

    changed: list[LineageAssignment] = []
    source_keys = set(existing_by_source) | set(source_edges)
    for source_node_kind, source_node_id in source_keys:
        prior = existing_by_source[(source_node_kind, source_node_id)]
        best = {node: item.best_path_score for node, item in prior.items()}
        predecessor = {node: item.predecessor_edge_id for node, item in prior.items()}
        hops = {node: item.hop_count for node, item in prior.items()}
        queue: list[tuple[float, str, str]] = []
        updated_nodes: set[tuple[str, str]] = set()

        for edge in source_edges.get((source_node_kind, source_node_id), []):
            node = (edge.dst_node_kind, edge.dst_node_id)
            if edge.score <= best.get(node, 0.0):
                continue
            best[node] = edge.score
            predecessor[node] = edge.edge_id
            hops[node] = 1
            updated_nodes.add(node)
            heapq.heappush(queue, (-edge.score, node[0], node[1]))

        for node in outgoing:
            if node in best:
                heapq.heappush(queue, (-best[node], node[0], node[1]))

        while queue:
            negative_score, node_kind, node_id = heapq.heappop(queue)
            path_score = -negative_score
            node = (node_kind, node_id)
            if path_score < best.get(node, 0.0):
                continue
            for edge in outgoing.get(node, []):
                next_node = (edge.dst_node_kind, edge.dst_node_id)
                next_score = path_score * edge.score
                if next_score < minimum_path_score:
                    continue
                if next_score <= best.get(next_node, 0.0):
                    continue
                best[next_node] = next_score
                predecessor[next_node] = edge.edge_id
                hops[next_node] = hops[node] + 1
                updated_nodes.add(next_node)
                heapq.heappush(queue, (-next_score, next_node[0], next_node[1]))

        changed.extend(
            LineageAssignment(
                analysis_run_id=analysis_run_id,
                source_node_kind=source_node_kind,
                source_node_id=source_node_id,
                node_kind=node_kind,
                node_id=node_id,
                best_path_score=best[(node_kind, node_id)],
                predecessor_edge_id=predecessor[(node_kind, node_id)],
                hop_count=hops[(node_kind, node_id)],
            )
            for node_kind, node_id in updated_nodes
        )
    return changed
