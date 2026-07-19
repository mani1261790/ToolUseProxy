from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from itertools import groupby
from pathlib import Path

from hook_monitor.analysis.adapters.common import make_structured_edge, normalize_tool_name
from hook_monitor.analysis.bash_submission import extract_bash_http_submissions
from hook_monitor.analysis.similarity import (
    SimilarityCandidateStats,
    compare_source_binding_text,
    compare_text,
    prepare_similarity_text,
    rank_similarity_candidate_ids,
)
from hook_monitor.runtime.fragments import is_artifact_root_fragment
from hook_monitor.runtime.models import (
    ArtifactContext,
    FlowEdge,
    ProtectedSource,
    ResourceVersion,
    SourceChunk,
)


MAX_LEXICAL_CANDIDATES = 50
MAX_SOURCE_CANDIDATES = 200
ARTIFACT_SIMILARITY_MINIMUM_LENGTH = 8
SOURCE_SIMILARITY_MINIMUM_LENGTH = 4
CONTENT_BEARING_ROLES = frozenset(
    {
        "command",
        "query",
        "search_query",
        "content",
        "stdout",
        "stderr",
        "tool_output",
        "final_answer",
    }
)


def select_canonical_similarity_contexts(
    contexts: list[ArtifactContext],
) -> list[ArtifactContext]:
    """観測fragmentを保持したまま、内容比較に使う代表fragmentだけを選ぶ。"""
    selected: list[ArtifactContext] = []
    seen_payloads: set[tuple[str, str, str]] = set()
    for context in contexts:
        if not _is_similarity_context(context):
            continue
        if context.fragment.fragment_kind in {
            "artifact_root",
            "payload",
        } and not _is_mcp_argument_scalar(context):
            identity = (
                context.fragment.artifact_id,
                context.fragment.semantic_role,
                context.fragment.normalized_text,
            )
            if identity in seen_payloads:
                continue
            seen_payloads.add(identity)
        selected.append(context)
    return selected


def build_artifact_flow_edges(
    contexts: list[ArtifactContext],
) -> list[FlowEdge]:
    """source定義とは独立に、時系列上のartifact fragment間の伝播候補を作る。"""
    ordered = sorted(
        select_canonical_similarity_contexts(contexts),
        key=lambda item: (item.sequence_no, item.fragment.fragment_id),
    )
    by_id = {item.fragment.fragment_id: item for item in ordered}
    prepared_by_id = {
        item.fragment.fragment_id: prepare_similarity_text(
            item.fragment.text,
            normalized_text=item.fragment.normalized_text,
        )
        for item in ordered
    }
    exact_index: dict[tuple[tuple[str, str, str], str], str] = {}
    feature_index: dict[tuple[tuple[str, str, str], str], set[str]] = defaultdict(set)
    feature_counts = {
        fragment_id: len(prepared.candidate_features)
        for fragment_id, prepared in prepared_by_id.items()
    }
    normalized_lengths = {
        item.fragment.fragment_id: len(item.fragment.normalized_text) for item in ordered
    }
    edges: dict[tuple[str, str], FlowEdge] = {}

    for _sequence_no, sequence_contexts_iter in groupby(
        ordered,
        key=lambda item: item.sequence_no,
    ):
        sequence_contexts = list(sequence_contexts_iter)
        # Do not let fragments from the same Hook event evict prior evidence or
        # become candidates for one another. All comparisons are time-forward.
        for current in sequence_contexts:
            scope = _comparison_scope(current)
            if scope is None:
                continue
            candidate_ids = _candidate_ids(
                current,
                artifact_candidate_exact_key(
                    current,
                    prepared_by_id[current.fragment.fragment_id].primary_exact_key,
                ),
                prepared_by_id[current.fragment.fragment_id].candidate_features,
                exact_index,
                feature_index,
                feature_counts,
                normalized_lengths,
            )
            for candidate_id in candidate_ids:
                previous = by_id[candidate_id]
                edge = _compare_artifact_pair(previous, current)
                if edge is None:
                    continue
                key = (edge.src_node_id, edge.dst_node_id)
                if key not in edges or edge.score > edges[key].score:
                    edges[key] = edge

        for current in sequence_contexts:
            scope = _comparison_scope(current)
            if scope is None:
                continue
            prepared = prepared_by_id[current.fragment.fragment_id]
            exact_index[
                (
                    scope,
                    artifact_candidate_exact_key(
                        current,
                        prepared.primary_exact_key,
                    ),
                )
            ] = current.fragment.fragment_id
            if (
                normalized_lengths[current.fragment.fragment_id]
                >= ARTIFACT_SIMILARITY_MINIMUM_LENGTH
            ):
                for feature in prepared.candidate_features:
                    feature_index[(scope, feature)].add(current.fragment.fragment_id)

    return list(edges.values())


def compare_artifact_contexts(
    previous: ArtifactContext,
    current: ArtifactContext,
) -> FlowEdge | None:
    """差分解析からもfull graphと同じpair判定を使う。"""
    if not _is_similarity_context(previous) or not _is_similarity_context(current):
        return None
    if _comparison_scope(previous) != _comparison_scope(current):
        return None
    return _compare_artifact_pair(previous, current)


def build_source_binding_edges(
    source_chunks: list[SourceChunk],
    contexts: list[ArtifactContext],
    artifact_edges: list[FlowEdge] | None = None,
    *,
    target_fragment_ids: set[str] | None = None,
) -> list[FlowEdge]:
    """protected sourceを既存グラフの上流側にある一致nodeへ接続する。

    Incremental callers may include bounded predecessor contexts solely to
    suppress redundant direct bindings. ``target_fragment_ids`` keeps emitted
    edges restricted to the actual delta while those predecessors remain
    available for the same topology decision as a full rebuild.
    """
    canonical_contexts = select_canonical_similarity_contexts(contexts)
    by_id = {context.fragment.fragment_id: context for context in canonical_contexts}
    prepared_contexts = {
        context.fragment.fragment_id: prepare_similarity_text(
            context.fragment.text,
            normalized_text=context.fragment.normalized_text,
        )
        for context in canonical_contexts
    }
    exact_index: dict[tuple[str | None, str], list[str]] = defaultdict(list)
    feature_index: dict[tuple[str | None, str], set[str]] = defaultdict(set)
    bash_submission_hash_index: dict[
        tuple[str | None, str],
        set[str],
    ] = defaultdict(set)
    bash_submission_values: dict[str, tuple[str, ...]] = {}
    for context in canonical_contexts:
        prepared = prepared_contexts[context.fragment.fragment_id]
        exact_index[
            (
                context.workspace_id,
                artifact_candidate_exact_key(
                    context,
                    prepared.primary_exact_key,
                ),
            )
        ].append(context.fragment.fragment_id)
        if len(context.fragment.normalized_text) >= SOURCE_SIMILARITY_MINIMUM_LENGTH:
            for feature in prepared.candidate_features:
                feature_index[(context.workspace_id, feature)].add(context.fragment.fragment_id)
        if context.fragment.fragment_kind != "bash_segment":
            continue
        projected_values = tuple(
            value
            for projection in extract_bash_http_submissions(context.fragment.text)
            if projection.extraction == "static_values"
            for value in projection.submitted_values
        )
        if not projected_values:
            continue
        bash_submission_values[context.fragment.fragment_id] = projected_values
        for value in projected_values:
            value_hash = hashlib.sha256(value.encode("utf-8")).hexdigest()
            bash_submission_hash_index[(context.workspace_id, value_hash)].add(
                context.fragment.fragment_id
            )

    incoming_from_artifact: dict[str, set[str]] = defaultdict(set)
    for edge in artifact_edges or []:
        if edge.src_node_kind == "artifact_fragment" and edge.dst_node_kind == "artifact_fragment":
            incoming_from_artifact[edge.dst_node_id].add(edge.src_node_id)

    edges: list[FlowEdge] = []
    for chunk in source_chunks:
        chunk_workspace_id = _legacy_compatible_workspace_id(
            chunk.workspace_id,
            {context.workspace_id for context in canonical_contexts},
        )
        if chunk_workspace_id is _AMBIGUOUS_WORKSPACE:
            continue
        prepared_chunk = prepare_similarity_text(
            chunk.text,
            normalized_text=chunk.normalized_text,
        )
        candidate_ids = set(exact_index[(chunk_workspace_id, prepared_chunk.primary_exact_key)])
        candidate_ids.update(exact_index[(chunk_workspace_id, chunk.text_hash)])
        candidate_ids.update(bash_submission_hash_index[(chunk_workspace_id, chunk.text_hash)])
        if len(chunk.normalized_text) >= SOURCE_SIMILARITY_MINIMUM_LENGTH:
            overlap_counts: dict[str, int] = defaultdict(int)
            for feature in prepared_chunk.candidate_features:
                for fragment_id in feature_index[(chunk_workspace_id, feature)]:
                    overlap_counts[fragment_id] += 1
            ranked = rank_similarity_candidate_ids(
                query_feature_count=len(prepared_chunk.candidate_features),
                query_normalized_length=len(chunk.normalized_text),
                minimum_length=SOURCE_SIMILARITY_MINIMUM_LENGTH,
                candidates=(
                    SimilarityCandidateStats(
                        candidate_id=fragment_id,
                        overlap_count=overlap_count,
                        candidate_feature_count=len(
                            prepared_contexts[fragment_id].candidate_features
                        ),
                        candidate_normalized_length=len(
                            by_id[fragment_id].fragment.normalized_text
                        ),
                    )
                    for fragment_id, overlap_count in overlap_counts.items()
                    if fragment_id not in candidate_ids
                ),
                limit=MAX_SOURCE_CANDIDATES,
            )
            candidate_ids.update(ranked)

        matched: dict[str, FlowEdge] = {}
        for fragment_id in candidate_ids:
            context = by_id[fragment_id]
            if chunk.text in bash_submission_values.get(fragment_id, ()):
                matched[fragment_id] = _make_edge(
                    src_kind="source_chunk",
                    src_id=chunk.chunk_id,
                    dst_kind="artifact_fragment",
                    dst_id=context.fragment.fragment_id,
                    relation="source_binding",
                    evidence_level="content_exact",
                    method="bash_submission_exact",
                    score=1.0,
                    reason=(
                        "static curl submission operand exactly matches protected source chunk"
                    ),
                )
                continue
            if context.fragment.fragment_kind == "json_key":
                if (
                    chunk.text_hash != context.fragment.text_hash
                    or chunk.text != context.fragment.text
                ):
                    continue
                matched[fragment_id] = _make_edge(
                    src_kind="source_chunk",
                    src_id=chunk.chunk_id,
                    dst_kind="artifact_fragment",
                    dst_id=context.fragment.fragment_id,
                    relation="source_binding",
                    evidence_level="content_exact",
                    method="exact",
                    score=1.0,
                    reason="identical JSON key text hash",
                )
                continue
            decision = compare_source_binding_text(
                source_binding_signal=chunk.source_binding_signal,
                left_text=chunk.text,
                left_normalized=chunk.normalized_text,
                left_hash=chunk.text_hash,
                right_text=context.fragment.text,
                right_normalized=context.fragment.normalized_text,
                right_hash=context.fragment.text_hash,
                minimum_length=SOURCE_SIMILARITY_MINIMUM_LENGTH,
            )
            if not decision.matched:
                continue
            matched[fragment_id] = _make_edge(
                src_kind="source_chunk",
                src_id=chunk.chunk_id,
                dst_kind="artifact_fragment",
                dst_id=context.fragment.fragment_id,
                relation="source_binding",
                evidence_level=_evidence_level(decision.method),
                method=decision.method,
                score=decision.score,
                reason=decision.reason,
            )

        # 下流nodeへsourceから直接edgeを張ると中間経路が消える。
        # 一致node同士のartifact edgeで到達できるnodeはseedから除外する。
        matched_ids = set(matched)
        for fragment_id, edge in matched.items():
            matching_predecessors = incoming_from_artifact[fragment_id] & matched_ids
            if matching_predecessors and edge.method != "bash_submission_exact":
                continue
            if target_fragment_ids is not None and fragment_id not in target_fragment_ids:
                continue
            edges.append(edge)
    return edges


def build_protected_source_resource_edges(
    sources: list[ProtectedSource],
    resources: list[ResourceVersion],
    repo_root: Path,
) -> list[FlowEdge]:
    """protected sourceのpathと一致するresource versionを確定的に接続する。"""
    resources_by_path: dict[
        tuple[str | None, str],
        list[ResourceVersion],
    ] = defaultdict(list)
    for resource in resources:
        if resource.resource_state in {"deleted", "missing"}:
            continue
        resources_by_path[(resource.workspace_id, resource.path)].append(resource)

    edges: list[FlowEdge] = []
    resource_workspaces = {resource.workspace_id for resource in resources}
    for source in sources:
        source_workspace_id = _legacy_compatible_workspace_id(
            source.workspace_id,
            resource_workspaces,
        )
        if source_workspace_id is _AMBIGUOUS_WORKSPACE:
            continue
        source_path = str((repo_root / source.path).expanduser().resolve(strict=False))
        for resource in resources_by_path[(source_workspace_id, source_path)]:
            edges.append(
                make_structured_edge(
                    src_kind="protected_source",
                    src_id=source.source_id,
                    dst_kind="resource_version",
                    dst_id=resource.node_id,
                    relation="source_binding",
                    method="protected_path",
                    reason=f"protected source path matches resource path {source_path}",
                )
            )
    return edges


def _candidate_ids(
    current: ArtifactContext,
    primary_exact_key: str,
    candidate_features: frozenset[str],
    exact_index: dict[tuple[tuple[str, str, str], str], str],
    feature_index: dict[tuple[tuple[str, str, str], str], set[str]],
    feature_counts: dict[str, int],
    normalized_lengths: dict[str, int],
) -> set[str]:
    scope = _comparison_scope(current)
    query_normalized_length = len(current.fragment.normalized_text)
    if scope is None:
        return set()
    exact_candidate = exact_index.get((scope, primary_exact_key))
    if exact_candidate is not None:
        return {exact_candidate}
    if query_normalized_length < ARTIFACT_SIMILARITY_MINIMUM_LENGTH:
        return set()

    overlap_counts: dict[str, int] = defaultdict(int)
    for feature in candidate_features:
        for fragment_id in feature_index[(scope, feature)]:
            overlap_counts[fragment_id] += 1

    ranked = rank_similarity_candidate_ids(
        query_feature_count=len(candidate_features),
        query_normalized_length=query_normalized_length,
        minimum_length=ARTIFACT_SIMILARITY_MINIMUM_LENGTH,
        candidates=(
            SimilarityCandidateStats(
                candidate_id=fragment_id,
                overlap_count=overlap_count,
                candidate_feature_count=feature_counts[fragment_id],
                candidate_normalized_length=normalized_lengths[fragment_id],
            )
            for fragment_id, overlap_count in overlap_counts.items()
        ),
        limit=MAX_LEXICAL_CANDIDATES,
    )
    return set(ranked)


def artifact_candidate_exact_key(
    context: ArtifactContext,
    primary_exact_key: str,
) -> str:
    """Keep JSON-key eligibility byte-exact while other content uses v2 canonical keys."""
    if context.fragment.fragment_kind == "json_key":
        return context.fragment.text_hash
    return primary_exact_key


def _is_similarity_context(context: ArtifactContext) -> bool:
    if context.fragment.fragment_kind in {
        "operation_container",
        "operation_control",
        "operation_removed",
    }:
        return False
    if context.phase == "post_tool_use" and context.artifact_role == "tool_input":
        return False
    if not context.fragment.normalized_text:
        return False
    if context.fragment.semantic_role not in CONTENT_BEARING_ROLES and not _is_mcp_argument_scalar(
        context
    ):
        return False
    if is_artifact_root_fragment(context.fragment) and _is_json_container(context.fragment.text):
        return False
    return True


def _is_mcp_argument_scalar(context: ArtifactContext) -> bool:
    if (
        context.phase != "pre_tool_use"
        or context.artifact_role != "tool_input"
        or is_artifact_root_fragment(context.fragment)
    ):
        return False
    tool_name = context.tool_name or ""
    parts = tool_name.split("__", 2)
    if len(parts) == 3 and parts[0].lower() == "mcp" and parts[1] and parts[2]:
        return True
    if normalize_tool_name(tool_name) not in {
        "mcp",
        "mcp_call",
        "mcp_tool_call",
        "mcp_server_tool_call",
        "mcpserver_tool_call",
    }:
        return False
    return context.fragment.json_pointer.startswith(("/arguments/", "/args/", "/input/"))


def _is_json_container(text: str) -> bool:
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        return False
    return isinstance(value, (dict, list))


def _comparison_scope(context: ArtifactContext) -> tuple[str, str, str] | None:
    workspace_id = context.workspace_id or "legacy-unscoped"
    if context.session_id is not None:
        return (workspace_id, "session", context.session_id)
    if context.turn_id is not None:
        return (workspace_id, "turn", context.turn_id)
    return None


_AMBIGUOUS_WORKSPACE = object()


def _legacy_compatible_workspace_id(
    explicit_workspace_id: str | None,
    observed_workspace_ids: set[str | None],
) -> str | None | object:
    """Unscoped legacy evidence is usable only inside one unambiguous workspace."""
    if explicit_workspace_id is not None:
        return explicit_workspace_id
    if len(observed_workspace_ids) == 1:
        return next(iter(observed_workspace_ids))
    return _AMBIGUOUS_WORKSPACE


def _compare_artifact_pair(
    previous: ArtifactContext,
    current: ArtifactContext,
) -> FlowEdge | None:
    if previous.sequence_no >= current.sequence_no:
        return None
    if previous.fragment.artifact_id == current.fragment.artifact_id:
        return None

    if "json_key" in {
        previous.fragment.fragment_kind,
        current.fragment.fragment_kind,
    }:
        if (
            previous.fragment.text_hash != current.fragment.text_hash
            or previous.fragment.text != current.fragment.text
        ):
            return None
        return _make_edge(
            src_kind="artifact_fragment",
            src_id=previous.fragment.fragment_id,
            dst_kind="artifact_fragment",
            dst_id=current.fragment.fragment_id,
            relation="derived_from",
            evidence_level="content_exact",
            method="exact",
            score=1.0,
            reason="identical JSON key text hash",
        )

    decision = compare_text(
        left_text=previous.fragment.text,
        left_normalized=previous.fragment.normalized_text,
        left_hash=previous.fragment.text_hash,
        right_text=current.fragment.text,
        right_normalized=current.fragment.normalized_text,
        right_hash=current.fragment.text_hash,
        minimum_length=ARTIFACT_SIMILARITY_MINIMUM_LENGTH,
    )
    if not decision.matched:
        return None
    return _make_edge(
        src_kind="artifact_fragment",
        src_id=previous.fragment.fragment_id,
        dst_kind="artifact_fragment",
        dst_id=current.fragment.fragment_id,
        relation="derived_from" if decision.method != "shingle_jaccard" else "similar_to",
        evidence_level=_evidence_level(decision.method),
        method=decision.method,
        score=decision.score,
        reason=decision.reason,
    )


def _evidence_level(method: str) -> str:
    return {
        "exact": "content_exact",
        "substring": "content_lexical",
        "token_equivalent": "content_lexical",
        "shingle_jaccard": "content_lexical",
        "embedding_cosine": "content_semantic",
    }.get(method, "unknown")


def _make_edge(
    *,
    src_kind: str,
    src_id: str,
    dst_kind: str,
    dst_id: str,
    relation: str,
    evidence_level: str,
    method: str,
    score: float,
    reason: str,
) -> FlowEdge:
    identity = "\0".join((src_kind, src_id, dst_kind, dst_id, relation, method))
    edge_id = hashlib.sha256(identity.encode("utf-8")).hexdigest()
    return FlowEdge(
        edge_id=edge_id,
        src_node_kind=src_kind,
        src_node_id=src_id,
        dst_node_kind=dst_kind,
        dst_node_id=dst_id,
        relation=relation,
        evidence_level=evidence_level,
        method=method,
        score=score,
        reason=reason,
    )
