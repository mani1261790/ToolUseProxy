from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from pathlib import Path

from hook_monitor.analysis.adapters.base import AdapterResult
from hook_monitor.analysis.adapters.common import make_structured_edge
from hook_monitor.runtime.models import ArtifactContext, FlowEdge, ResourceVersion


class FilesystemAdapter:
    """Filesystem read/writeの構造をresource version付きedgeへ変換する。"""

    name = "filesystem"

    _READ_NAMES = {
        "read",
        "read_file",
        "readfile",
        "read_text_file",
        "fs_read_file",
        "fs_readfile",
        "filesystem_read_file",
        "filesystem_read_text_file",
    }
    _WRITE_NAMES = {
        "write",
        "write_file",
        "writefile",
        "write_text_file",
        "fs_write_file",
        "fs_writefile",
        "filesystem_write_file",
        "filesystem_write_text_file",
    }

    def analyze(
        self,
        contexts: list[ArtifactContext],
        repo_root: Path,
    ) -> AdapterResult:
        groups = _group_tool_calls(contexts)
        latest_by_session_path: dict[tuple[str | None, str], ResourceVersion] = {}
        edges: list[FlowEdge] = []
        resources: dict[str, ResourceVersion] = {}

        for group in groups:
            operation = self._operation(group[0].tool_name)
            if operation is None:
                continue

            path_context = _select_path_context(group)
            if path_context is None:
                continue
            path = _normalize_path(path_context.fragment.text, path_context.cwd, repo_root)
            sequence_no = min(context.sequence_no for context in group)
            session_id = group[0].session_id
            tool_use_id = group[0].tool_use_id
            resource_key = (session_id, path)

            if operation == "write":
                content_contexts = _select_content_contexts(group, phase="pre_tool_use")
                if not content_contexts:
                    content_contexts = _select_content_contexts(
                        group,
                        phase="post_tool_use",
                    )
                if not content_contexts:
                    continue
                content_hash = _combined_content_hash(content_contexts)
                resource = _make_resource_version(
                    path=path,
                    content_hash=content_hash,
                    sequence_no=sequence_no,
                    session_id=session_id,
                    tool_use_id=tool_use_id,
                )
                resources[resource.node_id] = resource
                latest_by_session_path[resource_key] = resource
                edges.extend(
                    make_structured_edge(
                        src_kind="artifact_fragment",
                        src_id=context.fragment.fragment_id,
                        dst_kind="resource_version",
                        dst_id=resource.node_id,
                        relation="written_to",
                        method="filesystem_write",
                        reason=f"filesystem write content to {path}",
                    )
                    for context in content_contexts
                )
                continue

            output_contexts = _select_output_contexts(group)
            if not output_contexts:
                continue
            output_hash = _combined_content_hash(output_contexts)
            resource = latest_by_session_path.get(resource_key)
            if resource is None or (
                resource.content_hash is not None and resource.content_hash != output_hash
            ):
                resource = _make_resource_version(
                    path=path,
                    content_hash=output_hash,
                    sequence_no=sequence_no,
                    session_id=session_id,
                    tool_use_id=tool_use_id,
                )
                latest_by_session_path[resource_key] = resource
            resources[resource.node_id] = resource
            edges.extend(
                make_structured_edge(
                    src_kind="resource_version",
                    src_id=resource.node_id,
                    dst_kind="artifact_fragment",
                    dst_id=context.fragment.fragment_id,
                    relation="read_from",
                    method="filesystem_read",
                    reason=f"filesystem read output from {path}",
                )
                for context in output_contexts
            )

        return AdapterResult(tuple(edges), tuple(resources.values()))

    def _operation(self, tool_name: str | None) -> str | None:
        if not tool_name:
            return None
        normalized = re.sub(r"[^a-z0-9]+", "_", tool_name.lower()).strip("_")
        if normalized in self._READ_NAMES:
            return "read"
        if normalized in self._WRITE_NAMES:
            return "write"
        return None


def _group_tool_calls(
    contexts: list[ArtifactContext],
) -> list[list[ArtifactContext]]:
    grouped: dict[tuple[str | None, str | None], list[ArtifactContext]] = defaultdict(list)
    for context in contexts:
        # tool_use_idがないevent同士を誤ってまとめないようevent_idをfallbackにする。
        identity = context.tool_use_id or context.event_id
        grouped[(context.session_id, identity)].append(context)
    return sorted(
        grouped.values(),
        key=lambda group: min(context.sequence_no for context in group),
    )


def _select_path_context(
    group: list[ArtifactContext],
) -> ArtifactContext | None:
    paths = [
        context
        for context in group
        if context.fragment.semantic_role == "path"
        and context.fragment.json_pointer != "/"
    ]
    if not paths:
        return None
    return min(paths, key=lambda context: context.sequence_no)


def _select_content_contexts(
    group: list[ArtifactContext],
    phase: str,
) -> list[ArtifactContext]:
    return _prefer_leaf_fragments(
        [
            context
            for context in group
            if context.phase == phase
            and context.fragment.semantic_role == "content"
        ]
    )


def _select_output_contexts(
    group: list[ArtifactContext],
) -> list[ArtifactContext]:
    candidates = [
        context
        for context in group
        if context.phase == "post_tool_use"
        and context.artifact_role == "tool_output"
        and context.fragment.semantic_role
        in {"content", "stdout", "tool_output"}
    ]
    return _prefer_leaf_fragments(candidates)


def _prefer_leaf_fragments(
    contexts: list[ArtifactContext],
) -> list[ArtifactContext]:
    leaves = [context for context in contexts if context.fragment.json_pointer != "/"]
    return leaves or contexts


def _normalize_path(path: str, cwd: str | None, repo_root: Path) -> str:
    candidate = Path(path).expanduser()
    if not candidate.is_absolute():
        base = Path(cwd).expanduser() if cwd else repo_root
        candidate = base / candidate
    return str(candidate.resolve(strict=False))


def _combined_content_hash(contexts: list[ArtifactContext]) -> str:
    digest = hashlib.sha256()
    for context in sorted(contexts, key=lambda item: item.fragment.fragment_id):
        digest.update(context.fragment.text.encode("utf-8"))
        digest.update(b"\0")
    return digest.hexdigest()


def _make_resource_version(
    *,
    path: str,
    content_hash: str | None,
    sequence_no: int,
    session_id: str | None,
    tool_use_id: str | None,
) -> ResourceVersion:
    identity = "\0".join(
        (
            session_id or "-",
            path,
            content_hash or "-",
            str(sequence_no),
            tool_use_id or "-",
        )
    )
    node_id = hashlib.sha256(identity.encode("utf-8")).hexdigest()
    return ResourceVersion(
        node_id=node_id,
        path=path,
        content_hash=content_hash,
        sequence_no=sequence_no,
        session_id=session_id,
        origin_tool_use_id=tool_use_id,
    )
