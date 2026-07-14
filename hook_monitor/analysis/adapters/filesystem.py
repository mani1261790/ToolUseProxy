from __future__ import annotations

import hashlib
import os
import re
import stat
from collections import defaultdict
from pathlib import Path
from typing import Optional

from hook_monitor.analysis.adapters.base import AdapterResult
from hook_monitor.analysis.adapters.common import make_structured_edge, normalize_tool_name
from hook_monitor.analysis.bash_file_parser import parse_bash_command_plan
from hook_monitor.analysis.patch_parser import PatchOperation, parse_apply_patch
from hook_monitor.runtime.models import (
    ArtifactContext,
    FlowEdge,
    ResourceSnapshot,
    ResourceVersion,
    ToolOperation,
)
from hook_monitor.runtime.operations import (
    apply_patch_operation_kind,
    bash_segment_fragment_ids,
    make_operation_id,
)


_OperationLookup = dict[
    tuple[str, str, int],
    ToolOperation,
]
_ResourceLookup = dict[
    tuple[Optional[str], Optional[str], str],
    ResourceVersion,
]


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
    _APPLY_PATCH_NAME = "apply_patch"
    _BASH_NAMES = {
        "bash",
        "shell",
        "exec",
        "command",
        "terminal",
        "run_command",
    }

    def analyze(
        self,
        contexts: list[ArtifactContext],
        repo_root: Path,
    ) -> AdapterResult:
        return self._analyze_with_resources(contexts, repo_root, (), (), ())

    def analyze_with_evidence(
        self,
        contexts: list[ArtifactContext],
        repo_root: Path,
        operations: tuple[ToolOperation, ...],
        snapshots: tuple[ResourceSnapshot, ...],
    ) -> AdapterResult:
        return self._analyze_with_resources(
            contexts,
            repo_root,
            (),
            operations,
            snapshots,
        )

    def analyze_incremental(
        self,
        contexts: list[ArtifactContext],
        repo_root: Path,
        existing_resources: tuple[ResourceVersion, ...],
        operations: tuple[ToolOperation, ...] = (),
        snapshots: tuple[ResourceSnapshot, ...] = (),
    ) -> AdapterResult:
        return self._analyze_with_resources(
            contexts,
            repo_root,
            existing_resources,
            operations,
            snapshots,
        )

    def _analyze_with_resources(
        self,
        contexts: list[ArtifactContext],
        repo_root: Path,
        existing_resources: tuple[ResourceVersion, ...],
        operations: tuple[ToolOperation, ...],
        snapshots: tuple[ResourceSnapshot, ...],
    ) -> AdapterResult:
        groups = _group_tool_calls(contexts)
        outcome_event_by_operation = {
            operation.operation_id: operation.outcome_event_id
            for operation in operations
        }
        operations_by_identity: _OperationLookup = {
            (
                operation.event_id,
                operation.adapter,
                operation.operation_index,
            ): operation
            for operation in operations
        }
        snapshots_by_operation_role = {
            (snapshot.operation_id, snapshot.path_role): snapshot
            for snapshot in snapshots
            if (
                not outcome_event_by_operation
                or (
                    snapshot.operation_id in outcome_event_by_operation
                    and outcome_event_by_operation[snapshot.operation_id]
                    in {None, snapshot.post_event_id}
                )
            )
        }
        latest_by_workspace_session_path: _ResourceLookup = {}
        for resource in sorted(
            existing_resources,
            key=lambda item: (
                item.sequence_no,
                -1 if item.operation_index is None else item.operation_index,
                item.node_id,
            ),
        ):
            key = (resource.workspace_id, resource.session_id, resource.path)
            if resource.resource_state in {"deleted", "missing"}:
                latest_by_workspace_session_path.pop(key, None)
            else:
                latest_by_workspace_session_path[key] = resource
        edges: list[FlowEdge] = []
        resources: dict[str, ResourceVersion] = {}

        for group in groups:
            normalized_tool_name = normalize_tool_name(group[0].tool_name)
            if normalized_tool_name == self._APPLY_PATCH_NAME:
                self._analyze_apply_patch(
                    group,
                    repo_root,
                    latest_by_workspace_session_path,
                    resources,
                    edges,
                    snapshots_by_operation_role,
                    operations_by_identity,
                )
                continue
            if normalized_tool_name in self._BASH_NAMES:
                self._analyze_bash_filesystem(
                    group,
                    repo_root,
                    latest_by_workspace_session_path,
                    resources,
                    edges,
                    snapshots_by_operation_role,
                    operations_by_identity,
                )
                continue
            operation = self._operation(group[0].tool_name)
            if operation is None:
                continue

            path_context = _select_path_context(group)
            if path_context is None:
                continue
            path = _normalize_path(path_context.fragment.text, path_context, repo_root)
            if path is None:
                continue
            sequence_no = min(context.sequence_no for context in group)
            workspace_id = group[0].workspace_id
            session_id = group[0].session_id
            tool_use_id = group[0].tool_use_id
            resource_key = (workspace_id, session_id, path)

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
                    workspace_id=workspace_id,
                    content_hash=content_hash,
                    sequence_no=sequence_no,
                    session_id=session_id,
                    tool_use_id=tool_use_id,
                )
                resources[resource.node_id] = resource
                latest_by_workspace_session_path[resource_key] = resource
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
            resource = latest_by_workspace_session_path.get(resource_key)
            if resource is None or (
                resource.content_hash is not None and resource.content_hash != output_hash
            ):
                resource = _make_resource_version(
                    path=path,
                    workspace_id=workspace_id,
                    content_hash=output_hash,
                    sequence_no=sequence_no,
                    session_id=session_id,
                    tool_use_id=tool_use_id,
                )
                latest_by_workspace_session_path[resource_key] = resource
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

    def _analyze_bash_filesystem(
        self,
        group: list[ArtifactContext],
        repo_root: Path,
        latest_by_workspace_session_path: _ResourceLookup,
        resources: dict[str, ResourceVersion],
        edges: list[FlowEdge],
        snapshots_by_operation_role: dict[
            tuple[str, str], ResourceSnapshot
        ],
        operations_by_identity: _OperationLookup,
    ) -> None:
        command_context = _select_command_context(group)
        if command_context is None:
            return
        plan = parse_bash_command_plan(command_context.fragment.text)
        if plan is None:
            return
        operations = [
            operation
            for segment in plan.segments
            for operation in segment.operations
        ]
        if not operations:
            return
        segment_ids = bash_segment_fragment_ids(command_context.fragment, plan)
        segment_contexts = {
            context.fragment.fragment_id: context
            for context in group
            if context.phase == "pre_tool_use"
            and context.fragment.fragment_kind == "bash_segment"
        }

        workspace_id = group[0].workspace_id
        session_id = group[0].session_id
        tool_use_id = group[0].tool_use_id
        pre_sequence_no = command_context.sequence_no
        post_contexts = [
            context for context in group if context.phase == "post_tool_use"
        ]
        stored_outcome = (
            _stored_tool_outcome(
                operations_by_identity,
                event_id=command_context.event_id,
                session_id=session_id,
                tool_use_id=tool_use_id,
                adapter="bash",
            )
            if post_contexts
            else None
        )
        succeeded = (
            stored_outcome == "succeeded"
            if stored_outcome is not None
            else bool(post_contexts) and _bash_succeeded(group)
        )
        outputs = _select_output_contexts(group) if succeeded else []

        for index, operation in enumerate(operations):
            operation_context = segment_contexts.get(
                segment_ids.get(operation.segment_index, ""),
                command_context,
            )
            path = _normalize_path(operation.path, operation_context, repo_root)
            if path is None:
                continue
            resource_key = (workspace_id, session_id, path)
            previous = latest_by_workspace_session_path.get(resource_key)
            source_path = operation.path if operation.operation == "read" else None
            target_path = None if operation.operation == "read" else operation.path
            stored_operation = _validated_stored_operation(
                operations_by_identity,
                event_id=command_context.event_id,
                session_id=session_id,
                tool_use_id=tool_use_id,
                adapter="bash",
                operation_index=index,
                operation_kind=operation.operation,
                source_path=source_path,
                target_path=target_path,
                segment_index=operation.segment_index,
            )
            operation_id = (
                stored_operation.operation_id
                if stored_operation is not None
                else make_operation_id(
                    event_id=command_context.event_id,
                    adapter="bash",
                    operation_index=index,
                    operation_kind=operation.operation,
                    source_path=source_path,
                    target_path=target_path,
                    segment_index=operation.segment_index,
                )
            )
            operation_index = (
                index
                if stored_operation is None
                else stored_operation.operation_index
            )
            connector = (
                plan.segments[operation.segment_index].connector_from
                if stored_operation is None
                else stored_operation.connector
            )

            if operation.operation == "read":
                resource = previous or _make_resource_version(
                    path=path,
                    workspace_id=workspace_id,
                    content_hash=None,
                    sequence_no=pre_sequence_no,
                    session_id=session_id,
                    tool_use_id=tool_use_id,
                    version_tag=f"bash_read:{index}:{operation.path}",
                )
                resources[resource.node_id] = resource
                latest_by_workspace_session_path[resource_key] = resource
                edges.append(
                    make_structured_edge(
                        src_kind="resource_version",
                        src_id=resource.node_id,
                        dst_kind="artifact_fragment",
                        dst_id=operation_context.fragment.fragment_id,
                        relation="read_by",
                        method="bash_file_read",
                        reason=f"Bash command reads {path}",
                    )
                )
                if operation.output_is_file_content:
                    edges.extend(
                        make_structured_edge(
                            src_kind="resource_version",
                            src_id=resource.node_id,
                            dst_kind="artifact_fragment",
                            dst_id=output.fragment.fragment_id,
                            relation="read_from",
                            method="bash_cat_output",
                            reason=f"Bash cat output reads {path}",
                        )
                        for output in outputs
                    )
                continue

            if connector in {"and_then", "or_else"}:
                # Post全体の成功だけでは条件付きsegmentの実行を確定できない。
                # snapshot statusがbounded captureで省略されてもwriteを断定しない。
                continue
            if not succeeded:
                continue
            post_sequence_no = max(context.sequence_no for context in post_contexts)
            snapshot = snapshots_by_operation_role.get((operation_id, "target"))
            if not _snapshot_materializable(
                snapshot,
                operation_context,
                expected_path=path,
                expected_requested_path=operation.path,
            ):
                continue
            resource_path = _snapshot_path(
                snapshot,
                path,
                operation_context,
                expected_requested_path=operation.path,
            )
            resource = _make_resource_version(
                path=resource_path,
                workspace_id=workspace_id,
                content_hash=_snapshot_hash(snapshot),
                sequence_no=post_sequence_no,
                session_id=session_id,
                tool_use_id=tool_use_id,
                version_tag=(
                    f"bash_{operation.operation}:{index}:{operation.path}:"
                    f"fd={operation.file_descriptor}:segment={operation.segment_index}"
                ),
                operation_id=operation_id,
                operation_index=operation_index,
                snapshot_id=None if snapshot is None else snapshot.snapshot_id,
                resource_state=_snapshot_state(snapshot),
            )
            resources[resource.node_id] = resource
            resource_key = (workspace_id, session_id, resource_path)
            _record_latest_resource(
                latest_by_workspace_session_path,
                resource_key,
                resource,
            )
            edges.append(
                make_structured_edge(
                    src_kind="artifact_fragment",
                    src_id=operation_context.fragment.fragment_id,
                    dst_kind="resource_version",
                    dst_id=resource.node_id,
                    relation="written_to",
                    method=f"bash_{operation.operation}",
                    reason=f"Bash command writes {path}",
                )
            )
            if (
                operation.operation == "append"
                and previous is not None
                and previous.node_id != resource.node_id
            ):
                edges.append(
                    make_structured_edge(
                        src_kind="resource_version",
                        src_id=previous.node_id,
                        dst_kind="resource_version",
                        dst_id=resource.node_id,
                        relation="updated_from",
                        method="bash_append",
                        reason=f"Bash append preserves previous content of {path}",
                    )
                )

    def _analyze_apply_patch(
        self,
        group: list[ArtifactContext],
        repo_root: Path,
        latest_by_workspace_session_path: _ResourceLookup,
        resources: dict[str, ResourceVersion],
        edges: list[FlowEdge],
        snapshots_by_operation_role: dict[
            tuple[str, str], ResourceSnapshot
        ],
        operations_by_identity: _OperationLookup,
    ) -> None:
        command_context = _select_apply_patch_command(group)
        if command_context is None:
            return
        post_contexts = [
            context for context in group if context.phase == "post_tool_use"
        ]
        if not post_contexts:
            return
        workspace_id = group[0].workspace_id
        session_id = group[0].session_id
        tool_use_id = group[0].tool_use_id
        stored_outcome = _stored_tool_outcome(
            operations_by_identity,
            event_id=command_context.event_id,
            session_id=session_id,
            tool_use_id=tool_use_id,
            adapter="apply_patch",
        )
        succeeded = (
            stored_outcome == "succeeded"
            if stored_outcome is not None
            else _apply_patch_succeeded(group)
        )
        if not succeeded:
            return
        operations = parse_apply_patch(command_context.fragment.text)
        if not operations:
            return

        sequence_no = max(context.sequence_no for context in post_contexts)
        for index, operation in enumerate(operations):
            operation_kind = apply_patch_operation_kind(operation)
            source_path = None if operation.operation == "add" else operation.path
            target_path = (
                None
                if operation.operation == "delete"
                else operation.move_to or operation.path
            )
            stored_operation = _validated_stored_operation(
                operations_by_identity,
                event_id=command_context.event_id,
                session_id=session_id,
                tool_use_id=tool_use_id,
                adapter="apply_patch",
                operation_index=index,
                operation_kind=operation_kind,
                source_path=source_path,
                target_path=target_path,
                segment_index=None,
            )
            operation_id = (
                stored_operation.operation_id
                if stored_operation is not None
                else make_operation_id(
                    event_id=command_context.event_id,
                    adapter="apply_patch",
                    operation_index=index,
                    operation_kind=operation_kind,
                    source_path=source_path,
                    target_path=target_path,
                )
            )
            operation_index = (
                index
                if stored_operation is None
                else stored_operation.operation_index
            )
            self._apply_patch_operation(
                operation=operation,
                operation_index=operation_index,
                operation_id=operation_id,
                command_context=command_context,
                operation_content_context=_select_operation_fragment(
                    group,
                    operation_id,
                    "operation_added",
                ),
                operation_control_context=_select_operation_fragment(
                    group,
                    operation_id,
                    "operation_control",
                ),
                repo_root=repo_root,
                sequence_no=sequence_no,
                workspace_id=workspace_id,
                session_id=session_id,
                tool_use_id=tool_use_id,
                latest_by_workspace_session_path=latest_by_workspace_session_path,
                resources=resources,
                edges=edges,
                source_snapshot=snapshots_by_operation_role.get(
                    (operation_id, "source")
                ),
                target_snapshot=snapshots_by_operation_role.get(
                    (operation_id, "target")
                ),
            )

    def _apply_patch_operation(
        self,
        *,
        operation: PatchOperation,
        operation_index: int,
        operation_id: str,
        command_context: ArtifactContext,
        operation_content_context: ArtifactContext | None,
        operation_control_context: ArtifactContext | None,
        repo_root: Path,
        sequence_no: int,
        workspace_id: str | None,
        session_id: str | None,
        tool_use_id: str | None,
        latest_by_workspace_session_path: _ResourceLookup,
        resources: dict[str, ResourceVersion],
        edges: list[FlowEdge],
        source_snapshot: ResourceSnapshot | None,
        target_snapshot: ResourceSnapshot | None,
    ) -> None:
        source_path = _normalize_path(operation.path, command_context, repo_root)
        if source_path is None:
            return
        source_key = (workspace_id, session_id, source_path)
        previous = latest_by_workspace_session_path.get(source_key)
        if operation.move_to is not None and previous is None:
            # move-only patchは追加本文を持たない。Pre時点のsource resourceを
            # 合成し、protected pathから移動先へのlineageを切らさない。
            previous = _make_resource_version(
                path=source_path,
                workspace_id=workspace_id,
                content_hash=None,
                sequence_no=command_context.sequence_no,
                session_id=session_id,
                tool_use_id=tool_use_id,
                version_tag=f"apply_patch:{operation_index}:move:source",
                operation_id=operation_id,
                operation_index=operation_index,
                resource_state="present",
            )
            resources[previous.node_id] = previous
            latest_by_workspace_session_path[source_key] = previous
        operation_context = operation_content_context
        if operation_context is None and operation_control_context is None:
            # 旧eventにはoperation fragmentがないため、再解析互換として
            # patch全体fragmentへfallbackする。
            operation_context = command_context

        if operation.operation == "delete":
            if previous is not None:
                delete_context = operation_control_context or command_context
                edges.append(
                    make_structured_edge(
                        src_kind="resource_version",
                        src_id=previous.node_id,
                        dst_kind="artifact_fragment",
                        dst_id=delete_context.fragment.fragment_id,
                        relation="deleted_by",
                        method="apply_patch_delete",
                        reason=f"apply_patch requested deletion of {source_path}",
                    )
                )
            if _snapshot_confirms_deleted(
                source_snapshot,
                command_context,
                expected_path=source_path,
                expected_requested_path=operation.path,
            ):
                tombstone = _make_resource_version(
                    path=_snapshot_path(
                        source_snapshot,
                        source_path,
                        command_context,
                        expected_requested_path=operation.path,
                    ),
                    workspace_id=workspace_id,
                    content_hash=None,
                    sequence_no=sequence_no,
                    session_id=session_id,
                    tool_use_id=tool_use_id,
                    version_tag=f"apply_patch:{operation_index}:delete:tombstone",
                    operation_id=operation_id,
                    operation_index=operation_index,
                    snapshot_id=source_snapshot.snapshot_id,
                    resource_state="deleted",
                )
                resources[tombstone.node_id] = tombstone
                if previous is not None and previous.node_id != tombstone.node_id:
                    edges.append(
                        make_structured_edge(
                            src_kind="resource_version",
                            src_id=previous.node_id,
                            dst_kind="resource_version",
                            dst_id=tombstone.node_id,
                            relation="deleted_to",
                            method="apply_patch_delete_snapshot",
                            reason=f"PostToolUse confirmed deletion of {source_path}",
                        )
                    )
                latest_by_workspace_session_path.pop(source_key, None)
            return

        target_path = _normalize_path(
            operation.move_to or operation.path,
            command_context,
            repo_root,
        )
        if target_path is None:
            return
        expected_target_request = operation.move_to or operation.path
        if _snapshot_materializable(
            target_snapshot,
            command_context,
            expected_path=target_path,
            expected_requested_path=expected_target_request,
        ):
            resource_path = _snapshot_path(
                target_snapshot,
                target_path,
                command_context,
                expected_requested_path=expected_target_request,
            )
            resource = _make_resource_version(
                path=resource_path,
                workspace_id=workspace_id,
                content_hash=_snapshot_hash(target_snapshot),
                sequence_no=sequence_no,
                session_id=session_id,
                tool_use_id=tool_use_id,
                version_tag=(
                    f"apply_patch:{operation_index}:{operation.operation}:"
                    f"{operation.path}:{operation.move_to or '-'}"
                ),
                operation_id=operation_id,
                operation_index=operation_index,
                snapshot_id=(
                    None if target_snapshot is None else target_snapshot.snapshot_id
                ),
                resource_state=_snapshot_state(target_snapshot),
            )
            resources[resource.node_id] = resource
            target_key = (workspace_id, session_id, resource_path)
            _record_latest_resource(
                latest_by_workspace_session_path,
                target_key,
                resource,
            )
            if operation_context is not None:
                edges.append(
                    make_structured_edge(
                        src_kind="artifact_fragment",
                        src_id=operation_context.fragment.fragment_id,
                        dst_kind="resource_version",
                        dst_id=resource.node_id,
                        relation="written_to",
                        method="apply_patch_write",
                        reason=(
                            f"apply_patch operation {operation_id} wrote "
                            f"{resource_path}"
                        ),
                    )
                )

            if previous is not None and previous.node_id != resource.node_id:
                relation = (
                    "moved_to" if operation.move_to is not None else "updated_from"
                )
                method = (
                    "apply_patch_move"
                    if operation.move_to is not None
                    else "apply_patch_update"
                )
                edges.append(
                    make_structured_edge(
                        src_kind="resource_version",
                        src_id=previous.node_id,
                        dst_kind="resource_version",
                        dst_id=resource.node_id,
                        relation=relation,
                        method=method,
                        reason=(
                            f"apply_patch produced {resource_path} from {source_path}"
                        ),
                    )
                )
        if operation.move_to is not None and _snapshot_confirms_deleted(
            source_snapshot,
            command_context,
            expected_path=source_path,
            expected_requested_path=operation.path,
        ):
            tombstone = _make_resource_version(
                path=_snapshot_path(
                    source_snapshot,
                    source_path,
                    command_context,
                    expected_requested_path=operation.path,
                ),
                workspace_id=workspace_id,
                content_hash=None,
                sequence_no=sequence_no,
                session_id=session_id,
                tool_use_id=tool_use_id,
                version_tag=f"apply_patch:{operation_index}:move:tombstone",
                operation_id=operation_id,
                operation_index=operation_index,
                snapshot_id=source_snapshot.snapshot_id,
                resource_state="deleted",
            )
            resources[tombstone.node_id] = tombstone
            if previous is not None and previous.node_id != tombstone.node_id:
                edges.append(
                    make_structured_edge(
                        src_kind="resource_version",
                        src_id=previous.node_id,
                        dst_kind="resource_version",
                        dst_id=tombstone.node_id,
                        relation="deleted_to",
                        method="apply_patch_move_snapshot",
                        reason=f"PostToolUse confirmed move source removal of {source_path}",
                    )
                )
            latest_by_workspace_session_path.pop(source_key, None)

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
    grouped: dict[
        tuple[str | None, str | None, str],
        list[ArtifactContext],
    ] = defaultdict(list)
    for context in contexts:
        # tool_use_idがないevent同士を誤ってまとめないようevent_idをfallbackにする。
        identity = context.tool_use_id or context.event_id
        grouped[(context.workspace_id, context.session_id, identity)].append(context)
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


def _select_apply_patch_command(
    group: list[ArtifactContext],
) -> ArtifactContext | None:
    commands = [
        context
        for context in group
        if context.phase == "pre_tool_use"
        and context.artifact_role == "tool_input"
        and context.fragment.semantic_role == "command"
        and context.fragment.json_pointer != "/"
        and context.fragment.fragment_kind != "bash_segment"
    ]
    return min(commands, key=lambda context: context.sequence_no) if commands else None


def _select_command_context(
    group: list[ArtifactContext],
) -> ArtifactContext | None:
    commands = [
        context
        for context in group
        if context.phase == "pre_tool_use"
        and context.artifact_role == "tool_input"
        and context.fragment.semantic_role == "command"
        and context.fragment.json_pointer != "/"
    ]
    if not commands:
        return None
    containers = [
        context
        for context in commands
        if context.fragment.fragment_kind == "operation_container"
    ]
    return min(
        containers or commands,
        key=lambda context: (context.sequence_no, context.fragment.fragment_id),
    )


def _select_operation_fragment(
    group: list[ArtifactContext],
    operation_id: str,
    fragment_kind: str,
) -> ArtifactContext | None:
    matches = [
        context
        for context in group
        if context.phase == "pre_tool_use"
        and context.fragment.operation_id == operation_id
        and context.fragment.fragment_kind == fragment_kind
    ]
    return min(matches, key=lambda context: context.fragment.fragment_id) if matches else None


def _apply_patch_succeeded(group: list[ArtifactContext]) -> bool:
    outputs = _select_output_contexts(group)
    if not outputs:
        return False
    text = "\n".join(context.fragment.text for context in outputs).lower()
    if re.search(r"exit code:\s*[1-9][0-9]*", text):
        return False
    if "failed" in text or "error:" in text:
        return False
    return bool(
        re.search(r"exit code:\s*0\b", text)
        or "success" in text
        or "done!" in text
    )


def _bash_succeeded(group: list[ArtifactContext]) -> bool:
    post_outputs = [
        context
        for context in group
        if context.phase == "post_tool_use" and context.artifact_role == "tool_output"
    ]
    if not post_outputs:
        return False
    text = "\n".join(context.fragment.text for context in post_outputs).lower()
    if re.search(r"exit code:\s*[1-9][0-9]*", text):
        return False
    return "command failed" not in text and "execution failed" not in text


def _prefer_leaf_fragments(
    contexts: list[ArtifactContext],
) -> list[ArtifactContext]:
    leaves = [context for context in contexts if context.fragment.json_pointer != "/"]
    return leaves or contexts


def _normalize_path(
    path: str,
    context: ArtifactContext,
    repo_root: Path,
) -> str | None:
    candidate = Path(path).expanduser()
    if (
        context.workspace_status == "ready"
        and context.workspace_id is not None
        and context.workspace_root is not None
        and context.workspace_execution_cwd is not None
    ):
        root = os.path.abspath(os.path.normpath(context.workspace_root))
        base = os.path.abspath(
            os.path.normpath(context.workspace_execution_cwd)
        )
        if candidate.is_absolute():
            lexical = os.path.abspath(os.path.normpath(str(candidate)))
            raw_mappings = (
                (context.cwd, base),
                (context.workspace_lexical_root, root),
            )
            for raw_value, canonical_base in raw_mappings:
                if raw_value is None:
                    continue
                raw_base = os.path.abspath(os.path.normpath(raw_value))
                try:
                    if os.path.commonpath((raw_base, lexical)) == raw_base:
                        lexical = os.path.abspath(
                            os.path.normpath(
                                str(
                                    Path(canonical_base)
                                    / os.path.relpath(lexical, raw_base)
                                )
                            )
                        )
                        break
                except ValueError:
                    return None
        else:
            lexical = os.path.abspath(
                os.path.normpath(str(Path(base) / candidate))
            )
        try:
            if (
                os.path.commonpath((root, base)) != root
                or os.path.commonpath((root, lexical)) != root
            ):
                return None
        except ValueError:
            return None
        if _has_symlink_component(root, lexical):
            return None
        return lexical

    base = Path(context.cwd).expanduser() if context.cwd else repo_root
    base_input = os.path.abspath(os.path.normpath(str(base)))
    base_canonical = base_input
    try:
        if not os.path.islink(base_input):
            base_canonical = os.path.realpath(base_input)
    except OSError:
        pass
    if candidate.is_absolute():
        candidate_lexical = os.path.abspath(os.path.normpath(str(candidate)))
        try:
            if os.path.commonpath((base_input, candidate_lexical)) == base_input:
                candidate = Path(base_canonical) / os.path.relpath(
                    candidate_lexical,
                    base_input,
                )
        except ValueError:
            pass
    else:
        candidate = Path(base_canonical) / candidate
    return os.path.abspath(os.path.normpath(str(candidate)))


def _has_symlink_component(workspace_root: str, lexical_path: str) -> bool:
    relative = os.path.relpath(lexical_path, workspace_root)
    current = Path(workspace_root)
    for part in Path(relative).parts:
        if part in {"", "."}:
            continue
        if part == "..":
            return True
        current = current / part
        try:
            metadata = os.lstat(current)
        except FileNotFoundError:
            return False
        except OSError:
            return True
        if stat.S_ISLNK(metadata.st_mode):
            return True
    return False


def _combined_content_hash(contexts: list[ArtifactContext]) -> str:
    digest = hashlib.sha256()
    for context in sorted(contexts, key=lambda item: item.fragment.fragment_id):
        digest.update(context.fragment.text.encode("utf-8"))
        digest.update(b"\0")
    return digest.hexdigest()


def _make_resource_version(
    *,
    path: str,
    workspace_id: str | None,
    content_hash: str | None,
    sequence_no: int,
    session_id: str | None,
    tool_use_id: str | None,
    version_tag: str = "",
    operation_id: str | None = None,
    operation_index: int | None = None,
    snapshot_id: str | None = None,
    resource_state: str = "present",
) -> ResourceVersion:
    identity = "\0".join(
        (
            "resource_version_v2",
            workspace_id or "legacy-unscoped",
            session_id or "-",
            path,
            content_hash or "-",
            str(sequence_no),
            tool_use_id or "-",
            version_tag,
            operation_id or "-",
            "-" if operation_index is None else str(operation_index),
            snapshot_id or "-",
            resource_state,
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
        operation_id=operation_id,
        operation_index=operation_index,
        snapshot_id=snapshot_id,
        resource_state=resource_state,
        workspace_id=workspace_id,
    )


def _snapshot_path(
    snapshot: ResourceSnapshot | None,
    fallback: str,
    context: ArtifactContext,
    *,
    expected_requested_path: str,
) -> str:
    if (
        snapshot is not None
        and snapshot.lexical_path is not None
        and _snapshot_belongs_to_context(
            snapshot,
            context,
            expected_path=fallback,
            expected_requested_path=expected_requested_path,
        )
    ):
        return snapshot.lexical_path
    return fallback


def _snapshot_hash(snapshot: ResourceSnapshot | None) -> str | None:
    if snapshot is None or snapshot.resource_state != "present":
        return None
    return snapshot.content_sha256


def _snapshot_state(snapshot: ResourceSnapshot | None) -> str:
    return "present" if snapshot is None else snapshot.resource_state


def _snapshot_confirms_deleted(
    snapshot: ResourceSnapshot | None,
    context: ArtifactContext,
    *,
    expected_path: str,
    expected_requested_path: str,
) -> bool:
    return bool(
        snapshot is not None
        and _snapshot_belongs_to_context(
            snapshot,
            context,
            expected_path=expected_path,
            expected_requested_path=expected_requested_path,
        )
        and snapshot.resource_state == "deleted"
        and snapshot.capture_status == "deleted"
    )


def _snapshot_materializable(
    snapshot: ResourceSnapshot | None,
    context: ArtifactContext,
    *,
    expected_path: str,
    expected_requested_path: str,
) -> bool:
    if snapshot is None:
        return True
    if not _snapshot_belongs_to_context(
        snapshot,
        context,
        expected_path=expected_path,
        expected_requested_path=expected_requested_path,
    ):
        return False
    return snapshot.capture_status not in {
        "ambiguous_final_writer",
        "execution_unknown",
    }


def _snapshot_belongs_to_context(
    snapshot: ResourceSnapshot,
    context: ArtifactContext,
    *,
    expected_path: str,
    expected_requested_path: str,
) -> bool:
    if snapshot.requested_path != expected_requested_path:
        return False
    if (
        context.workspace_status != "ready"
        or context.workspace_id is None
        or context.workspace_root is None
    ):
        return True
    if snapshot.workspace_root != context.workspace_root:
        return False
    if snapshot.lexical_path is None:
        return (
            snapshot.content_sha256 is None
            and snapshot.captured_bytes == 0
            and snapshot.resource_state == "unknown"
        )
    if snapshot.lexical_path != expected_path:
        return False
    try:
        inside = (
            os.path.commonpath(
                (context.workspace_root, snapshot.lexical_path)
            )
            == context.workspace_root
        )
    except ValueError:
        return False
    return inside and not _has_symlink_component(
        context.workspace_root,
        snapshot.lexical_path,
    )


def _validated_stored_operation(
    operations_by_identity: _OperationLookup,
    *,
    event_id: str,
    session_id: str | None,
    tool_use_id: str | None,
    adapter: str,
    operation_index: int,
    operation_kind: str,
    source_path: str | None,
    target_path: str | None,
    segment_index: int | None,
) -> ToolOperation | None:
    operation = operations_by_identity.get(
        (event_id, adapter, operation_index)
    )
    if operation is None:
        return None
    if (
        operation.session_id != session_id
        or operation.tool_use_id != tool_use_id
        or operation.operation_kind != operation_kind
        or operation.source_path != source_path
        or operation.target_path != target_path
        or operation.segment_index != segment_index
    ):
        return None
    return operation


def _stored_tool_outcome(
    operations_by_identity: _OperationLookup,
    *,
    event_id: str,
    session_id: str | None,
    tool_use_id: str | None,
    adapter: str,
) -> str | None:
    operation_outcomes = {
        (operation.outcome, operation.outcome_event_id)
        for (
            operation_event_id,
            operation_adapter,
            _operation_index,
        ), operation in operations_by_identity.items()
        if operation_event_id == event_id
        and operation.session_id == session_id
        and operation.tool_use_id == tool_use_id
        and operation_adapter == adapter
    }
    if not operation_outcomes:
        return None
    if not any(event_id is not None for _outcome, event_id in operation_outcomes):
        # outcome履歴導入前のeventだけは従来のoutput heuristicへfallbackする。
        return None
    outcomes = {outcome for outcome, _event_id in operation_outcomes}
    if outcomes == {"succeeded"}:
        return "succeeded"
    if "failed" in outcomes:
        return "failed"
    return "unknown"


def _record_latest_resource(
    latest_by_workspace_session_path: _ResourceLookup,
    key: tuple[str | None, str | None, str],
    resource: ResourceVersion,
) -> None:
    if resource.resource_state in {"deleted", "missing"}:
        latest_by_workspace_session_path.pop(key, None)
    else:
        latest_by_workspace_session_path[key] = resource
