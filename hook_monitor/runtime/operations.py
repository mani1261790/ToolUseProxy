from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, replace

from hook_monitor.analysis.patch_parser import PatchOperation, parse_apply_patch
from hook_monitor.runtime.models import (
    ArtifactFragment,
    ArtifactRecord,
    NormalizedEvent,
    ToolOperation,
)
from hook_monitor.runtime.normalize import estimate_token_count, normalize_text


@dataclass(frozen=True)
class OperationExtraction:
    operations: tuple[ToolOperation, ...]
    fragments: tuple[ArtifactFragment, ...]


def extract_tool_operations(
    event: NormalizedEvent,
    artifacts: list[ArtifactRecord],
    fragments: list[ArtifactFragment],
) -> OperationExtraction:
    """PreToolUse inputを、永続化できる静的operationへ分解する。"""
    if event.phase != "pre_tool_use":
        return OperationExtraction((), ())
    if (event.tool_name or "").casefold() != "apply_patch":
        return OperationExtraction((), ())

    artifact_ids = {
        artifact.artifact_id
        for artifact in artifacts
        if artifact.role == "tool_input"
    }
    commands = [
        fragment
        for fragment in fragments
        if fragment.artifact_id in artifact_ids
        and fragment.semantic_role == "command"
        and fragment.json_pointer != "/"
    ]
    if not commands:
        return OperationExtraction((), ())
    parent = min(commands, key=lambda fragment: fragment.fragment_id)
    parsed = parse_apply_patch(parent.text)
    if not parsed:
        return OperationExtraction((), ())

    operations: list[ToolOperation] = []
    # 同じIDを後からupsertし、patch全体を比較用contentではなく
    # operationを束ねる監査containerとして扱う。
    derived: list[ArtifactFragment] = [
        replace(parent, fragment_kind="operation_container")
    ]
    for index, patch_operation in enumerate(parsed):
        operation_kind = apply_patch_operation_kind(patch_operation)
        source_path = None if patch_operation.operation == "add" else patch_operation.path
        target_path = (
            None
            if patch_operation.operation == "delete"
            else patch_operation.move_to or patch_operation.path
        )
        operation_id = make_operation_id(
            event_id=event.event_id,
            adapter="apply_patch",
            operation_index=index,
            operation_kind=operation_kind,
            source_path=source_path,
            target_path=target_path,
        )
        control = _make_derived_fragment(
            parent,
            operation_id=operation_id,
            fragment_kind="operation_control",
            semantic_role="operation_control",
            text=json.dumps(
                {
                    "operation": operation_kind,
                    "source_path": source_path,
                    "target_path": target_path,
                },
                ensure_ascii=False,
                sort_keys=True,
            ),
        )
        derived.append(control)

        content_fragment: ArtifactFragment | None = None
        if patch_operation.added_text:
            content_fragment = _make_derived_fragment(
                parent,
                operation_id=operation_id,
                fragment_kind="operation_added",
                semantic_role="content",
                text=patch_operation.added_text,
            )
            derived.append(content_fragment)
        if patch_operation.removed_text:
            derived.append(
                _make_derived_fragment(
                    parent,
                    operation_id=operation_id,
                    fragment_kind="operation_removed",
                    semantic_role="removed_content",
                    text=patch_operation.removed_text,
                )
            )

        operations.append(
            ToolOperation(
                operation_id=operation_id,
                event_id=event.event_id,
                artifact_id=parent.artifact_id,
                parent_fragment_id=parent.fragment_id,
                session_id=event.session_id,
                tool_use_id=event.tool_use_id,
                tool_name=event.tool_name,
                adapter="apply_patch",
                operation_index=index,
                operation_kind=operation_kind,
                source_path=source_path,
                target_path=target_path,
                segment_index=None,
                connector=None,
                content_fragment_id=(
                    None if content_fragment is None else content_fragment.fragment_id
                ),
            )
        )
    return OperationExtraction(tuple(operations), tuple(derived))


def apply_patch_operation_kind(operation: PatchOperation) -> str:
    if operation.move_to is not None:
        return "move"
    return operation.operation


def make_operation_id(
    *,
    event_id: str,
    adapter: str,
    operation_index: int,
    operation_kind: str,
    source_path: str | None,
    target_path: str | None,
    segment_index: int | None = None,
) -> str:
    identity = "\0".join(
        (
            event_id,
            adapter,
            str(operation_index),
            operation_kind,
            source_path or "-",
            target_path or "-",
            "-" if segment_index is None else str(segment_index),
        )
    )
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()


def _make_derived_fragment(
    parent: ArtifactFragment,
    *,
    operation_id: str,
    fragment_kind: str,
    semantic_role: str,
    text: str,
) -> ArtifactFragment:
    normalized = normalize_text(text)
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    identity = "\0".join((operation_id, fragment_kind, digest))
    fragment_id = hashlib.sha256(identity.encode("utf-8")).hexdigest()
    return ArtifactFragment(
        fragment_id=f"{parent.artifact_id}:operation:{fragment_id[:24]}",
        artifact_id=parent.artifact_id,
        json_pointer=parent.json_pointer,
        semantic_role=semantic_role,
        text=text,
        text_hash=digest,
        normalized_text=normalized,
        token_count=estimate_token_count(normalized),
        fragment_kind=fragment_kind,
        parent_fragment_id=parent.fragment_id,
        operation_id=operation_id,
    )
