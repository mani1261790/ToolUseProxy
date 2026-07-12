from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class PatchOperation:
    operation: str
    path: str
    move_to: str | None
    added_text: str
    removed_text: str


def parse_apply_patch(command: str) -> list[PatchOperation]:
    """Codex apply_patch形式をfile operation単位へ分解する。"""
    lines = command.splitlines()
    if not lines or lines[0].strip() != "*** Begin Patch":
        return []
    if lines[-1].strip() != "*** End Patch":
        return []

    operations: list[PatchOperation] = []
    current_operation: str | None = None
    current_path: str | None = None
    current_move_to: str | None = None
    added: list[str] = []
    removed: list[str] = []

    def finish_current() -> bool:
        nonlocal current_operation, current_path, current_move_to, added, removed
        if current_operation is None:
            return True
        if current_path is None or not _valid_path(current_path):
            return False
        if current_move_to is not None and not _valid_path(current_move_to):
            return False
        operations.append(
            PatchOperation(
                operation=current_operation,
                path=current_path,
                move_to=current_move_to,
                added_text="\n".join(added),
                removed_text="\n".join(removed),
            )
        )
        current_operation = None
        current_path = None
        current_move_to = None
        added = []
        removed = []
        return True

    for line in lines[1:-1]:
        header = _operation_header(line)
        if header is not None:
            if not finish_current():
                return []
            current_operation, current_path = header
            continue
        if line.startswith("*** Move to: "):
            if current_operation != "update" or current_move_to is not None:
                return []
            current_move_to = line.removeprefix("*** Move to: ").strip()
            continue
        if line.startswith("*** ") and not line.startswith("*** End of File"):
            return []
        if current_operation is None:
            if line.strip():
                return []
            continue
        if line.startswith("+"):
            added.append(line[1:])
        elif line.startswith("-"):
            removed.append(line[1:])

    if not finish_current():
        return []
    return operations


def _operation_header(line: str) -> tuple[str, str] | None:
    prefixes = (
        ("*** Add File: ", "add"),
        ("*** Update File: ", "update"),
        ("*** Delete File: ", "delete"),
    )
    for prefix, operation in prefixes:
        if line.startswith(prefix):
            return operation, line.removeprefix(prefix).strip()
    return None


def _valid_path(path: str) -> bool:
    return bool(path) and "\0" not in path
