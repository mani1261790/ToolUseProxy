#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_WORKFLOW_ROOT = REPO_ROOT / ".github" / "workflows"
APPROVED_REMOTE_ACTIONS = {
    "actions/checkout",
    "actions/setup-python",
}
REMOTE_ACTION_PATTERN = re.compile(
    r"^(?P<action>[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)@"
    r"(?P<revision>[0-9a-f]{40})\s+#\s+(?P<label>v\S+)$"
)
USES_PATTERN = re.compile(r"^\s*uses:\s*(?P<reference>.+?)\s*$")
STEP_PATTERN = re.compile(r"^(?P<indent>\s*)-\s+name:\s*")


class SupplyChainContractError(RuntimeError):
    pass


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Check the fail-closed GitHub Actions supply-chain contract.",
    )
    parser.add_argument(
        "--workflow-root",
        type=Path,
        default=DEFAULT_WORKFLOW_ROOT,
        help="Workflow directory. Defaults to .github/workflows.",
    )
    args = parser.parse_args()
    try:
        summary = check_workflows(args.workflow_root.expanduser().resolve())
    except SupplyChainContractError as error:
        print(f"CI supply chain: {error}", file=sys.stderr)
        return 1
    print(json.dumps(summary, sort_keys=True))
    return 0


def check_workflows(workflow_root: Path) -> dict[str, object]:
    if (
        not workflow_root.is_dir()
        or workflow_root.is_symlink()
        or not _is_within_requested_root(workflow_root)
    ):
        raise SupplyChainContractError("workflow root must be a regular directory")
    workflows = sorted(
        path
        for path in workflow_root.iterdir()
        if path.suffix in {".yml", ".yaml"}
    )
    if not workflows:
        raise SupplyChainContractError("no workflow files found")

    remote_action_count = 0
    checkout_count = 0
    for workflow in workflows:
        if workflow.is_symlink() or not workflow.is_file():
            raise SupplyChainContractError(f"workflow must be a regular file: {workflow.name}")
        try:
            lines = workflow.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeError) as error:
            raise SupplyChainContractError(f"workflow is unreadable: {workflow.name}") from error
        _check_trigger_and_permissions(workflow.name, lines)
        steps = _workflow_steps(lines)
        workflow_checkout_count = 0
        for line in lines:
            match = USES_PATTERN.match(line)
            if match is None:
                continue
            reference = match.group("reference")
            if reference.startswith("./"):
                continue
            remote_action_count += 1
            action = _validate_remote_action(workflow.name, reference)
            if action == "actions/checkout":
                checkout_count += 1
                workflow_checkout_count += 1

        checkout_step_count = 0
        for step in steps:
            references = [
                match.group("reference")
                for line in step
                if (match := USES_PATTERN.match(line)) is not None
            ]
            if not any(reference.startswith("actions/checkout@") for reference in references):
                continue
            checkout_step_count += 1
            if not any(
                re.fullmatch(r"\s*persist-credentials:\s*false\s*", candidate)
                for candidate in step
            ):
                raise SupplyChainContractError(
                    f"checkout must disable credential persistence: {workflow.name}"
                )
        if checkout_step_count != workflow_checkout_count:
            raise SupplyChainContractError(
                f"checkout must be declared in a named step: {workflow.name}"
            )

    if remote_action_count == 0 or checkout_count == 0:
        raise SupplyChainContractError("workflow must use an approved pinned checkout action")
    return {
        "schema_version": 1,
        "status": "passed",
        "workflow_count": len(workflows),
        "remote_action_count": remote_action_count,
        "pinned_remote_action_count": remote_action_count,
        "checkout_count": checkout_count,
        "checkout_credentials_persisted": False,
        "pull_request_target_enabled": False,
        "top_level_permissions": {"contents": "read"},
    }


def _is_within_requested_root(path: Path) -> bool:
    try:
        path.resolve(strict=True)
    except OSError:
        return False
    return True


def _check_trigger_and_permissions(name: str, lines: list[str]) -> None:
    if any(
        re.fullmatch(r'''\s*["']?pull_request_target["']?:\s*''', line)
        for line in lines
    ):
        raise SupplyChainContractError(f"pull_request_target is forbidden: {name}")
    permission_blocks = [index for index, line in enumerate(lines) if line.strip() == "permissions:"]
    if permission_blocks != [next((i for i, line in enumerate(lines) if line == "permissions:"), -1)]:
        raise SupplyChainContractError(f"exactly one top-level permissions block is required: {name}")
    index = permission_blocks[0]
    permission_lines: list[str] = []
    for line in lines[index + 1 :]:
        if line and not line.startswith((" ", "\t")):
            break
        if line.strip():
            permission_lines.append(line.strip())
    if permission_lines != ["contents: read"]:
        raise SupplyChainContractError(f"workflow permissions must be contents: read only: {name}")


def _workflow_steps(lines: list[str]) -> list[list[str]]:
    starts: list[tuple[int, int]] = []
    for index, line in enumerate(lines):
        match = STEP_PATTERN.match(line)
        if match is not None:
            starts.append((index, len(match.group("indent"))))
    steps: list[list[str]] = []
    for position, (start, indent) in enumerate(starts):
        end = len(lines)
        for next_start, next_indent in starts[position + 1 :]:
            if next_indent == indent:
                end = next_start
                break
        steps.append(lines[start:end])
    return steps


def _validate_remote_action(workflow_name: str, reference: str) -> str:
    match = REMOTE_ACTION_PATTERN.fullmatch(reference)
    if match is None:
        raise SupplyChainContractError(
            f"remote action must use a full commit SHA and version comment: {workflow_name}"
        )
    action = match.group("action")
    if action not in APPROVED_REMOTE_ACTIONS:
        raise SupplyChainContractError(
            f"remote action is not approved: {workflow_name}:{action}"
        )
    return action


if __name__ == "__main__":
    raise SystemExit(main())
