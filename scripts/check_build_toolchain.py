#!/usr/bin/env python3
from __future__ import annotations

import argparse
import importlib.metadata
import json
import re
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_LOCK = REPO_ROOT / "requirements" / "build.txt"
EXPECTED_PACKAGES = {
    "build",
    "packaging",
    "pyproject-hooks",
    "setuptools",
    "wheel",
}
ENTRY_PATTERN = re.compile(
    r"^(?P<name>[a-z0-9-]+)==(?P<version>[A-Za-z0-9][A-Za-z0-9._+-]*)\s+\\\n"
    r"    --hash=sha256:(?P<digest>[0-9a-f]{64})$"
)


class BuildToolchainError(RuntimeError):
    pass


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Check the hash-locked release build toolchain.",
    )
    parser.add_argument(
        "--lock",
        type=Path,
        default=DEFAULT_LOCK,
        help="Build requirements lock. Defaults to requirements/build.txt.",
    )
    parser.add_argument(
        "--skip-environment",
        action="store_true",
        help="Validate lock structure without checking installed package versions.",
    )
    args = parser.parse_args()
    try:
        locked = read_lock(args.lock.expanduser().resolve())
        if not args.skip_environment:
            check_installed_versions(locked)
    except BuildToolchainError as error:
        print(f"build toolchain: {error}", file=sys.stderr)
        return 1
    print(
        json.dumps(
            {
                "schema_version": 1,
                "status": "passed",
                "package_count": len(locked),
                "packages": {name: locked[name][0] for name in sorted(locked)},
                "environment_checked": not args.skip_environment,
                "hash_algorithm": "sha256",
                "only_binary_required": True,
            },
            sort_keys=True,
        )
    )
    return 0


def read_lock(path: Path) -> dict[str, tuple[str, str]]:
    if path.is_symlink() or not path.is_file():
        raise BuildToolchainError("lock must be a regular file")
    try:
        lines = path.read_text(encoding="ascii").splitlines()
    except (OSError, UnicodeError) as error:
        raise BuildToolchainError("lock is unreadable") from error
    entries: dict[str, tuple[str, str]] = {}
    index = 0
    while index < len(lines):
        line = lines[index]
        if not line or line.startswith("#"):
            index += 1
            continue
        if index + 1 >= len(lines):
            raise BuildToolchainError("lock entry is incomplete")
        candidate = f"{line}\n{lines[index + 1]}"
        match = ENTRY_PATTERN.fullmatch(candidate)
        if match is None:
            raise BuildToolchainError("lock entries must use exact versions and one SHA-256")
        name = match.group("name")
        if name in entries:
            raise BuildToolchainError(f"duplicate locked package: {name}")
        entries[name] = (match.group("version"), match.group("digest"))
        index += 2
    if set(entries) != EXPECTED_PACKAGES:
        raise BuildToolchainError("lock must contain the exact release build package set")
    if list(entries) != sorted(entries):
        raise BuildToolchainError("locked packages must be sorted")
    return entries


def check_installed_versions(locked: dict[str, tuple[str, str]]) -> None:
    for name, (expected, _) in locked.items():
        try:
            installed = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError as error:
            raise BuildToolchainError(f"locked package is not installed: {name}") from error
        if installed != expected:
            raise BuildToolchainError(
                f"installed package does not match lock: {name} {installed} != {expected}"
            )


if __name__ == "__main__":
    raise SystemExit(main())
