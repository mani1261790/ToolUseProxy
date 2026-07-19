#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import subprocess
from collections import Counter, defaultdict
from pathlib import Path, PurePosixPath
from typing import Iterable


REPO_ROOT = Path(__file__).resolve().parents[1]
MAX_BLOB_BYTES = 2 * 1024 * 1024
FORBIDDEN_BASENAMES = {
    ".ds_store",
    "auth.json",
    "credentials.json",
    "events.db",
    "secrets.json",
}
ALLOWED_BINARY_MAGIC = {
    ".pdf": b"%PDF-",
    ".png": b"\x89PNG\r\n\x1a\n",
}
FORBIDDEN_SUFFIXES = {
    ".db",
    ".der",
    ".jks",
    ".key",
    ".keystore",
    ".p12",
    ".pem",
    ".pfx",
    ".sqlite",
    ".sqlite3",
}
KNOWN_SYNTHETIC_VALUES = {
    "AKIA1234567890ABCDEF",
}
CREDENTIAL_PATTERNS = {
    "private_key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    "github_token": re.compile(
        r"(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,})"
    ),
    "openai_key": re.compile(r"sk-(?:proj-)?[A-Za-z0-9_-]{20,}"),
    "aws_access_key": re.compile(r"(?:AKIA|ASIA)[A-Z0-9]{16}"),
    "slack_token": re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),
    "stripe_live_key": re.compile(r"sk_live_[A-Za-z0-9]{16,}"),
    "google_api_key": re.compile(r"AIza[0-9A-Za-z_-]{35}"),
    "credential_url": re.compile(
        r"(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?)://[^\s/:@]+:[^\s/@]+@",
        re.IGNORECASE,
    ),
}
POSIX_USER_PATH = re.compile(r"/(?:Users|home)/[A-Za-z0-9._-]+/")
WINDOWS_USER_PATH = re.compile(r"[A-Za-z]:\\Users\\[A-Za-z0-9._-]+\\", re.IGNORECASE)


class PublicSourceAuditError(RuntimeError):
    pass


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Audit public HEAD and reachable Git history without emitting values or paths.",
    )
    parser.add_argument(
        "--repo",
        type=Path,
        default=REPO_ROOT,
        help="Git repository. Defaults to the ToolUseProxy checkout.",
    )
    parser.add_argument(
        "--require-clean",
        action="store_true",
        help="Fail when tracked or non-ignored untracked worktree content differs from HEAD.",
    )
    args = parser.parse_args()
    try:
        summary = audit_repository(
            args.repo.expanduser().resolve(),
            require_clean=args.require_clean,
        )
    except PublicSourceAuditError as error:
        print(
            json.dumps(
                {
                    "schema_version": 1,
                    "status": "failed",
                    "error_code": str(error),
                    "report_publishable": True,
                    "raw_value_exposure": False,
                },
                sort_keys=True,
            )
        )
        return 1
    print(json.dumps(summary, sort_keys=True))
    return 0 if summary["status"] == "passed" else 1


def audit_repository(repo: Path, *, require_clean: bool) -> dict[str, object]:
    if repo.is_symlink() or not repo.is_dir() or not (repo / ".git").exists():
        raise PublicSourceAuditError("repository_invalid")
    dirty = bool(_git(repo, "status", "--porcelain", "--untracked-files=normal").strip())
    if require_clean and dirty:
        raise PublicSourceAuditError("worktree_dirty")

    findings: Counter[str] = Counter()
    observations: Counter[str] = Counter()
    ignored_synthetic_count = 0
    history_paths, blob_metadata = _reachable_blob_inventory(repo)
    history_bytes = 0
    for object_id, content in _read_blobs(repo, blob_metadata):
        history_bytes += len(content)
        for path in history_paths.get(object_id, ()):
            if _forbidden_path(path):
                findings["forbidden_path"] += 1
        ignored_synthetic_count += _scan_content(
            content,
            findings,
            observations,
            binary_allowed=_allowed_binary(content, history_paths.get(object_id, ())),
        )

    worktree_paths = _worktree_paths(repo)
    worktree_bytes = 0
    for relative_path in worktree_paths:
        path = repo / relative_path
        if path.is_symlink() or not path.is_file():
            findings["non_regular_worktree_file"] += 1
            continue
        try:
            content = path.read_bytes()
        except OSError:
            findings["unreadable_worktree_file"] += 1
            continue
        worktree_bytes += len(content)
        if _forbidden_path(relative_path):
            findings["forbidden_path"] += 1
        ignored_synthetic_count += _scan_content(
            content,
            findings,
            observations,
            binary_allowed=_allowed_binary(content, (relative_path,)),
        )

    commit_messages = _nul_records(_git_bytes(repo, "log", "--all", "--format=%B%x00"))
    tag_messages = _nul_records(
        _git_bytes(repo, "for-each-ref", "--format=%(contents)%00", "refs/tags")
    )
    for message in (*commit_messages, *tag_messages):
        ignored_synthetic_count += _scan_content(
            message,
            findings,
            observations,
            binary_allowed=False,
        )

    finding_counts = {name: findings[name] for name in sorted(findings) if findings[name]}
    return {
        "schema_version": 1,
        "status": "passed" if not finding_counts else "failed",
        "report_publishable": True,
        "raw_value_exposure": False,
        "history": {
            "ref_count": _line_count(_git(repo, "for-each-ref", "--format=%(refname)")),
            "commit_count": int(_git(repo, "rev-list", "--count", "--all").strip() or "0"),
            "unique_blob_count": len(blob_metadata),
            "path_binding_count": sum(len(paths) for paths in history_paths.values()),
            "scanned_bytes": history_bytes,
            "commit_message_count": len(commit_messages),
            "tag_message_count": len(tag_messages),
        },
        "worktree": {
            "dirty": dirty,
            "file_count": len(worktree_paths),
            "scanned_bytes": worktree_bytes,
        },
        "limits": {"max_blob_bytes": MAX_BLOB_BYTES},
        "known_synthetic_ignored_count": ignored_synthetic_count,
        "finding_count": sum(finding_counts.values()),
        "finding_counts": finding_counts,
        "observation_counts": {
            name: observations[name] for name in sorted(observations) if observations[name]
        },
    }


def _reachable_blob_inventory(
    repo: Path,
) -> tuple[dict[str, set[str]], dict[str, int]]:
    output = _git(repo, "-c", "core.quotePath=false", "rev-list", "--objects", "--all")
    object_ids: list[str] = []
    paths: dict[str, set[str]] = defaultdict(set)
    for line in output.splitlines():
        object_id, separator, path = line.partition(" ")
        if not re.fullmatch(r"[0-9a-f]{40,64}", object_id):
            raise PublicSourceAuditError("git_object_inventory_invalid")
        object_ids.append(object_id)
        if separator and path:
            paths[object_id].add(path)
    if not object_ids:
        raise PublicSourceAuditError("git_history_empty")
    metadata_input = "".join(f"{object_id}\n" for object_id in object_ids).encode("ascii")
    result = subprocess.run(
        ["git", "cat-file", "--batch-check=%(objectname) %(objecttype) %(objectsize)"],
        cwd=repo,
        input=metadata_input,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise PublicSourceAuditError("git_object_metadata_failed")
    blobs: dict[str, int] = {}
    for line in result.stdout.decode("ascii").splitlines():
        parts = line.split()
        if len(parts) != 3:
            raise PublicSourceAuditError("git_object_metadata_invalid")
        object_id, object_type, size_text = parts
        if object_type == "blob":
            blobs[object_id] = int(size_text)
    return paths, blobs


def _read_blobs(repo: Path, blobs: dict[str, int]) -> Iterable[tuple[str, bytes]]:
    if not blobs:
        return
    request = "".join(f"{object_id}\n" for object_id in blobs).encode("ascii")
    result = subprocess.run(
        ["git", "cat-file", "--batch"],
        cwd=repo,
        input=request,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise PublicSourceAuditError("git_blob_read_failed")
    payload = result.stdout
    offset = 0
    for expected_id, expected_size in blobs.items():
        header_end = payload.find(b"\n", offset)
        if header_end < 0:
            raise PublicSourceAuditError("git_blob_stream_invalid")
        header = payload[offset:header_end].decode("ascii").split()
        if len(header) != 3 or header[0] != expected_id or header[1] != "blob":
            raise PublicSourceAuditError("git_blob_stream_invalid")
        size = int(header[2])
        if size != expected_size:
            raise PublicSourceAuditError("git_blob_size_mismatch")
        start = header_end + 1
        end = start + size
        if end >= len(payload) or payload[end : end + 1] != b"\n":
            raise PublicSourceAuditError("git_blob_stream_invalid")
        yield expected_id, payload[start:end]
        offset = end + 1
    if offset != len(payload):
        raise PublicSourceAuditError("git_blob_stream_invalid")


def _worktree_paths(repo: Path) -> list[str]:
    output = _git_bytes(
        repo,
        "ls-files",
        "-z",
        "--cached",
        "--others",
        "--exclude-standard",
    )
    return sorted(
        value.decode("utf-8", errors="surrogateescape")
        for value in output.split(b"\x00")
        if value
    )


def _forbidden_path(value: str) -> bool:
    path = PurePosixPath(value)
    basename = path.name.casefold()
    if basename == ".env" or basename.startswith(".env."):
        return True
    if basename in FORBIDDEN_BASENAMES:
        return True
    return any(basename.endswith(suffix) for suffix in FORBIDDEN_SUFFIXES)


def _allowed_binary(content: bytes, paths: Iterable[str]) -> bool:
    bound_paths = tuple(paths)
    if not bound_paths:
        return False
    for value in bound_paths:
        expected_magic = ALLOWED_BINARY_MAGIC.get(PurePosixPath(value).suffix.casefold())
        if expected_magic is None or not content.startswith(expected_magic):
            return False
    return True


def _scan_content(
    content: bytes,
    findings: Counter[str],
    observations: Counter[str],
    *,
    binary_allowed: bool,
) -> int:
    if len(content) > MAX_BLOB_BYTES:
        findings["oversized_blob"] += 1
        return 0
    if b"\x00" in content:
        if binary_allowed:
            observations["allowed_binary_blob"] += 1
        else:
            findings["binary_blob"] += 1
        return 0
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        if binary_allowed:
            observations["allowed_binary_blob"] += 1
        else:
            findings["binary_blob"] += 1
        return 0
    ignored = 0
    for name, pattern in CREDENTIAL_PATTERNS.items():
        for match in pattern.finditer(text):
            if match.group(0) in KNOWN_SYNTHETIC_VALUES:
                ignored += 1
            else:
                findings[name] += 1
    observations["private_absolute_path"] += len(POSIX_USER_PATH.findall(text))
    observations["private_absolute_path"] += len(WINDOWS_USER_PATH.findall(text))
    return ignored


def _nul_records(payload: bytes) -> list[bytes]:
    return [record for record in payload.split(b"\x00") if record.strip()]


def _line_count(value: str) -> int:
    return sum(1 for line in value.splitlines() if line)


def _git(repo: Path, *arguments: str) -> str:
    try:
        return _git_bytes(repo, *arguments).decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise PublicSourceAuditError("git_output_not_utf8") from error


def _git_bytes(repo: Path, *arguments: str) -> bytes:
    result = subprocess.run(
        ["git", *arguments],
        cwd=repo,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise PublicSourceAuditError("git_command_failed")
    return result.stdout


if __name__ == "__main__":
    raise SystemExit(main())
