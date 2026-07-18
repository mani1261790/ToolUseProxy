from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import stat
from collections.abc import Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, replace
from pathlib import Path, PurePath
from typing import Iterator, Literal, NoReturn

from hook_monitor.analysis.source_index import load_sources_and_chunks

try:  # pragma: no cover - exercised on the supported POSIX runtime
    import fcntl
except ImportError:  # pragma: no cover - Windows compatibility fallback
    fcntl = None  # type: ignore[assignment]


REGISTRATION_SCHEMA_VERSION = 1
DETECTOR_VERSION = "protected-source-candidate-v1"
MANIFEST_FILENAME = "protected_sources.json"
MAX_PROTECTED_FILE_BYTES = 1024 * 1024
MAX_JSON_DEPTH = 32
MAX_JSON_ITEMS = 4096
MAX_SELECTOR_VALUES = 256
MAX_SELECTOR_VALUE_BYTES = 4096
MAX_MANIFEST_SOURCES = 256

_DOTENV_ASSIGNMENT = re.compile(
    r"^(?:export\s+)?([A-Za-z_][A-Za-z0-9_.-]*)\s*=(.*)$"
)
_SAFE_SOURCE_ID = re.compile(r"[a-z][a-z0-9_-]{0,95}\Z")
_SAFE_REASON_CODE = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")
_HEX_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_CANDIDATE_ID = re.compile(r"[0-9a-f]{32}\Z")
_SECRET_MARKERS = frozenset(
    {
        "secret",
        "token",
        "password",
        "passwd",
        "api_key",
        "private_key",
        "credential",
        "auth",
        "bearer",
        "access_key",
    }
)
_REVIEW_REASON_CODES = frozenset(
    {
        "user_rejected",
        "not_sensitive",
        "already_managed",
        "false_positive",
        "deferred",
    }
)
_ERROR_MESSAGES = {
    "invalid_workspace": "workspace must be a non-symlink directory",
    "invalid_relative_path": "path must be workspace-relative and normalized",
    "unsupported_source_format": "only .env, .env.* and .json files are supported",
    "source_not_safe": "source must be a private regular file inside the workspace",
    "source_too_large": "source exceeds the protected-file size limit",
    "source_changed": "source changed after the candidate was created",
    "source_not_utf8": "source must be valid UTF-8",
    "source_not_parseable": "source is not statically parseable",
    "dotenv_duplicate_key": "dotenv source contains a duplicate key",
    "json_duplicate_key": "JSON source contains a duplicate object key",
    "json_too_deep": "JSON source exceeds the nesting-depth limit",
    "json_too_many_items": "JSON source exceeds the item-count limit",
    "no_secret_selector": "source contains no supported secret-like string key",
    "too_many_selectors": "source contains too many protected selectors",
    "selector_too_long": "a protected selector exceeds the size limit",
    "manifest_missing": "protected_sources.json does not exist",
    "manifest_not_safe": "protected_sources.json must be a private regular file",
    "manifest_too_large": "protected_sources.json exceeds the size limit",
    "manifest_not_utf8": "protected_sources.json must be valid UTF-8",
    "manifest_invalid_json": "protected_sources.json must be strict JSON",
    "manifest_schema_legacy": "protected_sources.json schema version 1 is not writable",
    "manifest_schema_future": "protected_sources.json schema version is not supported",
    "manifest_schema_invalid": "protected_sources.json schema version must be 2",
    "manifest_sources_invalid": "protected_sources.json sources must be a list",
    "manifest_too_many_sources": "protected_sources.json contains too many sources",
    "manifest_source_invalid": "protected_sources.json contains an invalid source",
    "manifest_source_too_large": "a protected source exceeds the validation size limit",
    "manifest_duplicate_id": "protected_sources.json contains duplicate source ids",
    "manifest_duplicate_path": "protected_sources.json contains duplicate source paths",
    "manifest_conflict": "protected_sources.json changed after the candidate was created",
    "source_id_conflict": "the proposed source id is already used by another source",
    "source_path_conflict": "the proposed path is already registered differently",
    "candidate_invalid": "saved candidate data is invalid",
    "candidate_revision_invalid": "candidate revision does not match the saved candidate",
    "review_reason_invalid": "candidate review reason code is invalid",
    "manifest_validation_failed": "the updated protected source manifest is invalid",
    "manifest_write_failed": "protected_sources.json could not be updated safely",
    "workspace_lock_unavailable": "exclusive workspace locking is unavailable",
    "manifest_durability_unknown": "protected_sources.json was replaced but durability is unknown",
    "manifest_postcondition_failed": "protected_sources.json update could not be verified",
}


class ProtectedSourceRegistrationError(ValueError):
    """A value-free registration failure with a stable machine-readable code."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(_ERROR_MESSAGES.get(code, "protected source registration failed"))


@dataclass(frozen=True)
class FileBinding:
    sha256: str
    device: int
    inode: int
    size: int
    mtime_ns: int
    ctime_ns: int
    mode: int
    link_count: int

    def to_storage_record(self) -> dict[str, object]:
        return {
            "sha256": self.sha256,
            "device": self.device,
            "inode": self.inode,
            "size": self.size,
            "mtime_ns": self.mtime_ns,
            "ctime_ns": self.ctime_ns,
            "mode": self.mode,
            "link_count": self.link_count,
        }

    @classmethod
    def from_storage_record(cls, value: object) -> FileBinding:
        if not isinstance(value, Mapping):
            _raise("candidate_invalid")
        sha256 = value.get("sha256")
        integers = {
            name: value.get(name)
            for name in (
                "device",
                "inode",
                "size",
                "mtime_ns",
                "ctime_ns",
                "mode",
                "link_count",
            )
        }
        if (
            not isinstance(sha256, str)
            or _HEX_SHA256.fullmatch(sha256) is None
            or any(type(item) is not int or item < 0 for item in integers.values())
        ):
            _raise("candidate_invalid")
        return cls(sha256=sha256, **integers)  # type: ignore[arg-type]


@dataclass
class ProtectedSourceWorkspaceLock:
    """Opaque ownership token for one locked protected-source workspace."""

    _root_fd: int
    _root_path: Path
    _root_stat: os.stat_result
    _active: bool = True


@dataclass(frozen=True)
class ProtectedSourceCandidate:
    candidate_id: str
    workspace_id: str
    relative_path: str
    reason_codes: tuple[str, ...]
    confidence: float
    proposed_source: dict[str, object]
    source_binding: FileBinding
    manifest_binding: FileBinding
    candidate_revision_sha256: str
    detector_version: str = DETECTOR_VERSION
    candidate_revision: str | None = None
    status: Literal["proposed", "approving", "approved"] = "proposed"
    already_registered: bool = False

    @property
    def manifest_sha256(self) -> str:
        return self.manifest_binding.sha256

    @property
    def suppression_fingerprint(self) -> str:
        identity = _canonical_json_bytes(
            {
                "detector_version": self.detector_version,
                "workspace_id": self.workspace_id,
                "path": self.relative_path,
                "source_sha256": self.source_binding.sha256,
                "proposed_source": self.proposed_source,
            }
        )
        return hashlib.sha256(identity).hexdigest()

    def with_candidate_id(self, candidate_id: str) -> ProtectedSourceCandidate:
        if not isinstance(candidate_id, str) or _CANDIDATE_ID.fullmatch(candidate_id) is None:
            _raise("candidate_invalid")
        return replace(self, candidate_id=candidate_id)

    def to_public_payload(self) -> dict[str, object]:
        if (
            self.candidate_revision is None
            or _CANDIDATE_ID.fullmatch(self.candidate_id) is None
        ):
            _raise("candidate_revision_invalid")
        return {
            "candidate_id": self.candidate_id,
            "candidate_revision": self.candidate_revision,
            "path": self.relative_path,
            "reason_codes": list(self.reason_codes),
            "confidence": self.confidence,
            "proposed_source": _copy_json_object(self.proposed_source),
            "review_required": True,
        }

    def to_storage_record(
        self,
        *,
        discovery_source: str = "explicit_path",
    ) -> dict[str, object]:
        if discovery_source not in {"explicit_path", "bounded_scan", "runtime_observation"}:
            _raise("candidate_invalid")
        return {
            "candidate_revision_sha256": self.candidate_revision_sha256,
            "workspace_id": self.workspace_id,
            "relative_path": self.relative_path,
            "detector_version": self.detector_version,
            "discovery_source": discovery_source,
            "rule_ids": self.reason_codes,
            "confidence": self.confidence,
            "proposed_source_json": _canonical_json_bytes(
                self.proposed_source
            ).decode("utf-8"),
            "source_sha256": self.source_binding.sha256,
            "source_size": self.source_binding.size,
            "source_mtime_ns": self.source_binding.mtime_ns,
            "source_device": self.source_binding.device,
            "source_inode": self.source_binding.inode,
            "manifest_sha256": self.manifest_binding.sha256,
            "suppression_fingerprint": self.suppression_fingerprint,
        }

    @classmethod
    def from_storage_record(cls, value: Mapping[str, object]) -> ProtectedSourceCandidate:
        try:
            candidate_id = value.get("candidate_id")
            workspace_id = value.get("workspace_id")
            relative_path = value.get("path", value.get("relative_path"))
            reason_codes = value.get("reason_codes", value.get("rule_ids"))
            confidence = value.get("confidence")
            proposed_source = value.get("proposed_source")
            if proposed_source is None:
                proposed_source_json = value.get("proposed_source_json")
                if not isinstance(proposed_source_json, str):
                    _raise("candidate_invalid")
                proposed_source = _strict_candidate_json(proposed_source_json)
            revision_sha256 = value.get("candidate_revision_sha256")
            detector_version = value.get("detector_version")
            status = value.get("status", "proposed")
            if (
                not isinstance(candidate_id, str)
                or _CANDIDATE_ID.fullmatch(candidate_id) is None
                or not isinstance(workspace_id, str)
                or not workspace_id
                or not isinstance(relative_path, str)
                or not isinstance(reason_codes, Sequence)
                or isinstance(reason_codes, (str, bytes))
                or not reason_codes
                or not all(
                    isinstance(item, str) and _SAFE_REASON_CODE.fullmatch(item)
                    for item in reason_codes
                )
                or type(confidence) not in {int, float}
                or not 0.0 <= float(confidence) <= 1.0
                or not isinstance(proposed_source, Mapping)
                or not isinstance(revision_sha256, str)
                or _HEX_SHA256.fullmatch(revision_sha256) is None
                or detector_version != DETECTOR_VERSION
                or status not in {"proposed", "approving", "approved"}
            ):
                _raise("candidate_invalid")
            normalized_path = _normalize_relative_path(relative_path)
            source_payload = _validate_proposed_source(
                dict(proposed_source), expected_path=normalized_path
            )
            source_binding_value = value.get("source_binding")
            if source_binding_value is None:
                source_binding_value = _flat_source_binding_record(value)
            manifest_binding_value = value.get("manifest_binding")
            if manifest_binding_value is None:
                manifest_binding_value = _flat_manifest_binding_record(value)
            return cls(
                candidate_id=candidate_id,
                workspace_id=workspace_id,
                relative_path=normalized_path,
                reason_codes=tuple(reason_codes),
                confidence=float(confidence),
                proposed_source=source_payload,
                source_binding=FileBinding.from_storage_record(source_binding_value),
                manifest_binding=FileBinding.from_storage_record(manifest_binding_value),
                candidate_revision_sha256=revision_sha256,
                detector_version=detector_version,
                status=status,
            )
        except ProtectedSourceRegistrationError:
            raise
        except (KeyError, TypeError, ValueError):
            _raise("candidate_invalid")


@dataclass(frozen=True)
class ApprovalResult:
    status: Literal["approved", "already_registered"]
    candidate_id: str
    source_id: str
    manifest_sha256: str

    def to_public_payload(self) -> dict[str, object]:
        return {
            "schema_version": REGISTRATION_SCHEMA_VERSION,
            "status": self.status,
            "candidate_id": self.candidate_id,
            "source_id": self.source_id,
            "manifest_sha256": self.manifest_sha256,
        }


@dataclass(frozen=True)
class CandidateReview:
    candidate_id: str
    status: Literal["rejected", "ignored"]
    reason_code: str

    def to_public_payload(self) -> dict[str, object]:
        return {
            "schema_version": REGISTRATION_SCHEMA_VERSION,
            "status": self.status,
            "candidate_id": self.candidate_id,
            "reason_code": self.reason_code,
        }

    def to_storage_record(self) -> dict[str, object]:
        return self.to_public_payload()


def suggest_protected_source(
    workspace_root: Path,
    relative_path: str,
    *,
    workspace_id: str,
) -> ProtectedSourceCandidate:
    """Create one value-free, explicitly reviewable protected-source candidate."""

    if not isinstance(workspace_id, str) or not workspace_id.strip():
        _raise("candidate_invalid")
    normalized_path = _normalize_relative_path(relative_path)
    source_kind = _source_kind(normalized_path)
    root_fd, root_path, root_stat = _open_workspace(workspace_root)
    try:
        source_text, source_binding = _read_relative_text(
            root_fd,
            normalized_path,
            root_device=root_stat.st_dev,
            maximum_bytes=MAX_PROTECTED_FILE_BYTES,
            unsafe_code="source_not_safe",
            too_large_code="source_too_large",
            not_utf8_code="source_not_utf8",
        )
        manifest_text, manifest_binding = _read_manifest_text(root_fd, root_stat.st_dev)
        _verify_workspace_path(root_path, root_stat)
        manifest = _parse_and_validate_manifest(manifest_text, root_path)
        selector, reason_codes, confidence = _discover_selector(source_kind, source_text)
        proposed_source = _build_proposed_source(normalized_path, selector)
        already_registered = _validate_new_source_against_manifest(
            manifest,
            proposed_source,
            root_path,
        )

        # Prefix the opaque revision so it can always be passed as an argparse
        # option value without being mistaken for another option.
        candidate_revision = f"r1_{secrets.token_urlsafe(32)}"
        revision_sha256 = hashlib.sha256(candidate_revision.encode("ascii")).hexdigest()
        return ProtectedSourceCandidate(
            candidate_id="",
            workspace_id=workspace_id,
            relative_path=normalized_path,
            reason_codes=reason_codes,
            confidence=confidence,
            proposed_source=proposed_source,
            source_binding=source_binding,
            manifest_binding=manifest_binding,
            candidate_revision_sha256=revision_sha256,
            candidate_revision=candidate_revision,
            already_registered=already_registered,
        )
    finally:
        os.close(root_fd)


@contextmanager
def lock_protected_source_workspace(
    workspace_root: Path,
) -> Iterator[ProtectedSourceWorkspaceLock]:
    """Hold the cooperating-writer lock across DB reservation and manifest I/O."""

    root_fd, root_path, root_stat = _open_workspace(workspace_root)
    workspace_lock = ProtectedSourceWorkspaceLock(
        _root_fd=root_fd,
        _root_path=root_path,
        _root_stat=root_stat,
    )
    try:
        _lock_workspace(root_fd)
        _verify_workspace_path(root_path, root_stat)
        yield workspace_lock
    finally:
        workspace_lock._active = False
        os.close(root_fd)


def approve_protected_source(
    workspace_root: Path,
    candidate: ProtectedSourceCandidate | Mapping[str, object],
    *,
    candidate_revision: str | None = None,
    expected_manifest_sha256: str | None = None,
    workspace_lock: ProtectedSourceWorkspaceLock | None = None,
) -> ApprovalResult:
    """Revalidate and atomically add an explicitly approved saved candidate.

    The workspace lock serializes cooperating ToolUseProxy writers. The
    expected manifest hash is an optimistic precondition for external edits,
    not an OS-level compare-and-swap against a non-cooperating same-UID writer.
    """

    if workspace_lock is None:
        with lock_protected_source_workspace(workspace_root) as acquired_lock:
            return approve_protected_source(
                workspace_root,
                candidate,
                candidate_revision=candidate_revision,
                expected_manifest_sha256=expected_manifest_sha256,
                workspace_lock=acquired_lock,
            )

    root_fd, root_path, root_stat = _require_workspace_lock(
        workspace_root,
        workspace_lock,
    )
    saved = _coerce_candidate(candidate)
    supplied_revision = candidate_revision or saved.candidate_revision
    _verify_candidate_revision(saved, supplied_revision)
    expected_sha256 = expected_manifest_sha256 or saved.manifest_sha256
    if not isinstance(expected_sha256, str) or _HEX_SHA256.fullmatch(expected_sha256) is None:
        _raise("candidate_invalid")

    temporary_name: str | None = None
    try:
        _verify_workspace_path(root_path, root_stat)
        manifest_text, initial_manifest_binding = _read_manifest_text(
            root_fd, root_stat.st_dev
        )
        manifest = _parse_and_validate_manifest(manifest_text, root_path)
        existing = _find_existing_source(manifest, saved.proposed_source, root_path)
        source_id = _required_source_id(saved.proposed_source)
        if existing == "exact":
            try:
                if saved.status in {"proposed", "approving"}:
                    _revalidate_source(root_fd, root_stat.st_dev, saved)
                confirmed_binding = _confirm_exact_manifest_durability(
                    root_fd,
                    root_path,
                    root_stat,
                    saved,
                )
            except ProtectedSourceRegistrationError as exc:
                if (
                    saved.status == "approving"
                    and exc.code
                    not in {
                        "manifest_durability_unknown",
                        "manifest_postcondition_failed",
                    }
                ):
                    _raise("manifest_postcondition_failed")
                raise
            return ApprovalResult(
                status="already_registered",
                candidate_id=saved.candidate_id,
                source_id=source_id,
                manifest_sha256=confirmed_binding.sha256,
            )
        if existing == "id_conflict":
            _raise("source_id_conflict")
        if existing == "path_conflict":
            _raise("source_path_conflict")
        if saved.status == "approved":
            _raise("manifest_conflict")
        _revalidate_source(root_fd, root_stat.st_dev, saved)
        if not (
            hmac.compare_digest(initial_manifest_binding.sha256, expected_sha256)
            and hmac.compare_digest(
                initial_manifest_binding.sha256,
                saved.manifest_sha256,
            )
        ):
            _raise("manifest_conflict")
        _preflight_manifest_sources(
            root_fd,
            root_path,
            root_stat.st_dev,
            manifest,
        )

        raw_sources = manifest["sources"]
        assert isinstance(raw_sources, list)
        if len(raw_sources) >= MAX_MANIFEST_SOURCES:
            _raise("manifest_too_many_sources")
        raw_sources.append(_copy_json_object(saved.proposed_source))
        encoded = _encode_manifest(manifest)
        temporary_name = _write_temporary_manifest(root_fd, encoded)
        temporary_path = root_path / temporary_name
        _verify_workspace_path(root_path, root_stat)
        try:
            load_sources_and_chunks(
                root_path,
                temporary_path,
                workspace_id=saved.workspace_id,
            )
        except Exception:
            _raise("manifest_validation_failed")

        _verify_workspace_path(root_path, root_stat)
        _verify_temporary_file(root_fd, temporary_name, root_stat.st_dev, encoded)
        _revalidate_source(root_fd, root_stat.st_dev, saved)
        _, final_manifest_binding = _read_manifest_text(root_fd, root_stat.st_dev)
        if (
            not hmac.compare_digest(final_manifest_binding.sha256, expected_sha256)
            or final_manifest_binding != initial_manifest_binding
        ):
            _raise("manifest_conflict")
        _verify_workspace_path(root_path, root_stat)

        try:
            os.replace(
                temporary_name,
                MANIFEST_FILENAME,
                src_dir_fd=root_fd,
                dst_dir_fd=root_fd,
            )
        except OSError:
            _raise("manifest_write_failed")
        temporary_name = None
        try:
            os.fsync(root_fd)
        except OSError:
            _raise("manifest_durability_unknown")
        try:
            _verify_workspace_path(root_path, root_stat)
            _, installed_binding = _read_manifest_text(root_fd, root_stat.st_dev)
            installed_sha256 = hashlib.sha256(encoded).hexdigest()
            if not hmac.compare_digest(installed_binding.sha256, installed_sha256):
                _raise("manifest_postcondition_failed")
        except ProtectedSourceRegistrationError as exc:
            if exc.code == "manifest_postcondition_failed":
                raise
            _raise("manifest_postcondition_failed")
        return ApprovalResult(
            status="approved",
            candidate_id=saved.candidate_id,
            source_id=source_id,
            manifest_sha256=installed_sha256,
        )
    finally:
        if temporary_name is not None:
            try:
                os.unlink(temporary_name, dir_fd=root_fd)
            except FileNotFoundError:
                pass


def reject_protected_source_candidate(
    candidate: ProtectedSourceCandidate | Mapping[str, object],
    *,
    candidate_revision: str | None = None,
    reason_code: str = "user_rejected",
) -> CandidateReview:
    return _review_candidate(
        candidate,
        candidate_revision=candidate_revision,
        status="rejected",
        reason_code=reason_code,
    )


def ignore_protected_source_candidate(
    candidate: ProtectedSourceCandidate | Mapping[str, object],
    *,
    candidate_revision: str | None = None,
    reason_code: str = "deferred",
) -> CandidateReview:
    return _review_candidate(
        candidate,
        candidate_revision=candidate_revision,
        status="ignored",
        reason_code=reason_code,
    )


def _review_candidate(
    candidate: ProtectedSourceCandidate | Mapping[str, object],
    *,
    candidate_revision: str | None,
    status: Literal["rejected", "ignored"],
    reason_code: str,
) -> CandidateReview:
    saved = _coerce_candidate(candidate)
    _verify_candidate_revision(saved, candidate_revision or saved.candidate_revision)
    if reason_code not in _REVIEW_REASON_CODES:
        _raise("review_reason_invalid")
    return CandidateReview(
        candidate_id=saved.candidate_id,
        status=status,
        reason_code=reason_code,
    )


def _coerce_candidate(
    candidate: ProtectedSourceCandidate | Mapping[str, object],
) -> ProtectedSourceCandidate:
    if isinstance(candidate, ProtectedSourceCandidate):
        return candidate
    if isinstance(candidate, Mapping):
        return ProtectedSourceCandidate.from_storage_record(candidate)
    _raise("candidate_invalid")


def _verify_candidate_revision(
    candidate: ProtectedSourceCandidate,
    revision: str | None,
) -> None:
    if not isinstance(revision, str) or not revision or len(revision) > 256:
        _raise("candidate_revision_invalid")
    try:
        encoded = revision.encode("ascii")
    except UnicodeEncodeError:
        _raise("candidate_revision_invalid")
    supplied_sha256 = hashlib.sha256(encoded).hexdigest()
    if not hmac.compare_digest(supplied_sha256, candidate.candidate_revision_sha256):
        _raise("candidate_revision_invalid")


def _revalidate_source(
    root_fd: int,
    root_device: int,
    candidate: ProtectedSourceCandidate,
) -> None:
    text, binding = _read_relative_text(
        root_fd,
        candidate.relative_path,
        root_device=root_device,
        maximum_bytes=MAX_PROTECTED_FILE_BYTES,
        unsafe_code="source_not_safe",
        too_large_code="source_too_large",
        not_utf8_code="source_not_utf8",
    )
    if not _source_binding_matches(binding, candidate.source_binding):
        _raise("source_changed")
    source_kind = _source_kind(candidate.relative_path)
    selector, reason_codes, confidence = _discover_selector(source_kind, text)
    proposed = _build_proposed_source(candidate.relative_path, selector)
    if (
        proposed != candidate.proposed_source
        or reason_codes != candidate.reason_codes
        or confidence != candidate.confidence
    ):
        _raise("source_changed")


def _discover_selector(
    source_kind: Literal["dotenv", "json"],
    text: str,
) -> tuple[dict[str, list[str]], tuple[str, ...], float]:
    if source_kind == "dotenv":
        keys = _discover_dotenv_keys(text)
        return {"dotenv_keys": keys}, ("secret_like_dotenv_key",), 0.95
    pointers = _discover_json_pointers(text)
    return {"json_pointers": pointers}, ("secret_like_json_key",), 0.95


def _discover_dotenv_keys(text: str) -> list[str]:
    selected: list[str] = []
    seen: set[str] = set()
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        match = _DOTENV_ASSIGNMENT.fullmatch(line)
        if match is None:
            _raise("source_not_parseable")
        key = match.group(1)
        if key in seen:
            _raise("dotenv_duplicate_key")
        seen.add(key)
        value = _parse_dotenv_value(match.group(2))
        if value is None:
            _raise("source_not_parseable")
        if value.strip() and _is_secret_like_key(key):
            selected.append(key)
    if not selected:
        _raise("no_secret_selector")
    if len(selected) > MAX_SELECTOR_VALUES:
        _raise("too_many_selectors")
    if any(len(key.encode("utf-8")) > MAX_SELECTOR_VALUE_BYTES for key in selected):
        _raise("selector_too_long")
    return sorted(selected)


def _parse_dotenv_value(raw_value: str) -> str | None:
    value = raw_value.lstrip()
    if not value:
        return ""
    if value[0] == "'":
        closing = value.find("'", 1)
        if closing < 0 or not _valid_dotenv_trailing(value[closing + 1 :]):
            return None
        return value[1:closing]
    if value[0] == '"':
        decoded: list[str] = []
        escaped = False
        closing: int | None = None
        for index, character in enumerate(value[1:], start=1):
            if escaped:
                decoded.append(
                    {
                        "n": "\n",
                        "r": "\r",
                        "t": "\t",
                        '"': '"',
                        "\\": "\\",
                    }.get(character, f"\\{character}")
                )
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                closing = index
                break
            else:
                decoded.append(character)
        if escaped or closing is None:
            return None
        if not _valid_dotenv_trailing(value[closing + 1 :]):
            return None
        return "".join(decoded)
    if "\\" in value or "'" in value or '"' in value:
        return None
    return _strip_dotenv_inline_comment(value).rstrip()


def _valid_dotenv_trailing(trailing: str) -> bool:
    stripped = trailing.strip()
    return not stripped or stripped.startswith("#")


def _strip_dotenv_inline_comment(value: str) -> str:
    for index, character in enumerate(value):
        if character == "#" and (index == 0 or value[index - 1].isspace()):
            return value[:index]
    return value


def _discover_json_pointers(text: str) -> list[str]:
    payload = _strict_json_loads(text, duplicate_code="json_duplicate_key")
    pointers: list[str] = []
    item_count = 0

    def walk(value: object, pointer: str, depth: int) -> None:
        nonlocal item_count
        if depth > MAX_JSON_DEPTH:
            _raise("json_too_deep")
        if isinstance(value, dict):
            for key, child in value.items():
                item_count += 1
                if item_count > MAX_JSON_ITEMS:
                    _raise("json_too_many_items")
                child_pointer = f"{pointer}/{_escape_json_pointer_segment(key)}"
                if (
                    isinstance(child, str)
                    and child.strip()
                    and _is_secret_like_key(key)
                ):
                    pointers.append(child_pointer)
                walk(child, child_pointer, depth + 1)
        elif isinstance(value, list):
            for index, child in enumerate(value):
                item_count += 1
                if item_count > MAX_JSON_ITEMS:
                    _raise("json_too_many_items")
                walk(child, f"{pointer}/{index}", depth + 1)

    walk(payload, "", 0)
    if not pointers:
        _raise("no_secret_selector")
    if len(pointers) > MAX_SELECTOR_VALUES:
        _raise("too_many_selectors")
    if any(
        len(pointer.encode("utf-8")) > MAX_SELECTOR_VALUE_BYTES
        for pointer in pointers
    ):
        _raise("selector_too_long")
    return sorted(pointers)


def _strict_json_loads(text: str, *, duplicate_code: str) -> object:
    def reject_duplicate_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                _raise(duplicate_code)
            result[key] = value
        return result

    def reject_constant(_: str) -> NoReturn:
        _raise("source_not_parseable")

    try:
        return json.loads(
            text,
            object_pairs_hook=reject_duplicate_pairs,
            parse_constant=reject_constant,
        )
    except ProtectedSourceRegistrationError:
        raise
    except (json.JSONDecodeError, RecursionError, ValueError):
        _raise("source_not_parseable")


def _strict_candidate_json(text: str) -> dict[str, object]:
    try:
        value = _strict_json_loads(text, duplicate_code="candidate_invalid")
    except ProtectedSourceRegistrationError:
        _raise("candidate_invalid")
    if not isinstance(value, dict):
        _raise("candidate_invalid")
    return value


def _is_secret_like_key(key: str) -> bool:
    snake = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", key)
    normalized = re.sub(r"[^A-Za-z0-9]+", "_", snake).strip("_").casefold()
    if not normalized:
        return False
    if normalized in _SECRET_MARKERS:
        return True
    segments = tuple(part for part in normalized.split("_") if part)
    if any(marker in segments for marker in _SECRET_MARKERS if "_" not in marker):
        return True
    joined_pairs = {"_".join(segments[index : index + 2]) for index in range(len(segments) - 1)}
    return bool(joined_pairs & _SECRET_MARKERS)


def _escape_json_pointer_segment(value: str) -> str:
    return value.replace("~", "~0").replace("/", "~1")


def _build_proposed_source(
    relative_path: str,
    selector: dict[str, list[str]],
) -> dict[str, object]:
    path = PurePath(relative_path)
    slug_source = re.sub(r"[^a-z0-9]+", "_", path.name.casefold()).strip("_")
    slug = slug_source[:40] or "source"
    identity = f"{DETECTOR_VERSION}\0{relative_path}".encode("utf-8")
    source_id = f"protected_{slug}_{hashlib.sha256(identity).hexdigest()[:16]}"
    if _SAFE_SOURCE_ID.fullmatch(source_id) is None:
        _raise("candidate_invalid")
    return {
        "id": source_id,
        "path": relative_path,
        "type": "secretfile",
        "sensitivity": "high",
        "policy_tags": ["no_external", "no_search"],
        "selector": selector,
    }


def _validate_proposed_source(
    value: dict[str, object],
    *,
    expected_path: str,
) -> dict[str, object]:
    expected_keys = {"id", "path", "type", "sensitivity", "policy_tags", "selector"}
    if set(value) != expected_keys:
        _raise("candidate_invalid")
    source_id = value.get("id")
    path = value.get("path")
    source_type = value.get("type")
    sensitivity = value.get("sensitivity")
    tags = value.get("policy_tags")
    selector = value.get("selector")
    if (
        not isinstance(source_id, str)
        or _SAFE_SOURCE_ID.fullmatch(source_id) is None
        or path != expected_path
        or source_type != "secretfile"
        or sensitivity != "high"
        or tags != ["no_external", "no_search"]
        or not isinstance(selector, Mapping)
        or len(selector) != 1
    ):
        _raise("candidate_invalid")
    kind = next(iter(selector))
    expected_kind = "dotenv_keys" if _source_kind(expected_path) == "dotenv" else "json_pointers"
    values = selector.get(kind)
    if (
        kind != expected_kind
        or not isinstance(values, Sequence)
        or isinstance(values, (str, bytes))
        or not values
        or len(values) > MAX_SELECTOR_VALUES
        or not all(isinstance(item, str) and item for item in values)
        or any(
            len(item.encode("utf-8")) > MAX_SELECTOR_VALUE_BYTES
            for item in values
            if isinstance(item, str)
        )
        or len(set(values)) != len(values)
        or list(values) != sorted(values)
    ):
        _raise("candidate_invalid")
    return _copy_json_object(value)


def _source_kind(relative_path: str) -> Literal["dotenv", "json"]:
    name = PurePath(relative_path).name.casefold()
    if name == ".env" or name.startswith(".env."):
        return "dotenv"
    if name.endswith(".json"):
        return "json"
    _raise("unsupported_source_format")


def _normalize_relative_path(value: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        _raise("invalid_relative_path")
    path = PurePath(value)
    if path.is_absolute():
        _raise("invalid_relative_path")
    parts = path.parts
    if (
        not parts
        or any(part in {"", ".", ".."} for part in parts)
        or any(any(ord(character) < 32 for character in part) for part in parts)
    ):
        _raise("invalid_relative_path")
    normalized = Path(*parts).as_posix()
    if normalized != value.replace(os.sep, "/"):
        _raise("invalid_relative_path")
    return normalized


def _open_workspace(workspace_root: Path) -> tuple[int, Path, os.stat_result]:
    try:
        root_path = Path(os.path.abspath(os.fspath(workspace_root)))
        metadata = os.lstat(root_path)
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            _raise("invalid_workspace")
        flags = os.O_RDONLY
        flags |= getattr(os, "O_DIRECTORY", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(root_path, flags)
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(opened.st_mode)
            or opened.st_dev != metadata.st_dev
            or opened.st_ino != metadata.st_ino
        ):
            os.close(descriptor)
            _raise("invalid_workspace")
        return descriptor, root_path, opened
    except ProtectedSourceRegistrationError:
        raise
    except (OSError, TypeError, ValueError):
        _raise("invalid_workspace")


def _require_workspace_lock(
    workspace_root: Path,
    workspace_lock: ProtectedSourceWorkspaceLock,
) -> tuple[int, Path, os.stat_result]:
    try:
        requested_path = Path(os.path.abspath(os.fspath(workspace_root)))
        if (
            not isinstance(workspace_lock, ProtectedSourceWorkspaceLock)
            or not workspace_lock._active
            or requested_path != workspace_lock._root_path
        ):
            _raise("invalid_workspace")
        opened = os.fstat(workspace_lock._root_fd)
        expected = workspace_lock._root_stat
        if (
            not stat.S_ISDIR(opened.st_mode)
            or opened.st_dev != expected.st_dev
            or opened.st_ino != expected.st_ino
        ):
            _raise("invalid_workspace")
        _verify_workspace_path(workspace_lock._root_path, expected)
        return (
            workspace_lock._root_fd,
            workspace_lock._root_path,
            expected,
        )
    except ProtectedSourceRegistrationError:
        raise
    except (OSError, TypeError, ValueError):
        _raise("invalid_workspace")


def _verify_workspace_path(root_path: Path, expected: os.stat_result) -> None:
    try:
        current = os.lstat(root_path)
    except OSError:
        _raise("invalid_workspace")
    if (
        stat.S_ISLNK(current.st_mode)
        or not stat.S_ISDIR(current.st_mode)
        or current.st_dev != expected.st_dev
        or current.st_ino != expected.st_ino
    ):
        _raise("invalid_workspace")


def _confirm_exact_manifest_durability(
    root_fd: int,
    root_path: Path,
    root_stat: os.stat_result,
    candidate: ProtectedSourceCandidate,
) -> FileBinding:
    try:
        os.fsync(root_fd)
    except OSError:
        _raise("manifest_durability_unknown")
    _verify_workspace_path(root_path, root_stat)
    manifest_text, manifest_binding = _read_manifest_text(root_fd, root_stat.st_dev)
    manifest = _parse_and_validate_manifest(manifest_text, root_path)
    if _find_existing_source(manifest, candidate.proposed_source, root_path) != "exact":
        _raise("manifest_postcondition_failed")
    if candidate.status in {"proposed", "approving"}:
        _revalidate_source(root_fd, root_stat.st_dev, candidate)
    _verify_workspace_path(root_path, root_stat)
    return manifest_binding


def _read_manifest_text(root_fd: int, root_device: int) -> tuple[str, FileBinding]:
    try:
        return _read_relative_text(
            root_fd,
            MANIFEST_FILENAME,
            root_device=root_device,
            maximum_bytes=MAX_PROTECTED_FILE_BYTES,
            unsafe_code="manifest_not_safe",
            too_large_code="manifest_too_large",
            not_utf8_code="manifest_not_utf8",
        )
    except ProtectedSourceRegistrationError as exc:
        if exc.code == "manifest_not_safe":
            try:
                os.stat(MANIFEST_FILENAME, dir_fd=root_fd, follow_symlinks=False)
            except FileNotFoundError:
                _raise("manifest_missing")
        raise


def _read_relative_text(
    root_fd: int,
    relative_path: str,
    *,
    root_device: int,
    maximum_bytes: int,
    unsafe_code: str,
    too_large_code: str,
    not_utf8_code: str,
) -> tuple[str, FileBinding]:
    parts = PurePath(relative_path).parts
    current_fd = os.dup(root_fd)
    file_fd: int | None = None
    try:
        for part in parts[:-1]:
            flags = os.O_RDONLY
            flags |= getattr(os, "O_DIRECTORY", 0)
            flags |= getattr(os, "O_NOFOLLOW", 0)
            next_fd = os.open(part, flags, dir_fd=current_fd)
            opened = os.fstat(next_fd)
            if not stat.S_ISDIR(opened.st_mode) or opened.st_dev != root_device:
                os.close(next_fd)
                _raise(unsafe_code)
            os.close(current_fd)
            current_fd = next_fd

        flags = os.O_RDONLY
        flags |= getattr(os, "O_NOFOLLOW", 0)
        flags |= getattr(os, "O_NONBLOCK", 0)
        file_fd = os.open(parts[-1], flags, dir_fd=current_fd)
        before = os.fstat(file_fd)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_dev != root_device
            or before.st_nlink != 1
        ):
            _raise(unsafe_code)
        if before.st_size > maximum_bytes:
            _raise(too_large_code)
        body = _read_bounded(file_fd, maximum_bytes, too_large_code=too_large_code)
        after = os.fstat(file_fd)
        if not _same_stat(before, after):
            _raise(unsafe_code)
        try:
            text = body.decode("utf-8")
        except UnicodeDecodeError:
            _raise(not_utf8_code)
        return text, _make_binding(body, after)
    except ProtectedSourceRegistrationError:
        raise
    except (OSError, ValueError):
        _raise(unsafe_code)
    finally:
        if file_fd is not None:
            os.close(file_fd)
        os.close(current_fd)


def _read_bounded(
    file_fd: int,
    maximum_bytes: int,
    *,
    too_large_code: str,
) -> bytes:
    chunks: list[bytes] = []
    remaining = maximum_bytes + 1
    while remaining:
        chunk = os.read(file_fd, min(64 * 1024, remaining))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    body = b"".join(chunks)
    if len(body) > maximum_bytes:
        _raise(too_large_code)
    return body


def _same_stat(left: os.stat_result, right: os.stat_result) -> bool:
    return all(
        getattr(left, name) == getattr(right, name)
        for name in (
            "st_dev",
            "st_ino",
            "st_mode",
            "st_nlink",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
        )
    )


def _make_binding(body: bytes, metadata: os.stat_result) -> FileBinding:
    return FileBinding(
        sha256=hashlib.sha256(body).hexdigest(),
        device=metadata.st_dev,
        inode=metadata.st_ino,
        size=metadata.st_size,
        mtime_ns=metadata.st_mtime_ns,
        ctime_ns=metadata.st_ctime_ns,
        mode=metadata.st_mode,
        link_count=metadata.st_nlink,
    )


def _source_binding_matches(current: FileBinding, saved: FileBinding) -> bool:
    return (
        hmac.compare_digest(current.sha256, saved.sha256)
        and current.size == saved.size
        and current.mtime_ns == saved.mtime_ns
        and (saved.device == 0 or current.device == saved.device)
        and (saved.inode == 0 or current.inode == saved.inode)
    )


def _flat_source_binding_record(value: Mapping[str, object]) -> dict[str, object]:
    return {
        "sha256": value.get("source_sha256"),
        "device": _optional_binding_integer(value.get("source_device")),
        "inode": _optional_binding_integer(value.get("source_inode")),
        "size": value.get("source_size"),
        "mtime_ns": value.get("source_mtime_ns"),
        "ctime_ns": 0,
        "mode": 0,
        "link_count": 0,
    }


def _flat_manifest_binding_record(value: Mapping[str, object]) -> dict[str, object]:
    return {
        "sha256": value.get("manifest_sha256"),
        "device": 0,
        "inode": 0,
        "size": 0,
        "mtime_ns": 0,
        "ctime_ns": 0,
        "mode": 0,
        "link_count": 0,
    }


def _optional_binding_integer(value: object) -> object:
    return 0 if value is None else value


def _parse_and_validate_manifest(text: str, root_path: Path) -> dict[str, object]:
    try:
        payload = _strict_json_loads(text, duplicate_code="manifest_invalid_json")
    except ProtectedSourceRegistrationError as exc:
        if exc.code in {"source_not_parseable", "json_duplicate_key"}:
            _raise("manifest_invalid_json")
        raise
    if not isinstance(payload, dict):
        _raise("manifest_invalid_json")
    schema_version = payload.get("schema_version", 1)
    if type(schema_version) is not int:
        _raise("manifest_schema_invalid")
    if schema_version == 1:
        _raise("manifest_schema_legacy")
    if schema_version > 2:
        _raise("manifest_schema_future")
    if schema_version != 2:
        _raise("manifest_schema_invalid")
    sources = payload.get("sources")
    if not isinstance(sources, list):
        _raise("manifest_sources_invalid")
    if len(sources) > MAX_MANIFEST_SOURCES:
        _raise("manifest_too_many_sources")

    source_ids: set[str] = set()
    canonical_paths: set[str] = set()
    for source in sources:
        if not isinstance(source, dict):
            _raise("manifest_source_invalid")
        source_id = source.get("id")
        source_path = source.get("path")
        if (
            not isinstance(source_id, str)
            or not source_id.strip()
            or not isinstance(source_path, str)
            or not source_path.strip()
        ):
            _raise("manifest_source_invalid")
        if source_id in source_ids:
            _raise("manifest_duplicate_id")
        source_ids.add(source_id)
        canonical_path = _canonical_manifest_source_path(root_path, source_path)
        if canonical_path in canonical_paths:
            _raise("manifest_duplicate_path")
        canonical_paths.add(canonical_path)
    return payload


def _validate_new_source_against_manifest(
    manifest: dict[str, object],
    proposed_source: dict[str, object],
    root_path: Path,
) -> bool:
    result = _find_existing_source(manifest, proposed_source, root_path)
    if result == "id_conflict":
        _raise("source_id_conflict")
    if result == "path_conflict":
        _raise("source_path_conflict")
    return result == "exact"


def _preflight_manifest_sources(
    root_fd: int,
    root_path: Path,
    root_device: int,
    manifest: Mapping[str, object],
) -> None:
    raw_sources = manifest.get("sources")
    if not isinstance(raw_sources, list):
        _raise("manifest_sources_invalid")
    for raw_source in raw_sources:
        if not isinstance(raw_source, Mapping):
            _raise("manifest_source_invalid")
        source_path = raw_source.get("path")
        if not isinstance(source_path, str):
            _raise("manifest_source_invalid")
        try:
            candidate = Path(source_path).expanduser()
            if not candidate.is_absolute():
                candidate = root_path / candidate
            absolute = Path(os.path.abspath(os.path.normpath(candidate)))
            relative = absolute.relative_to(root_path).as_posix()
        except (OSError, RuntimeError, TypeError, ValueError):
            _raise("manifest_source_invalid")
        _read_relative_text(
            root_fd,
            relative,
            root_device=root_device,
            maximum_bytes=MAX_PROTECTED_FILE_BYTES,
            unsafe_code="manifest_source_invalid",
            too_large_code="manifest_source_too_large",
            not_utf8_code="manifest_source_invalid",
        )


def _find_existing_source(
    manifest: dict[str, object],
    proposed_source: dict[str, object],
    root_path: Path,
) -> Literal["none", "exact", "id_conflict", "path_conflict"]:
    raw_sources = manifest.get("sources")
    if not isinstance(raw_sources, list):
        _raise("manifest_sources_invalid")
    proposed_id = _required_source_id(proposed_source)
    proposed_path = proposed_source.get("path")
    assert isinstance(proposed_path, str)
    proposed_canonical = _canonical_manifest_source_path(root_path, proposed_path)
    for raw_source in raw_sources:
        if not isinstance(raw_source, dict):
            _raise("manifest_source_invalid")
        if raw_source.get("id") == proposed_id:
            return "exact" if raw_source == proposed_source else "id_conflict"
        raw_path = raw_source.get("path")
        if not isinstance(raw_path, str):
            _raise("manifest_source_invalid")
        if _canonical_manifest_source_path(root_path, raw_path) == proposed_canonical:
            return "path_conflict"
    return "none"


def _canonical_manifest_source_path(root_path: Path, source_path: str) -> str:
    try:
        candidate = Path(source_path).expanduser()
        if not candidate.is_absolute():
            candidate = root_path / candidate
        lexical = Path(os.path.abspath(os.path.normpath(candidate)))
        if os.path.commonpath((root_path, lexical)) != str(root_path):
            _raise("manifest_source_invalid")
        relative = lexical.relative_to(root_path)
        if not relative.parts:
            _raise("manifest_source_invalid")
        current = root_path
        for part in relative.parts:
            current = current / part
            metadata = os.lstat(current)
            if stat.S_ISLNK(metadata.st_mode):
                _raise("manifest_source_invalid")
        metadata = os.lstat(current)
        if not stat.S_ISREG(metadata.st_mode):
            _raise("manifest_source_invalid")
        return f"{metadata.st_dev}:{metadata.st_ino}"
    except ProtectedSourceRegistrationError:
        raise
    except (OSError, RuntimeError, TypeError, ValueError):
        _raise("manifest_source_invalid")


def _required_source_id(source: Mapping[str, object]) -> str:
    source_id = source.get("id")
    if not isinstance(source_id, str) or _SAFE_SOURCE_ID.fullmatch(source_id) is None:
        _raise("candidate_invalid")
    return source_id


def _lock_workspace(root_fd: int) -> None:
    if fcntl is None:
        _raise("workspace_lock_unavailable")
    try:
        fcntl.flock(root_fd, fcntl.LOCK_EX)
    except OSError:
        _raise("manifest_write_failed")


def _encode_manifest(manifest: dict[str, object]) -> bytes:
    try:
        encoded = (
            json.dumps(manifest, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
        ).encode("utf-8")
    except (TypeError, ValueError):
        _raise("manifest_invalid_json")
    if len(encoded) > MAX_PROTECTED_FILE_BYTES:
        _raise("manifest_too_large")
    return encoded


def _write_temporary_manifest(root_fd: int, encoded: bytes) -> str:
    temporary_name = f".{MANIFEST_FILENAME}.{secrets.token_hex(16)}.tmp"
    descriptor: int | None = None
    completed = False
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(temporary_name, flags, 0o600, dir_fd=root_fd)
        if os.name == "posix":
            os.fchmod(descriptor, 0o600)
        view = memoryview(encoded)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                _raise("manifest_write_failed")
            view = view[written:]
        os.fsync(descriptor)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            _raise("manifest_write_failed")
        completed = True
        return temporary_name
    except ProtectedSourceRegistrationError:
        raise
    except OSError:
        _raise("manifest_write_failed")
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if not completed:
            try:
                os.unlink(temporary_name, dir_fd=root_fd)
            except FileNotFoundError:
                pass


def _verify_temporary_file(
    root_fd: int,
    temporary_name: str,
    root_device: int,
    expected: bytes,
) -> None:
    try:
        text, binding = _read_relative_text(
            root_fd,
            temporary_name,
            root_device=root_device,
            maximum_bytes=MAX_PROTECTED_FILE_BYTES,
            unsafe_code="manifest_write_failed",
            too_large_code="manifest_write_failed",
            not_utf8_code="manifest_write_failed",
        )
    except ProtectedSourceRegistrationError:
        raise
    if text.encode("utf-8") != expected or not hmac.compare_digest(
        binding.sha256, hashlib.sha256(expected).hexdigest()
    ):
        _raise("manifest_write_failed")


def _canonical_json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _copy_json_object(value: Mapping[str, object]) -> dict[str, object]:
    try:
        copied = json.loads(json.dumps(value, ensure_ascii=False, allow_nan=False))
    except (TypeError, ValueError):
        _raise("candidate_invalid")
    if not isinstance(copied, dict):
        _raise("candidate_invalid")
    return copied


def _raise(code: str) -> NoReturn:
    raise ProtectedSourceRegistrationError(code)
