from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import stat
import unicodedata
from collections.abc import Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field, replace
from pathlib import Path, PurePath
from typing import Iterator, Literal, NoReturn

from hook_monitor.analysis.source_index import load_sources_and_chunks
from hook_monitor.runtime.source_config import (
    CURRENT_MANIFEST_SCHEMA_VERSION,
    LEGACY_MANIFEST_SCHEMA_VERSION,
)

try:  # pragma: no cover - exercised on the supported POSIX runtime
    import fcntl
except ImportError:  # pragma: no cover - Windows compatibility fallback
    fcntl = None  # type: ignore[assignment]


REGISTRATION_SCHEMA_VERSION = 1
LEGACY_DETECTOR_VERSION = "protected-source-candidate-v1"
DETECTOR_VERSION = "protected-source-candidate-v2"
# Source ids are durable manifest identities. Detector upgrades may change the
# evidence used to propose a source, but must not rename the same path.
_SOURCE_ID_DERIVATION_DOMAIN = LEGACY_DETECTOR_VERSION
MANIFEST_FILENAME = "protected_sources.json"
MAX_PROTECTED_FILE_BYTES = 1024 * 1024
MAX_JSON_DEPTH = 32
MAX_JSON_ITEMS = 4096
MAX_SELECTOR_VALUES = 256
MAX_SELECTOR_VALUE_BYTES = 4096
MAX_MANIFEST_SOURCES = 256
MANIFEST_MIGRATION_KIND = "protected_sources_manifest_v1_to_v2"
MANIFEST_MIGRATION_WRITER_VERSION = "protected-source-manifest-migration-v1"
MANIFEST_MIGRATION_FORMATTING_POLICY = "utf8_2_space_lf"
MANIFEST_BACKUP_DIRECTORY = "manifest-backups"
PROTECTED_SOURCE_SCANNER_VERSION = "protected-source-scan-v1"


@dataclass(frozen=True)
class ProtectedSourceScanLimits:
    max_depth: int = 8
    max_entries: int = 20_000
    max_files: int = 10_000
    max_eligible_files: int = 512
    max_total_read_bytes: int = 16 * 1024 * 1024
    max_candidates: int = 64
    max_public_metadata_bytes: int = 512 * 1024


DEFAULT_PROTECTED_SOURCE_SCAN_LIMITS = ProtectedSourceScanLimits()

_PROTECTED_SOURCE_SCAN_EXCLUDED_DIRECTORIES = frozenset(
    {
        ".cache",
        ".git",
        ".hg",
        ".mypy_cache",
        ".next",
        ".nox",
        ".nuxt",
        ".pytest_cache",
        ".ruff_cache",
        ".svn",
        ".tooluseproxy",
        ".tox",
        ".turbo",
        ".venv",
        "__pycache__",
        "build",
        "dist",
        "node_modules",
        "site-packages",
        "target",
        "vendor",
        "venv",
    }
)
_PROTECTED_SOURCE_SCAN_MAX_RELATIVE_PATH_BYTES = 4096
_PROTECTED_SOURCE_SCAN_REASON_ORDER = (
    "entry_limit",
    "depth_limit",
    "file_limit",
    "eligible_file_limit",
    "total_read_bytes_limit",
    "candidate_limit",
    "public_metadata_limit",
    "directory_read_error",
    "entry_read_error",
    "invalid_name",
    "source_changed",
    "source_not_safe",
    "source_not_utf8",
    "source_not_parseable",
    "dotenv_duplicate_key",
    "json_duplicate_key",
    "json_too_deep",
    "json_too_many_items",
    "too_many_selectors",
    "selector_too_long",
    "source_id_conflict",
    "source_path_conflict",
    "source_too_large",
    "excluded_path",
    "excluded_directory",
    "symlink",
    "hardlink",
    "non_regular",
    "cross_device",
    "no_secret_selector",
)

_DOTENV_ASSIGNMENT = re.compile(
    r"^(?:export\s+)?([A-Za-z_][A-Za-z0-9_.-]*)\s*=(.*)$"
)
_ACRONYM_KEY_BOUNDARY = re.compile(r"([A-Z]+)([A-Z][a-z])")
_CAMEL_KEY_BOUNDARY = re.compile(r"([a-z0-9])([A-Z])")
_NON_ASCII_ALNUM = re.compile(r"[^A-Za-z0-9]+")
_SHELL_REFERENCE = re.compile(r"\$[A-Za-z_][A-Za-z0-9_]*\Z")
_BRACED_SHELL_REFERENCE = re.compile(
    r"\$\{[A-Za-z_][A-Za-z0-9_]*(?::[-+?=][^{}]*)?\}\Z"
)
_MUSTACHE_REFERENCE = re.compile(r"\{\{[^{}]+\}\}\Z")
_ANGLE_PLACEHOLDER = re.compile(r"<[^<>]+>\Z")
_REFERENCE_URI = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://\S+\Z")
_REFERENCE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,255}\Z")
_METADATA_DESCRIPTOR = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/ -]{0,255}\Z")
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
_V2_SECRET_MARKERS = _SECRET_MARKERS | frozenset(
    {"authentication", "authorization"}
)
_DEFINITIVE_PLACEHOLDER_VALUES = frozenset(
    {
        "change_me",
        "changeme",
        "configure_later",
        "example_only",
        "illustrative_only",
        "not_set",
        "redacted",
        "replace_me",
        "replace_this",
        "set_me",
        "unset",
        "withheld",
    }
)
_WEAK_PLACEHOLDER_TOKENS = frozenset(
    {
        "demo",
        "dummy",
        "example",
        "fake",
        "fixture",
        "illustrative",
        "mock",
        "sample",
        "test",
    }
)
_PLACEHOLDER_BASENAME_TOKENS = _WEAK_PLACEHOLDER_TOKENS | frozenset(
    {
        "blueprint",
        "cookbook",
        "default",
        "defaults",
        "dist",
        "placeholder",
        "reference",
        "skeleton",
        "template",
    }
)
_PROTOCOL_METADATA_VALUES = frozenset(
    {
        "access",
        "api_key",
        "authorization_code",
        "basic",
        "bearer",
        "client_secret_basic",
        "client_secret_jwt",
        "client_secret_post",
        "digest",
        "dpop",
        "id_token",
        "jwt",
        "mac",
        "none",
        "ntlm",
        "oauth",
        "oauth2",
        "oidc",
        "openid",
        "password",
        "private_key_jwt",
        "refresh",
        "refresh_token",
        "saml",
    }
)
_ALGORITHM_METADATA_VALUES = frozenset(
    {
        "aes",
        "ed25519",
        "es256",
        "es384",
        "es512",
        "hs256",
        "hs384",
        "hs512",
        "none",
        "ps256",
        "ps384",
        "ps512",
        "rs256",
        "rs384",
        "rs512",
        "rsa",
    }
)
_METADATA_KEY_QUALIFIERS = frozenset(
    {
        "algorithm",
        "endpoint",
        "file",
        "format",
        "header",
        "id",
        "identifier",
        "method",
        "mode",
        "name",
        "path",
        "policy",
        "prefix",
        "ref",
        "reference",
        "scheme",
        "scope",
        "scopes",
        "type",
        "uri",
        "url",
        "version",
    }
)
_SECRET_MANAGER_REFERENCE_PREFIXES = (
    "arn:aws:secretsmanager:",
    "arn:aws:ssm:",
    "aws-secretsmanager://",
    "azure-keyvault://",
    "doppler://",
    "gcp-secret-manager://",
    "op://",
    "secret-manager://",
    "secret://",
    "sm://",
    "ssm://",
    "vault://",
)
_MAX_VALUE_CLASSIFICATION_CHARACTERS = 8192
_SCALAR_LABEL_ALIASES = {
    "d_po_p": "dpop",
    "o_auth": "oauth",
    "o_auth2": "oauth2",
    "open_id": "openid",
}
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
    "candidate_detector_stale": "saved candidate uses a stale detector version",
    "candidate_revision_invalid": "candidate revision does not match the saved candidate",
    "review_reason_invalid": "candidate review reason code is invalid",
    "manifest_validation_failed": "the updated protected source manifest is invalid",
    "manifest_write_failed": "protected_sources.json could not be updated safely",
    "workspace_lock_unavailable": "exclusive workspace locking is unavailable",
    "manifest_durability_unknown": "protected_sources.json was replaced but durability is unknown",
    "manifest_postcondition_failed": "protected_sources.json update could not be verified",
    "manifest_migration_not_required": "protected_sources.json is already schema version 2",
    "manifest_migration_revision_invalid": "manifest migration revision does not match the reviewed plan",
    "manifest_migration_conflict": "protected_sources.json changed after the migration plan was created",
    "manifest_migration_validation_failed": "the migrated protected source manifest is invalid",
    "manifest_backup_unavailable": "the private manifest backup directory is unavailable",
    "manifest_backup_missing": "the original manifest backup required for recovery is missing",
    "manifest_backup_conflict": "the original manifest backup does not match the reviewed migration",
    "scan_limits_invalid": "protected source scan limits are invalid",
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
    source_binding: FileBinding = field(repr=False)
    manifest_binding: FileBinding = field(repr=False)
    candidate_revision_sha256: str = field(repr=False)
    detector_version: str = DETECTOR_VERSION
    candidate_revision: str | None = field(default=None, repr=False)
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
            if isinstance(detector_version, str):
                if detector_version not in {
                    DETECTOR_VERSION,
                    LEGACY_DETECTOR_VERSION,
                }:
                    _raise("candidate_detector_stale")
                if (
                    detector_version == LEGACY_DETECTOR_VERSION
                    and status == "proposed"
                ):
                    _raise("candidate_detector_stale")
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
                or detector_version
                not in {DETECTOR_VERSION, LEGACY_DETECTOR_VERSION}
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
class ProtectedSourceScanResult:
    scanner_version: str
    manifest_sha256: str
    scan_complete: bool
    truncation_reasons: tuple[str, ...]
    candidates: tuple[ProtectedSourceCandidate, ...] = field(repr=False)
    already_registered_count: int = 0
    entries_seen: int = 0
    directories_scanned: int = 0
    files_seen: int = 0
    eligible_files_seen: int = 0
    inspected_bytes: int = 0
    detected_candidate_count: int = 0
    public_candidate_bytes: int = 0
    skipped_counts: tuple[tuple[str, int], ...] = ()


@dataclass(repr=False)
class _ProtectedSourceScanState:
    limits: ProtectedSourceScanLimits
    excluded_relative_parts: tuple[tuple[str, ...], ...]
    excluded_path_identities: frozenset[tuple[int, int]]
    registered_file_identities: frozenset[str]
    entries_seen: int = 0
    directories_scanned: int = 0
    files_seen: int = 0
    eligible_files_seen: int = 0
    inspected_bytes: int = 0
    detected_candidate_count: int = 0
    already_registered_count: int = 0
    public_candidate_bytes: int = 0
    candidates: list[ProtectedSourceCandidate] = field(default_factory=list)
    skipped_counts: dict[str, int] = field(default_factory=dict)
    incomplete_reasons: set[str] = field(default_factory=set)
    entry_limit_reached: bool = False

    def skip(self, code: str, *, incomplete: bool = False) -> None:
        self.skipped_counts[code] = self.skipped_counts.get(code, 0) + 1
        if incomplete:
            self.incomplete_reasons.add(code)


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


@dataclass(frozen=True)
class ProtectedSourceManifestMigrationPlan:
    status: Literal["review_required", "up_to_date"]
    migration_id: str | None
    migration_revision: str | None
    from_schema_version: int
    schema_version_was_omitted: bool
    to_schema_version: int
    source_count: int
    sources_field_will_be_added: bool
    manifest_sha256: str
    result_manifest_sha256: str
    backup_relative_path: str | None
    encoded_manifest: bytes | None = field(default=None, repr=False, compare=False)

    def to_public_payload(self) -> dict[str, object]:
        return {
            "schema_version": REGISTRATION_SCHEMA_VERSION,
            "status": self.status,
            "migration_kind": MANIFEST_MIGRATION_KIND,
            "migration_id": self.migration_id,
            "migration_revision": self.migration_revision,
            "from_schema_version": self.from_schema_version,
            "schema_version_was_omitted": self.schema_version_was_omitted,
            "to_schema_version": self.to_schema_version,
            "source_count": self.source_count,
            "sources_field_will_be_added": self.sources_field_will_be_added,
            "selector_changes": 0,
            "manifest_sha256": self.manifest_sha256,
            "result_manifest_sha256": self.result_manifest_sha256,
            "backup_relative_path": self.backup_relative_path,
            "formatting_policy": MANIFEST_MIGRATION_FORMATTING_POLICY,
            "changes": (
                []
                if self.status == "up_to_date"
                else [
                    "set_schema_version_to_2",
                    "preserve_source_semantics",
                    "normalize_json_utf8_2_space_lf",
                    "create_private_exact_byte_backup",
                ]
            ),
            "review_required": self.status == "review_required",
        }


@dataclass(frozen=True)
class ProtectedSourceManifestMigrationResult:
    status: Literal["migrated", "already_migrated"]
    migration_id: str
    manifest_sha256: str
    backup_relative_path: str

    def to_public_payload(self) -> dict[str, object]:
        return {
            "schema_version": REGISTRATION_SCHEMA_VERSION,
            "status": self.status,
            "migration_kind": MANIFEST_MIGRATION_KIND,
            "migration_id": self.migration_id,
            "from_schema_version": LEGACY_MANIFEST_SCHEMA_VERSION,
            "to_schema_version": CURRENT_MANIFEST_SCHEMA_VERSION,
            "manifest_sha256": self.manifest_sha256,
            "backup_relative_path": self.backup_relative_path,
        }


def suggest_protected_source(
    workspace_root: Path,
    relative_path: str,
    *,
    workspace_id: str,
    whole_file: bool = False,
) -> ProtectedSourceCandidate:
    """Create one value-free, explicitly reviewable protected-source candidate."""

    if not isinstance(workspace_id, str) or not workspace_id.strip():
        _raise("candidate_invalid")
    if type(whole_file) is not bool:
        _raise("candidate_invalid")
    normalized_path = _normalize_relative_path(relative_path)
    if whole_file:
        if normalized_path == MANIFEST_FILENAME:
            _raise("invalid_relative_path")
    else:
        _source_kind(normalized_path)
    root_fd, root_path, root_stat = _open_workspace(workspace_root)
    try:
        manifest_text, manifest_binding = _read_manifest_text(root_fd, root_stat.st_dev)
        _verify_workspace_path(root_path, root_stat)
        manifest = _parse_and_validate_manifest(manifest_text, root_path)
        source_text, source_binding = _read_relative_text(
            root_fd,
            normalized_path,
            root_device=root_stat.st_dev,
            maximum_bytes=MAX_PROTECTED_FILE_BYTES,
            unsafe_code="source_not_safe",
            too_large_code="source_too_large",
            not_utf8_code="source_not_utf8",
        )
        _verify_workspace_path(root_path, root_stat)
        return _build_protected_source_candidate(
            workspace_id=workspace_id,
            normalized_path=normalized_path,
            source_text=source_text,
            source_binding=source_binding,
            manifest=manifest,
            manifest_binding=manifest_binding,
            root_path=root_path,
            whole_file=whole_file,
        )
    finally:
        os.close(root_fd)


def scan_protected_sources(
    workspace_root: Path,
    workspace_id: str,
    workspace_lock: ProtectedSourceWorkspaceLock | None = None,
    excluded_relative_paths: tuple[str, ...] = (),
    limits: ProtectedSourceScanLimits = DEFAULT_PROTECTED_SOURCE_SCAN_LIMITS,
) -> ProtectedSourceScanResult:
    """Discover value-free candidates with a deterministic, bounded POSIX walk."""

    if not isinstance(workspace_id, str) or not workspace_id.strip():
        _raise("candidate_invalid")
    _validate_protected_source_scan_limits(limits)
    excluded_parts = _normalize_scan_exclusions(excluded_relative_paths)
    if workspace_lock is None:
        with lock_protected_source_workspace(workspace_root) as acquired_lock:
            return scan_protected_sources(
                workspace_root,
                workspace_id,
                workspace_lock=acquired_lock,
                excluded_relative_paths=excluded_relative_paths,
                limits=limits,
            )

    root_fd, root_path, root_stat = _require_workspace_lock(
        workspace_root,
        workspace_lock,
    )
    manifest_text, manifest_binding = _read_manifest_text(
        root_fd,
        root_stat.st_dev,
    )
    _verify_workspace_path(root_path, root_stat)
    manifest = _parse_and_validate_manifest(manifest_text, root_path)
    state = _ProtectedSourceScanState(
        limits=limits,
        excluded_relative_parts=excluded_parts,
        excluded_path_identities=_resolve_scan_exclusion_identities(
            root_fd,
            root_stat.st_dev,
            excluded_parts,
        ),
        registered_file_identities=_registered_manifest_file_identities(
            manifest,
            root_path,
        ),
    )
    _scan_protected_source_directory(
        root_fd,
        root_fd,
        root_path,
        root_stat,
        (),
        manifest,
        manifest_binding,
        workspace_id,
        state,
    )

    _verify_workspace_path(root_path, root_stat)
    _, confirmed_manifest_binding = _read_manifest_text(
        root_fd,
        root_stat.st_dev,
    )
    if confirmed_manifest_binding != manifest_binding:
        _raise("manifest_conflict")

    candidates = () if state.entry_limit_reached else tuple(state.candidates)
    public_candidate_bytes = (
        0 if state.entry_limit_reached else state.public_candidate_bytes
    )
    return ProtectedSourceScanResult(
        scanner_version=PROTECTED_SOURCE_SCANNER_VERSION,
        manifest_sha256=manifest_binding.sha256,
        scan_complete=not state.incomplete_reasons,
        truncation_reasons=_ordered_scan_reason_codes(state.incomplete_reasons),
        candidates=candidates,
        already_registered_count=state.already_registered_count,
        entries_seen=state.entries_seen,
        directories_scanned=state.directories_scanned,
        files_seen=state.files_seen,
        eligible_files_seen=state.eligible_files_seen,
        inspected_bytes=state.inspected_bytes,
        detected_candidate_count=state.detected_candidate_count,
        public_candidate_bytes=public_candidate_bytes,
        skipped_counts=_ordered_scan_counts(state.skipped_counts),
    )


def _build_protected_source_candidate(
    *,
    workspace_id: str,
    normalized_path: str,
    source_text: str,
    source_binding: FileBinding,
    manifest: dict[str, object],
    manifest_binding: FileBinding,
    root_path: Path,
    whole_file: bool = False,
) -> ProtectedSourceCandidate:
    if whole_file:
        selector = None
        reason_codes = ("explicit_whole_file",)
        confidence = 1.0
    else:
        source_kind = _source_kind(normalized_path)
        selector, reason_codes, confidence = _discover_selector(
            source_kind,
            source_text,
            relative_path=normalized_path,
        )
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


def plan_protected_source_manifest_migration(
    workspace_root: Path,
    *,
    workspace_id: str,
    backup_root: Path,
) -> ProtectedSourceManifestMigrationPlan:
    """Build a value-free, deterministic v1-to-v2 migration commitment."""

    _validate_migration_workspace_id(workspace_id)
    _validate_private_backup_root(backup_root)
    with lock_protected_source_workspace(workspace_root) as workspace_lock:
        root_fd, root_path, root_stat = _require_workspace_lock(
            workspace_root,
            workspace_lock,
        )
        manifest_text, manifest_binding = _read_manifest_text(
            root_fd,
            root_stat.st_dev,
        )
        payload, effective_schema, schema_was_omitted = (
            _parse_manifest_for_migration(manifest_text, root_path)
        )
        _validate_runtime_manifest(root_path, workspace_id)
        _verify_workspace_path(root_path, root_stat)
        _, confirmed_binding = _read_manifest_text(root_fd, root_stat.st_dev)
        if confirmed_binding != manifest_binding:
            _raise("manifest_migration_conflict")
        raw_sources = payload.get("sources", [])
        assert isinstance(raw_sources, list)
        if effective_schema == CURRENT_MANIFEST_SCHEMA_VERSION:
            _parse_and_validate_manifest(manifest_text, root_path)
            return ProtectedSourceManifestMigrationPlan(
                status="up_to_date",
                migration_id=None,
                migration_revision=None,
                from_schema_version=CURRENT_MANIFEST_SCHEMA_VERSION,
                schema_version_was_omitted=False,
                to_schema_version=CURRENT_MANIFEST_SCHEMA_VERSION,
                source_count=len(raw_sources),
                sources_field_will_be_added=False,
                manifest_sha256=manifest_binding.sha256,
                result_manifest_sha256=manifest_binding.sha256,
                backup_relative_path=None,
            )
        plan = _build_manifest_migration_plan(
            root_fd,
            root_path,
            root_stat.st_dev,
            workspace_id=workspace_id,
            manifest=payload,
            manifest_binding=manifest_binding,
            schema_version_was_omitted=schema_was_omitted,
        )
        # The public plan is a value-free commitment.  The canonical target
        # bytes are recomputed from the bound original during apply and must
        # not escape through an otherwise convenient dataclass attribute.
        return replace(plan, encoded_manifest=None)


def apply_protected_source_manifest_migration(
    workspace_root: Path,
    *,
    workspace_id: str,
    migration_revision: str,
    expected_manifest_sha256: str,
    backup_root: Path,
) -> ProtectedSourceManifestMigrationResult:
    """Apply or durably recover one exactly reviewed schema-only migration."""

    _validate_migration_workspace_id(workspace_id)
    _validate_migration_revision(migration_revision)
    if (
        not isinstance(expected_manifest_sha256, str)
        or _HEX_SHA256.fullmatch(expected_manifest_sha256) is None
    ):
        _raise("manifest_migration_conflict")
    _validate_private_backup_root(backup_root)
    with lock_protected_source_workspace(workspace_root) as workspace_lock:
        root_fd, root_path, root_stat = _require_workspace_lock(
            workspace_root,
            workspace_lock,
        )
        manifest_text, manifest_binding = _read_manifest_text(
            root_fd,
            root_stat.st_dev,
        )
        if hmac.compare_digest(
            manifest_binding.sha256,
            expected_manifest_sha256,
        ):
            payload, effective_schema, schema_was_omitted = (
                _parse_manifest_for_migration(manifest_text, root_path)
            )
            if effective_schema != LEGACY_MANIFEST_SCHEMA_VERSION:
                _raise("manifest_migration_conflict")
            _validate_runtime_manifest(root_path, workspace_id)
            plan = _build_manifest_migration_plan(
                root_fd,
                root_path,
                root_stat.st_dev,
                workspace_id=workspace_id,
                manifest=payload,
                manifest_binding=manifest_binding,
                schema_version_was_omitted=schema_was_omitted,
            )
            _verify_reviewed_migration(plan, migration_revision)
            assert plan.encoded_manifest is not None
            assert plan.backup_relative_path is not None
            assert plan.migration_id is not None
            _ensure_manifest_backup(
                backup_root,
                plan.backup_relative_path,
                manifest_text.encode("utf-8"),
            )
            installed_sha256 = _install_migrated_manifest(
                root_fd,
                root_path,
                root_stat,
                workspace_id=workspace_id,
                initial_binding=manifest_binding,
                encoded=plan.encoded_manifest,
            )
            return ProtectedSourceManifestMigrationResult(
                status="migrated",
                migration_id=plan.migration_id,
                manifest_sha256=installed_sha256,
                backup_relative_path=plan.backup_relative_path,
            )

        return _recover_applied_manifest_migration(
            root_fd,
            root_path,
            root_stat,
            workspace_id=workspace_id,
            migration_revision=migration_revision,
            expected_manifest_sha256=expected_manifest_sha256,
            current_manifest_text=manifest_text,
            current_manifest_binding=manifest_binding,
            backup_root=backup_root,
        )


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
    saved = _coerce_candidate(candidate, allow_legacy_recovery=True)
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
    *,
    allow_legacy_recovery: bool = False,
) -> ProtectedSourceCandidate:
    if isinstance(candidate, ProtectedSourceCandidate):
        saved = candidate
    elif isinstance(candidate, Mapping):
        saved = ProtectedSourceCandidate.from_storage_record(candidate)
    else:
        _raise("candidate_invalid")
    if saved.detector_version == DETECTOR_VERSION:
        return saved
    if (
        allow_legacy_recovery
        and saved.detector_version == LEGACY_DETECTOR_VERSION
        and saved.status in {"approving", "approved"}
    ):
        return saved
    _raise("candidate_detector_stale")


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
    if candidate.reason_codes == ("explicit_whole_file",):
        selector = None
        reason_codes = candidate.reason_codes
        confidence = 1.0
    else:
        source_kind = _source_kind(candidate.relative_path)
        selector, reason_codes, confidence = _discover_selector(
            source_kind,
            text,
            relative_path=candidate.relative_path,
            detector_version=candidate.detector_version,
        )
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
    *,
    relative_path: str,
    detector_version: str = DETECTOR_VERSION,
) -> tuple[dict[str, list[str]], tuple[str, ...], float]:
    if detector_version not in {DETECTOR_VERSION, LEGACY_DETECTOR_VERSION}:
        _raise("candidate_detector_stale")
    value_aware = detector_version == DETECTOR_VERSION
    if source_kind == "dotenv":
        keys = _discover_dotenv_keys(
            text,
            relative_path=relative_path,
            value_aware=value_aware,
        )
        return {"dotenv_keys": keys}, ("secret_like_dotenv_key",), 0.95
    pointers = _discover_json_pointers(
        text,
        relative_path=relative_path,
        value_aware=value_aware,
    )
    return {"json_pointers": pointers}, ("secret_like_json_key",), 0.95


def _discover_dotenv_keys(
    text: str,
    *,
    relative_path: str,
    value_aware: bool,
) -> list[str]:
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
        secret_like_key = (
            _is_secret_like_key(key)
            if value_aware
            else _is_secret_like_key_v1(key)
        )
        if value.strip() and secret_like_key and (
            not value_aware
            or _is_supported_secret_scalar(
                key,
                value,
                relative_path=relative_path,
            )
        ):
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


def _discover_json_pointers(
    text: str,
    *,
    relative_path: str,
    value_aware: bool,
) -> list[str]:
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
                secret_like_key = (
                    _is_secret_like_key(key)
                    if value_aware
                    else _is_secret_like_key_v1(key)
                )
                if (
                    isinstance(child, str)
                    and child.strip()
                    and secret_like_key
                    and (
                        not value_aware
                        or _is_supported_secret_scalar(
                            key,
                            child,
                            relative_path=relative_path,
                        )
                    )
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
    segments = _normalized_identifier_segments(key)
    if not segments:
        return False
    normalized = "_".join(segments)
    if normalized in _V2_SECRET_MARKERS:
        return True
    if any(
        marker in segments
        for marker in _V2_SECRET_MARKERS
        if "_" not in marker
    ):
        return True
    joined_pairs = {
        "_".join(segments[index : index + 2])
        for index in range(len(segments) - 1)
    }
    return bool(joined_pairs & _V2_SECRET_MARKERS)


def _is_secret_like_key_v1(key: str) -> bool:
    """Preserve the released v1 key contract for approval recovery only."""

    snake = _CAMEL_KEY_BOUNDARY.sub(r"\1_\2", key)
    normalized = _NON_ASCII_ALNUM.sub("_", snake).strip("_").casefold()
    if not normalized:
        return False
    if normalized in _SECRET_MARKERS:
        return True
    segments = tuple(part for part in normalized.split("_") if part)
    if any(marker in segments for marker in _SECRET_MARKERS if "_" not in marker):
        return True
    joined_pairs = {
        "_".join(segments[index : index + 2])
        for index in range(len(segments) - 1)
    }
    return bool(joined_pairs & _SECRET_MARKERS)


def _is_supported_secret_scalar(
    key: str,
    value: str,
    *,
    relative_path: str,
) -> bool:
    """Classify one scalar without retaining or returning its raw value."""

    stripped = value.strip()
    if not stripped:
        return False
    if _is_secret_manager_reference(stripped):
        return False
    if len(stripped) <= _MAX_VALUE_CLASSIFICATION_CHARACTERS:
        if _is_definitive_placeholder(stripped):
            return False
        if (
            _has_weak_placeholder_value(stripped)
            and _has_placeholder_like_basename(relative_path)
        ):
            return False
        key_segments = _normalized_identifier_segments(key)
        if _is_metadata_scalar(key_segments, stripped):
            return False
    return True


def _normalized_identifier_segments(value: str) -> tuple[str, ...]:
    normalized = unicodedata.normalize("NFKC", value)
    normalized = _ACRONYM_KEY_BOUNDARY.sub(r"\1_\2", normalized)
    normalized = _CAMEL_KEY_BOUNDARY.sub(r"\1_\2", normalized)
    normalized = _NON_ASCII_ALNUM.sub("_", normalized).strip("_").casefold()
    return tuple(segment for segment in normalized.split("_") if segment)


def _canonical_scalar_label(value: str) -> str:
    label = "_".join(_normalized_identifier_segments(value))
    return _SCALAR_LABEL_ALIASES.get(label, label)


def _is_definitive_placeholder(value: str) -> bool:
    normalized = unicodedata.normalize("NFKC", value).strip()
    if (
        _SHELL_REFERENCE.fullmatch(normalized) is not None
        or _BRACED_SHELL_REFERENCE.fullmatch(normalized) is not None
        or _MUSTACHE_REFERENCE.fullmatch(normalized) is not None
        or _ANGLE_PLACEHOLDER.fullmatch(normalized) is not None
    ):
        return True
    if len(normalized) >= 4 and set(normalized) <= {"*", "x", "X", "-", "_"}:
        return True
    label = _canonical_scalar_label(normalized)
    if label in _DEFINITIVE_PLACEHOLDER_VALUES:
        return True
    segments = _normalized_identifier_segments(normalized)
    return bool(
        len(segments) >= 2
        and segments[0] in {"change", "configure", "replace", "set"}
        and segments[-1] in {"later", "me", "placeholder", "this"}
    )


def _has_weak_placeholder_value(value: str) -> bool:
    return bool(
        set(_normalized_identifier_segments(value)) & _WEAK_PLACEHOLDER_TOKENS
    )


def _has_placeholder_like_basename(relative_path: str) -> bool:
    basename = PurePath(relative_path).name
    return bool(
        set(_normalized_identifier_segments(basename))
        & _PLACEHOLDER_BASENAME_TOKENS
    )


def _is_secret_manager_reference(value: str) -> bool:
    normalized = unicodedata.normalize("NFKC", value).strip().casefold()
    if normalized.startswith(_SECRET_MANAGER_REFERENCE_PREFIXES):
        return True
    parts = tuple(part for part in normalized.split("/") if part)
    return bool(
        len(parts) >= 6
        and parts[0] == "projects"
        and parts[2] == "secrets"
        and parts[4] == "versions"
    )


def _is_metadata_scalar(key_segments: tuple[str, ...], value: str) -> bool:
    if not key_segments or _is_access_key_id(key_segments):
        return False
    key_tokens = set(key_segments)
    value_label = _canonical_scalar_label(value)
    qualifiers = key_tokens & _METADATA_KEY_QUALIFIERS
    protocol_key = bool(
        key_tokens
        & {"auth", "authentication", "authorization", "bearer", "token"}
        or qualifiers & {"method", "mode", "scheme", "type"}
    )
    # Exact protocol vocabulary is metadata only when the key also describes
    # an authentication protocol. CLIENT_SECRET=jwt and PASSWORD=password are
    # therefore retained, while AUTH=OAuth2 and TOKEN_TYPE=Bearer are not.
    if protocol_key and value_label in _PROTOCOL_METADATA_VALUES:
        return True
    if not qualifiers:
        return False
    if qualifiers & {"algorithm", "format"}:
        return value_label in (
            _ALGORITHM_METADATA_VALUES | _PROTOCOL_METADATA_VALUES
        )
    if qualifiers & {"method", "mode", "scheme", "type"}:
        return value_label in _PROTOCOL_METADATA_VALUES
    if "policy" in qualifiers:
        return value_label in {
            "default",
            "disabled",
            "enforced",
            "optional",
            "required",
            "strict",
        }
    reference_qualifiers = qualifiers & {
        "endpoint",
        "file",
        "header",
        "id",
        "identifier",
        "name",
        "path",
        "prefix",
        "ref",
        "reference",
        "scope",
        "scopes",
        "uri",
        "url",
        "version",
    }
    return bool(
        reference_qualifiers
        and _looks_like_reference_metadata(value, reference_qualifiers)
    )


def _is_access_key_id(key_segments: tuple[str, ...]) -> bool:
    return any(
        key_segments[index : index + 3] == ("access", "key", "id")
        for index in range(max(0, len(key_segments) - 2))
    )


def _looks_like_reference_metadata(
    value: str,
    qualifiers: set[str],
) -> bool:
    normalized = unicodedata.normalize("NFKC", value).strip()
    if _REFERENCE_URI.fullmatch(normalized) is not None:
        return True
    if qualifiers & {"endpoint", "file", "path", "ref", "reference", "uri", "url"}:
        if (
            normalized.startswith(("/", "./", "../", "~/"))
            or "/" in normalized
            or "\\" in normalized
        ):
            return True
    return bool(
        qualifiers
        & {
            "file",
            "header",
            "id",
            "identifier",
            "name",
            "path",
            "prefix",
            "ref",
            "reference",
            "scope",
            "scopes",
            "endpoint",
            "uri",
            "url",
            "version",
        }
        and (
            _REFERENCE_NAME.fullmatch(normalized) is not None
            or (
                qualifiers & {"scope", "scopes"}
                and _METADATA_DESCRIPTOR.fullmatch(normalized) is not None
            )
        )
    )


def _escape_json_pointer_segment(value: str) -> str:
    return value.replace("~", "~0").replace("/", "~1")


def _build_proposed_source(
    relative_path: str,
    selector: dict[str, list[str]] | None,
) -> dict[str, object]:
    path = PurePath(relative_path)
    slug_source = re.sub(r"[^a-z0-9]+", "_", path.name.casefold()).strip("_")
    slug = slug_source[:40] or "source"
    identity = f"{_SOURCE_ID_DERIVATION_DOMAIN}\0{relative_path}".encode("utf-8")
    source_id = f"protected_{slug}_{hashlib.sha256(identity).hexdigest()[:16]}"
    if _SAFE_SOURCE_ID.fullmatch(source_id) is None:
        _raise("candidate_invalid")
    proposed: dict[str, object] = {
        "id": source_id,
        "path": relative_path,
        "type": "secretfile",
        "sensitivity": "high",
        "policy_tags": ["no_external", "no_search"],
    }
    if selector is not None:
        proposed["selector"] = selector
    return proposed


def _validate_proposed_source(
    value: dict[str, object],
    *,
    expected_path: str,
) -> dict[str, object]:
    base_keys = {"id", "path", "type", "sensitivity", "policy_tags"}
    if set(value) not in {
        frozenset(base_keys),
        frozenset(base_keys | {"selector"}),
    }:
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
    ):
        _raise("candidate_invalid")
    if "selector" not in value:
        if expected_path == MANIFEST_FILENAME:
            _raise("candidate_invalid")
        return _copy_json_object(value)
    if not isinstance(selector, Mapping) or len(selector) != 1:
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


def _validate_protected_source_scan_limits(
    limits: ProtectedSourceScanLimits,
) -> None:
    if not isinstance(limits, ProtectedSourceScanLimits):
        _raise("scan_limits_invalid")
    for name in (
        "max_depth",
        "max_entries",
        "max_files",
        "max_eligible_files",
        "max_total_read_bytes",
        "max_candidates",
        "max_public_metadata_bytes",
    ):
        value = getattr(limits, name)
        hard_maximum = getattr(DEFAULT_PROTECTED_SOURCE_SCAN_LIMITS, name)
        if type(value) is not int or not 1 <= value <= hard_maximum:
            _raise("scan_limits_invalid")


def _normalize_scan_exclusions(
    values: tuple[str, ...],
) -> tuple[tuple[str, ...], ...]:
    if not isinstance(values, tuple):
        _raise("invalid_relative_path")
    normalized: set[tuple[str, ...]] = set()
    for value in values:
        relative_path = _normalize_relative_path(value)
        try:
            encoded = relative_path.encode("utf-8")
        except UnicodeEncodeError:
            _raise("invalid_relative_path")
        if len(encoded) > _PROTECTED_SOURCE_SCAN_MAX_RELATIVE_PATH_BYTES:
            _raise("invalid_relative_path")
        normalized.add(PurePath(relative_path).parts)
    return tuple(
        sorted(
            normalized,
            key=lambda parts: "/".join(parts).encode("utf-8"),
        )
    )


def _scan_protected_source_directory(
    root_fd: int,
    directory_fd: int,
    root_path: Path,
    root_stat: os.stat_result,
    directory_parts: tuple[str, ...],
    manifest: dict[str, object],
    manifest_binding: FileBinding,
    workspace_id: str,
    state: _ProtectedSourceScanState,
) -> None:
    if state.entry_limit_reached:
        return
    state.directories_scanned += 1
    entries: list[tuple[bytes, str]] = []
    try:
        with os.scandir(directory_fd) as iterator:
            for entry in iterator:
                if state.entries_seen >= state.limits.max_entries:
                    state.skip("entry_limit", incomplete=True)
                    state.entry_limit_reached = True
                    return
                state.entries_seen += 1
                name = entry.name
                key = _scan_entry_name_key(name)
                if key is None:
                    state.skip("invalid_name", incomplete=True)
                    continue
                entries.append((key, name))
    except OSError:
        state.skip("directory_read_error", incomplete=True)
        return

    for _, name in sorted(entries, key=lambda item: item[0]):
        if state.entry_limit_reached:
            return
        relative_parts = (*directory_parts, name)
        if _scan_path_is_excluded(relative_parts, state.excluded_relative_parts):
            state.skip("excluded_path")
            continue
        if relative_parts == (MANIFEST_FILENAME,):
            continue
        relative_path = "/".join(relative_parts)
        try:
            normalized_path = _normalize_relative_path(relative_path)
            encoded_path = normalized_path.encode("utf-8")
        except (ProtectedSourceRegistrationError, UnicodeEncodeError):
            state.skip("invalid_name", incomplete=True)
            continue
        if len(encoded_path) > _PROTECTED_SOURCE_SCAN_MAX_RELATIVE_PATH_BYTES:
            state.skip("invalid_name", incomplete=True)
            continue

        try:
            metadata = os.stat(
                name,
                dir_fd=directory_fd,
                follow_symlinks=False,
            )
        except OSError:
            state.skip("entry_read_error", incomplete=True)
            continue
        if (metadata.st_dev, metadata.st_ino) in state.excluded_path_identities:
            state.skip("excluded_path")
            continue
        if stat.S_ISLNK(metadata.st_mode):
            state.skip("symlink")
            continue
        if stat.S_ISDIR(metadata.st_mode):
            if name.casefold() in _PROTECTED_SOURCE_SCAN_EXCLUDED_DIRECTORIES:
                state.skip("excluded_directory")
                continue
            if metadata.st_dev != root_stat.st_dev:
                state.skip("cross_device")
                continue
            if len(relative_parts) >= state.limits.max_depth:
                state.skip("depth_limit", incomplete=True)
                continue
            child_fd: int | None = None
            try:
                flags = os.O_RDONLY
                flags |= getattr(os, "O_DIRECTORY", 0)
                flags |= getattr(os, "O_NOFOLLOW", 0)
                flags |= getattr(os, "O_CLOEXEC", 0)
                child_fd = os.open(name, flags, dir_fd=directory_fd)
                opened = os.fstat(child_fd)
                if (
                    not stat.S_ISDIR(opened.st_mode)
                    or opened.st_dev != root_stat.st_dev
                    or opened.st_dev != metadata.st_dev
                    or opened.st_ino != metadata.st_ino
                ):
                    state.skip("entry_read_error", incomplete=True)
                    continue
                _scan_protected_source_directory(
                    root_fd,
                    child_fd,
                    root_path,
                    root_stat,
                    relative_parts,
                    manifest,
                    manifest_binding,
                    workspace_id,
                    state,
                )
            except OSError:
                state.skip("entry_read_error", incomplete=True)
            finally:
                if child_fd is not None:
                    os.close(child_fd)
            continue
        if not stat.S_ISREG(metadata.st_mode):
            state.skip("non_regular")
            continue
        if metadata.st_dev != root_stat.st_dev:
            state.skip("cross_device")
            continue
        if metadata.st_nlink != 1:
            state.skip("hardlink")
            continue
        _scan_protected_source_file(
            root_fd,
            root_path,
            root_stat,
            normalized_path,
            metadata,
            manifest,
            manifest_binding,
            workspace_id,
            state,
        )


def _scan_protected_source_file(
    root_fd: int,
    root_path: Path,
    root_stat: os.stat_result,
    normalized_path: str,
    metadata: os.stat_result,
    manifest: dict[str, object],
    manifest_binding: FileBinding,
    workspace_id: str,
    state: _ProtectedSourceScanState,
) -> None:
    if state.files_seen >= state.limits.max_files:
        state.skip("file_limit", incomplete=True)
        return
    state.files_seen += 1
    try:
        _source_kind(normalized_path)
    except ProtectedSourceRegistrationError as exc:
        if exc.code == "unsupported_source_format":
            return
        raise

    source_identity = f"{metadata.st_dev}:{metadata.st_ino}"
    if source_identity in state.registered_file_identities:
        state.already_registered_count += 1
        return

    if state.eligible_files_seen >= state.limits.max_eligible_files:
        state.skip("eligible_file_limit", incomplete=True)
        return
    state.eligible_files_seen += 1
    if metadata.st_size > MAX_PROTECTED_FILE_BYTES:
        state.skip("source_too_large", incomplete=True)
        return
    remaining_bytes = state.limits.max_total_read_bytes - state.inspected_bytes
    if metadata.st_size > remaining_bytes:
        state.skip("total_read_bytes_limit", incomplete=True)
        return
    # Reserve the stable enumerated size before I/O. A changed file cannot
    # consume a later candidate's aggregate budget even when it is rejected.
    state.inspected_bytes += metadata.st_size
    try:
        source_text, source_binding = _read_scan_source_text(
            root_fd,
            normalized_path,
            root_device=root_stat.st_dev,
            expected=metadata,
        )
        candidate = _build_protected_source_candidate(
            workspace_id=workspace_id,
            normalized_path=normalized_path,
            source_text=source_text,
            source_binding=source_binding,
            manifest=manifest,
            manifest_binding=manifest_binding,
            root_path=root_path,
        )
    except ProtectedSourceRegistrationError as exc:
        incomplete = exc.code != "no_secret_selector"
        state.skip(exc.code, incomplete=incomplete)
        return

    if candidate.already_registered:
        state.already_registered_count += 1
        return
    state.detected_candidate_count += 1
    if len(state.candidates) >= state.limits.max_candidates:
        state.skip("candidate_limit", incomplete=True)
        return
    public_bytes = _protected_source_candidate_public_bytes(candidate)
    if (
        state.public_candidate_bytes + public_bytes
        > state.limits.max_public_metadata_bytes
    ):
        state.skip("public_metadata_limit", incomplete=True)
        return
    state.candidates.append(candidate)
    state.public_candidate_bytes += public_bytes


def _read_scan_source_text(
    root_fd: int,
    relative_path: str,
    *,
    root_device: int,
    expected: os.stat_result,
) -> tuple[str, FileBinding]:
    parts = PurePath(relative_path).parts
    current_fd: int | None = None
    file_fd: int | None = None
    try:
        current_fd = os.dup(root_fd)
        for part in parts[:-1]:
            flags = os.O_RDONLY
            flags |= getattr(os, "O_DIRECTORY", 0)
            flags |= getattr(os, "O_NOFOLLOW", 0)
            flags |= getattr(os, "O_CLOEXEC", 0)
            assert current_fd is not None
            next_fd = os.open(part, flags, dir_fd=current_fd)
            opened = os.fstat(next_fd)
            if not stat.S_ISDIR(opened.st_mode) or opened.st_dev != root_device:
                os.close(next_fd)
                _raise("source_changed")
            os.close(current_fd)
            current_fd = next_fd

        flags = os.O_RDONLY
        flags |= getattr(os, "O_NOFOLLOW", 0)
        flags |= getattr(os, "O_NONBLOCK", 0)
        flags |= getattr(os, "O_CLOEXEC", 0)
        assert current_fd is not None
        file_fd = os.open(parts[-1], flags, dir_fd=current_fd)
        before = os.fstat(file_fd)
        if not _same_stat(expected, before):
            _raise("source_changed")
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_dev != root_device
            or before.st_nlink != 1
        ):
            _raise("source_not_safe")
        if before.st_size > MAX_PROTECTED_FILE_BYTES:
            _raise("source_too_large")

        chunks: list[bytes] = []
        read_bytes = 0
        while read_bytes < before.st_size:
            chunk = os.read(file_fd, min(64 * 1024, before.st_size - read_bytes))
            if not chunk:
                break
            chunks.append(chunk)
            read_bytes += len(chunk)
        after = os.fstat(file_fd)
        body = b"".join(chunks)
        if not _same_stat(before, after) or len(body) != after.st_size:
            _raise("source_changed")
        try:
            text = body.decode("utf-8")
        except UnicodeDecodeError:
            _raise("source_not_utf8")
        return text, _make_binding(body, after)
    except ProtectedSourceRegistrationError:
        raise
    except FileNotFoundError:
        _raise("source_changed")
    except (OSError, ValueError):
        _raise("source_not_safe")
    finally:
        if file_fd is not None:
            os.close(file_fd)
        if current_fd is not None:
            os.close(current_fd)


def _protected_source_candidate_public_bytes(
    candidate: ProtectedSourceCandidate,
) -> int:
    public_candidate = candidate.with_candidate_id("0" * 32).to_public_payload()
    return len(_canonical_json_bytes(public_candidate))


def _scan_entry_name_key(name: object) -> bytes | None:
    if not isinstance(name, str) or not name:
        return None
    if any(ord(character) < 32 for character in name):
        return None
    try:
        return name.encode("utf-8")
    except UnicodeEncodeError:
        return None


def _scan_path_is_excluded(
    relative_parts: tuple[str, ...],
    exclusions: tuple[tuple[str, ...], ...],
) -> bool:
    return any(
        len(relative_parts) >= len(excluded)
        and relative_parts[: len(excluded)] == excluded
        for excluded in exclusions
    )


def _resolve_scan_exclusion_identities(
    root_fd: int,
    root_device: int,
    exclusions: tuple[tuple[str, ...], ...],
) -> frozenset[tuple[int, int]]:
    """Resolve existing exclusions without following symlinks or reading contents."""

    identities: set[tuple[int, int]] = set()
    for parts in exclusions:
        current_fd: int | None = None
        next_fd: int | None = None
        target_fd: int | None = None
        try:
            current_fd = os.dup(root_fd)
            for part in parts[:-1]:
                flags = os.O_RDONLY
                flags |= getattr(os, "O_DIRECTORY", 0)
                flags |= getattr(os, "O_NOFOLLOW", 0)
                flags |= getattr(os, "O_CLOEXEC", 0)
                next_fd = os.open(part, flags, dir_fd=current_fd)
                opened = os.fstat(next_fd)
                if not stat.S_ISDIR(opened.st_mode) or opened.st_dev != root_device:
                    break
                os.close(current_fd)
                current_fd = next_fd
                next_fd = None
            else:
                flags = os.O_RDONLY
                flags |= getattr(os, "O_NOFOLLOW", 0)
                flags |= getattr(os, "O_NONBLOCK", 0)
                flags |= getattr(os, "O_CLOEXEC", 0)
                target_fd = os.open(parts[-1], flags, dir_fd=current_fd)
                opened = os.fstat(target_fd)
                identities.add((opened.st_dev, opened.st_ino))
        except OSError:
            # The lexical exclusion remains authoritative. Missing, replaced,
            # inaccessible, or symlinked aliases do not make the scan fail.
            continue
        finally:
            if next_fd is not None:
                os.close(next_fd)
            if target_fd is not None:
                os.close(target_fd)
            if current_fd is not None:
                os.close(current_fd)
    return frozenset(identities)


def _ordered_scan_reason_codes(values: set[str]) -> tuple[str, ...]:
    order = {
        code: index for index, code in enumerate(_PROTECTED_SOURCE_SCAN_REASON_ORDER)
    }
    return tuple(sorted(values, key=lambda code: (order.get(code, len(order)), code)))


def _ordered_scan_counts(
    values: Mapping[str, int],
) -> tuple[tuple[str, int], ...]:
    ordered_codes = _ordered_scan_reason_codes(set(values))
    return tuple((code, values[code]) for code in ordered_codes)


def _registered_manifest_file_identities(
    manifest: Mapping[str, object],
    root_path: Path,
) -> frozenset[str]:
    raw_sources = manifest.get("sources")
    if not isinstance(raw_sources, list):
        _raise("manifest_sources_invalid")
    identities: set[str] = set()
    for raw_source in raw_sources:
        if not isinstance(raw_source, Mapping):
            _raise("manifest_source_invalid")
        source_path = raw_source.get("path")
        if not isinstance(source_path, str):
            _raise("manifest_source_invalid")
        identities.add(_canonical_manifest_source_path(root_path, source_path))
    return frozenset(identities)


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


def _validate_migration_workspace_id(workspace_id: str) -> None:
    if (
        not isinstance(workspace_id, str)
        or not workspace_id
        or len(workspace_id.encode("utf-8")) > 4096
        or "\x00" in workspace_id
    ):
        _raise("candidate_invalid")


def _validate_private_backup_root(backup_root: Path) -> None:
    descriptor: int | None = None
    try:
        path = Path(os.path.abspath(os.fspath(backup_root)))
        metadata = os.lstat(path)
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            _raise("manifest_backup_unavailable")
        flags = os.O_RDONLY
        flags |= getattr(os, "O_DIRECTORY", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(opened.st_mode)
            or opened.st_dev != metadata.st_dev
            or opened.st_ino != metadata.st_ino
            or stat.S_IMODE(opened.st_mode) & 0o077
            or (hasattr(os, "geteuid") and opened.st_uid != os.geteuid())
        ):
            _raise("manifest_backup_unavailable")
    except ProtectedSourceRegistrationError:
        raise
    except (OSError, TypeError, ValueError):
        _raise("manifest_backup_unavailable")
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _parse_manifest_for_migration(
    text: str,
    root_path: Path,
    *,
    validate_source_paths: bool = True,
) -> tuple[dict[str, object], int, bool]:
    try:
        payload = _strict_json_loads(text, duplicate_code="manifest_invalid_json")
    except ProtectedSourceRegistrationError:
        _raise("manifest_invalid_json")
    if not isinstance(payload, dict):
        _raise("manifest_invalid_json")
    schema_was_omitted = "schema_version" not in payload
    schema_version = payload.get(
        "schema_version",
        LEGACY_MANIFEST_SCHEMA_VERSION,
    )
    if type(schema_version) is not int:
        _raise("manifest_schema_invalid")
    if schema_version > CURRENT_MANIFEST_SCHEMA_VERSION:
        _raise("manifest_schema_future")
    if schema_version not in {
        LEGACY_MANIFEST_SCHEMA_VERSION,
        CURRENT_MANIFEST_SCHEMA_VERSION,
    }:
        _raise("manifest_schema_invalid")
    sources = payload.get("sources", [])
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
        source_type = source.get("type")
        sensitivity = source.get("sensitivity")
        policy_tags = source.get("policy_tags", [])
        if (
            not isinstance(source_id, str)
            or not source_id.strip()
            or not isinstance(source_path, str)
            or not source_path.strip()
            or not isinstance(source_type, str)
            or not source_type.strip()
            or not isinstance(sensitivity, str)
            or not sensitivity.strip()
            or not isinstance(policy_tags, list)
            or not all(isinstance(tag, str) for tag in policy_tags)
            or (
                schema_version == LEGACY_MANIFEST_SCHEMA_VERSION
                and "selector" in source
            )
        ):
            _raise("manifest_source_invalid")
        if source_id in source_ids:
            _raise("manifest_duplicate_id")
        source_ids.add(source_id)
        if validate_source_paths:
            canonical_path = _canonical_manifest_source_path(root_path, source_path)
            if canonical_path in canonical_paths:
                _raise("manifest_duplicate_path")
            canonical_paths.add(canonical_path)
    return payload, schema_version, schema_was_omitted


def _validate_runtime_manifest(root_path: Path, workspace_id: str) -> None:
    try:
        load_sources_and_chunks(
            root_path,
            root_path / MANIFEST_FILENAME,
            workspace_id=workspace_id,
        )
    except Exception:
        _raise("manifest_migration_validation_failed")


def _build_manifest_migration_plan(
    root_fd: int,
    root_path: Path,
    root_device: int,
    *,
    workspace_id: str,
    manifest: dict[str, object],
    manifest_binding: FileBinding,
    schema_version_was_omitted: bool,
) -> ProtectedSourceManifestMigrationPlan:
    schema_version = manifest.get(
        "schema_version",
        LEGACY_MANIFEST_SCHEMA_VERSION,
    )
    if schema_version != LEGACY_MANIFEST_SCHEMA_VERSION:
        _raise("manifest_migration_not_required")
    sources_field_will_be_added = "sources" not in manifest
    raw_sources = manifest.get("sources", [])
    if not isinstance(raw_sources, list):
        _raise("manifest_sources_invalid")
    validation_manifest = dict(manifest)
    validation_manifest.setdefault("sources", [])
    _preflight_manifest_sources(
        root_fd,
        root_path,
        root_device,
        validation_manifest,
    )

    encoded = _encode_migrated_manifest(
        manifest,
        schema_version_was_omitted=schema_version_was_omitted,
    )
    migrated = _strict_json_loads(encoded.decode("utf-8"), duplicate_code="manifest_invalid_json")
    if not isinstance(migrated, dict):
        _raise("manifest_migration_validation_failed")
    validated = _parse_and_validate_manifest(encoded.decode("utf-8"), root_path)
    if validated != migrated:
        _raise("manifest_migration_validation_failed")
    result_sha256 = hashlib.sha256(encoded).hexdigest()
    backup_relative_path = _manifest_backup_relative_path(
        workspace_id,
        manifest_binding.sha256,
    )
    migration_id, migration_revision = _manifest_migration_commitment(
        workspace_id=workspace_id,
        manifest_sha256=manifest_binding.sha256,
        result_manifest_sha256=result_sha256,
        backup_relative_path=backup_relative_path,
    )
    return ProtectedSourceManifestMigrationPlan(
        status="review_required",
        migration_id=migration_id,
        migration_revision=migration_revision,
        from_schema_version=LEGACY_MANIFEST_SCHEMA_VERSION,
        schema_version_was_omitted=schema_version_was_omitted,
        to_schema_version=CURRENT_MANIFEST_SCHEMA_VERSION,
        source_count=len(raw_sources),
        sources_field_will_be_added=sources_field_will_be_added,
        manifest_sha256=manifest_binding.sha256,
        result_manifest_sha256=result_sha256,
        backup_relative_path=backup_relative_path,
        encoded_manifest=encoded,
    )


def _encode_migrated_manifest(
    manifest: Mapping[str, object],
    *,
    schema_version_was_omitted: bool,
) -> bytes:
    if manifest.get(
        "schema_version",
        LEGACY_MANIFEST_SCHEMA_VERSION,
    ) != LEGACY_MANIFEST_SCHEMA_VERSION:
        _raise("manifest_migration_not_required")
    if schema_version_was_omitted:
        migrated: dict[str, object] = {
            "schema_version": CURRENT_MANIFEST_SCHEMA_VERSION
        }
        migrated.update(manifest)
    else:
        migrated = dict(manifest)
        migrated["schema_version"] = CURRENT_MANIFEST_SCHEMA_VERSION
    migrated.setdefault("sources", [])
    return _encode_manifest(migrated)


def _manifest_backup_relative_path(
    workspace_id: str,
    manifest_sha256: str,
) -> str:
    namespace = hashlib.sha256(
        (MANIFEST_MIGRATION_WRITER_VERSION + "\0" + workspace_id).encode("utf-8")
    ).hexdigest()
    return (
        f"{MANIFEST_BACKUP_DIRECTORY}/{namespace}/"
        f"protected_sources.schema-v1.{manifest_sha256}.json"
    )


def _manifest_migration_commitment(
    *,
    workspace_id: str,
    manifest_sha256: str,
    result_manifest_sha256: str,
    backup_relative_path: str,
) -> tuple[str, str]:
    digest = hashlib.sha256(
        _canonical_json_bytes(
            {
                "operation": MANIFEST_MIGRATION_KIND,
                "writer_version": MANIFEST_MIGRATION_WRITER_VERSION,
                "workspace_id": workspace_id,
                "from_schema_version": LEGACY_MANIFEST_SCHEMA_VERSION,
                "to_schema_version": CURRENT_MANIFEST_SCHEMA_VERSION,
                "manifest_sha256": manifest_sha256,
                "result_manifest_sha256": result_manifest_sha256,
                "backup_relative_path": backup_relative_path,
                "formatting_policy": MANIFEST_MIGRATION_FORMATTING_POLICY,
            }
        )
    ).hexdigest()
    return digest[:32], f"m1_{digest}"


def _validate_migration_revision(migration_revision: str) -> None:
    if (
        not isinstance(migration_revision, str)
        or re.fullmatch(r"m1_[0-9a-f]{64}", migration_revision) is None
    ):
        _raise("manifest_migration_revision_invalid")


def _verify_reviewed_migration(
    plan: ProtectedSourceManifestMigrationPlan,
    migration_revision: str,
) -> None:
    if (
        plan.status != "review_required"
        or plan.migration_revision is None
        or not hmac.compare_digest(plan.migration_revision, migration_revision)
    ):
        _raise("manifest_migration_revision_invalid")


def _install_migrated_manifest(
    root_fd: int,
    root_path: Path,
    root_stat: os.stat_result,
    *,
    workspace_id: str,
    initial_binding: FileBinding,
    encoded: bytes,
) -> str:
    temporary_name: str | None = None
    try:
        temporary_name = _write_temporary_manifest(root_fd, encoded)
        temporary_path = root_path / temporary_name
        _verify_workspace_path(root_path, root_stat)
        try:
            load_sources_and_chunks(
                root_path,
                temporary_path,
                workspace_id=workspace_id,
            )
        except Exception:
            _raise("manifest_migration_validation_failed")
        _verify_temporary_file(root_fd, temporary_name, root_stat.st_dev, encoded)
        _, final_binding = _read_manifest_text(root_fd, root_stat.st_dev)
        if final_binding != initial_binding:
            _raise("manifest_migration_conflict")
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
        expected_sha256 = hashlib.sha256(encoded).hexdigest()
        try:
            _verify_workspace_path(root_path, root_stat)
            installed_text, installed_binding = _read_manifest_text(
                root_fd,
                root_stat.st_dev,
            )
            if (
                not hmac.compare_digest(installed_binding.sha256, expected_sha256)
                or installed_text.encode("utf-8") != encoded
            ):
                _raise("manifest_postcondition_failed")
            _parse_and_validate_manifest(installed_text, root_path)
        except ProtectedSourceRegistrationError as exc:
            if exc.code == "manifest_postcondition_failed":
                raise
            _raise("manifest_postcondition_failed")
        return expected_sha256
    finally:
        if temporary_name is not None:
            try:
                os.unlink(temporary_name, dir_fd=root_fd)
            except FileNotFoundError:
                pass


def _recover_applied_manifest_migration(
    root_fd: int,
    root_path: Path,
    root_stat: os.stat_result,
    *,
    workspace_id: str,
    migration_revision: str,
    expected_manifest_sha256: str,
    current_manifest_text: str,
    current_manifest_binding: FileBinding,
    backup_root: Path,
) -> ProtectedSourceManifestMigrationResult:
    backup_relative_path = _manifest_backup_relative_path(
        workspace_id,
        expected_manifest_sha256,
    )
    try:
        _, effective_schema, _ = _parse_manifest_for_migration(
            current_manifest_text,
            root_path,
            validate_source_paths=False,
        )
    except ProtectedSourceRegistrationError:
        _raise("manifest_migration_conflict")
    if effective_schema != CURRENT_MANIFEST_SCHEMA_VERSION:
        _raise("manifest_migration_conflict")
    migration_id, expected_revision = _manifest_migration_commitment(
        workspace_id=workspace_id,
        manifest_sha256=expected_manifest_sha256,
        result_manifest_sha256=current_manifest_binding.sha256,
        backup_relative_path=backup_relative_path,
    )
    if not hmac.compare_digest(expected_revision, migration_revision):
        _raise("manifest_migration_revision_invalid")
    backup_text, backup_binding = _read_manifest_backup(
        backup_root,
        backup_relative_path,
        missing_code="manifest_backup_missing",
    )
    if not hmac.compare_digest(
        backup_binding.sha256,
        expected_manifest_sha256,
    ):
        _raise("manifest_backup_conflict")
    backup_payload, backup_schema, schema_was_omitted = (
        _parse_manifest_for_migration(
            backup_text,
            root_path,
            validate_source_paths=False,
        )
    )
    if backup_schema != LEGACY_MANIFEST_SCHEMA_VERSION:
        _raise("manifest_backup_conflict")
    expected_manifest = _encode_migrated_manifest(
        backup_payload,
        schema_version_was_omitted=schema_was_omitted,
    )
    if not hmac.compare_digest(
        hashlib.sha256(expected_manifest).hexdigest(),
        current_manifest_binding.sha256,
    ) or current_manifest_text.encode("utf-8") != expected_manifest:
        _raise("manifest_migration_conflict")
    try:
        os.fsync(root_fd)
    except OSError:
        _raise("manifest_durability_unknown")
    _verify_workspace_path(root_path, root_stat)
    confirmed_text, confirmed_binding = _read_manifest_text(
        root_fd,
        root_stat.st_dev,
    )
    if (
        confirmed_binding != current_manifest_binding
        or confirmed_text != current_manifest_text
    ):
        _raise("manifest_postcondition_failed")
    return ProtectedSourceManifestMigrationResult(
        status="already_migrated",
        migration_id=migration_id,
        manifest_sha256=confirmed_binding.sha256,
        backup_relative_path=backup_relative_path,
    )


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


def _ensure_manifest_backup(
    backup_root: Path,
    backup_relative_path: str,
    original_bytes: bytes,
) -> FileBinding:
    root_fd, backup_parent_fd, namespace_fd, filename = (
        _open_private_backup_namespace(
            backup_root,
            backup_relative_path,
            create=True,
        )
    )
    temporary_name = f".{filename}.tmp"
    temporary_fd: int | None = None
    try:
        _remove_recoverable_backup_temporary(namespace_fd, temporary_name)
        existing = _read_private_backup_file(
            namespace_fd,
            filename,
            missing_code=None,
        )
        if existing is not None:
            existing_text, existing_binding = existing
            if existing_text.encode("utf-8") != original_bytes:
                _raise("manifest_backup_conflict")
            try:
                os.fsync(namespace_fd)
            except OSError:
                _raise("manifest_backup_unavailable")
            return existing_binding

        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        flags |= getattr(os, "O_NOFOLLOW", 0)
        temporary_fd = os.open(
            temporary_name,
            flags,
            0o600,
            dir_fd=namespace_fd,
        )
        if os.name == "posix":
            os.fchmod(temporary_fd, 0o600)
        view = memoryview(original_bytes)
        while view:
            written = os.write(temporary_fd, view)
            if written <= 0:
                _raise("manifest_backup_unavailable")
            view = view[written:]
        os.fsync(temporary_fd)
        temporary_stat = os.fstat(temporary_fd)
        if (
            not stat.S_ISREG(temporary_stat.st_mode)
            or temporary_stat.st_nlink != 1
            or stat.S_IMODE(temporary_stat.st_mode) != 0o600
            or (
                hasattr(os, "geteuid")
                and temporary_stat.st_uid != os.geteuid()
            )
        ):
            _raise("manifest_backup_unavailable")
        os.close(temporary_fd)
        temporary_fd = None
        try:
            os.link(
                temporary_name,
                filename,
                src_dir_fd=namespace_fd,
                dst_dir_fd=namespace_fd,
                follow_symlinks=False,
            )
        except FileExistsError:
            pass
        os.unlink(temporary_name, dir_fd=namespace_fd)
        try:
            os.fsync(namespace_fd)
        except OSError:
            _raise("manifest_backup_unavailable")
        installed = _read_private_backup_file(
            namespace_fd,
            filename,
            missing_code="manifest_backup_missing",
        )
        assert installed is not None
        installed_text, installed_binding = installed
        if installed_text.encode("utf-8") != original_bytes:
            _raise("manifest_backup_conflict")
        return installed_binding
    except ProtectedSourceRegistrationError:
        raise
    except (OSError, TypeError, ValueError):
        _raise("manifest_backup_unavailable")
    finally:
        if temporary_fd is not None:
            os.close(temporary_fd)
        try:
            os.unlink(temporary_name, dir_fd=namespace_fd)
        except FileNotFoundError:
            pass
        os.close(namespace_fd)
        os.close(backup_parent_fd)
        os.close(root_fd)


def _read_manifest_backup(
    backup_root: Path,
    backup_relative_path: str,
    *,
    missing_code: str,
) -> tuple[str, FileBinding]:
    root_fd, backup_parent_fd, namespace_fd, filename = (
        _open_private_backup_namespace(
            backup_root,
            backup_relative_path,
            create=False,
        )
    )
    try:
        result = _read_private_backup_file(
            namespace_fd,
            filename,
            missing_code=missing_code,
        )
        assert result is not None
        try:
            os.fsync(namespace_fd)
        except OSError:
            _raise("manifest_backup_unavailable")
        return result
    finally:
        os.close(namespace_fd)
        os.close(backup_parent_fd)
        os.close(root_fd)


def _open_private_backup_namespace(
    backup_root: Path,
    backup_relative_path: str,
    *,
    create: bool,
) -> tuple[int, int, int, str]:
    parts = PurePath(backup_relative_path).parts
    if (
        len(parts) != 3
        or parts[0] != MANIFEST_BACKUP_DIRECTORY
        or _HEX_SHA256.fullmatch(parts[1]) is None
        or re.fullmatch(
            r"protected_sources\.schema-v1\.[0-9a-f]{64}\.json",
            parts[2],
        )
        is None
    ):
        _raise("manifest_backup_unavailable")
    root_fd = _open_private_backup_root(backup_root)
    backup_parent_fd: int | None = None
    namespace_fd: int | None = None
    try:
        backup_parent_fd = _open_or_create_private_directory(
            root_fd,
            parts[0],
            create=create,
        )
        namespace_fd = _open_or_create_private_directory(
            backup_parent_fd,
            parts[1],
            create=create,
        )
        return root_fd, backup_parent_fd, namespace_fd, parts[2]
    except Exception:
        if namespace_fd is not None:
            os.close(namespace_fd)
        if backup_parent_fd is not None:
            os.close(backup_parent_fd)
        os.close(root_fd)
        raise


def _open_private_backup_root(backup_root: Path) -> int:
    descriptor: int | None = None
    try:
        path = Path(os.path.abspath(os.fspath(backup_root)))
        metadata = os.lstat(path)
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            _raise("manifest_backup_unavailable")
        flags = os.O_RDONLY
        flags |= getattr(os, "O_DIRECTORY", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(opened.st_mode)
            or opened.st_dev != metadata.st_dev
            or opened.st_ino != metadata.st_ino
            or stat.S_IMODE(opened.st_mode) & 0o077
            or (hasattr(os, "geteuid") and opened.st_uid != os.geteuid())
        ):
            _raise("manifest_backup_unavailable")
        return descriptor
    except ProtectedSourceRegistrationError:
        if descriptor is not None:
            os.close(descriptor)
        raise
    except (OSError, TypeError, ValueError):
        if descriptor is not None:
            os.close(descriptor)
        _raise("manifest_backup_unavailable")


def _open_or_create_private_directory(
    parent_fd: int,
    name: str,
    *,
    create: bool,
) -> int:
    if create:
        try:
            os.mkdir(name, 0o700, dir_fd=parent_fd)
        except FileExistsError:
            pass
        except OSError:
            _raise("manifest_backup_unavailable")
        try:
            os.fsync(parent_fd)
        except OSError:
            _raise("manifest_backup_unavailable")
    flags = os.O_RDONLY
    flags |= getattr(os, "O_DIRECTORY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(name, flags, dir_fd=parent_fd)
    except FileNotFoundError:
        _raise("manifest_backup_missing")
    except OSError:
        _raise("manifest_backup_unavailable")
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o700
        or (hasattr(os, "geteuid") and metadata.st_uid != os.geteuid())
    ):
        os.close(descriptor)
        _raise("manifest_backup_unavailable")
    return descriptor


def _read_private_backup_file(
    namespace_fd: int,
    filename: str,
    *,
    missing_code: str | None,
) -> tuple[str, FileBinding] | None:
    try:
        before = os.stat(filename, dir_fd=namespace_fd, follow_symlinks=False)
    except FileNotFoundError:
        if missing_code is None:
            return None
        _raise(missing_code)
    except OSError:
        _raise("manifest_backup_conflict")
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or stat.S_IMODE(before.st_mode) != 0o600
        or (hasattr(os, "geteuid") and before.st_uid != os.geteuid())
    ):
        _raise("manifest_backup_conflict")
    text, binding = _read_relative_text(
        namespace_fd,
        filename,
        root_device=os.fstat(namespace_fd).st_dev,
        maximum_bytes=MAX_PROTECTED_FILE_BYTES,
        unsafe_code="manifest_backup_conflict",
        too_large_code="manifest_backup_conflict",
        not_utf8_code="manifest_backup_conflict",
    )
    if before.st_dev != binding.device or before.st_ino != binding.inode:
        _raise("manifest_backup_conflict")
    return text, binding


def _remove_recoverable_backup_temporary(
    namespace_fd: int,
    temporary_name: str,
) -> None:
    try:
        metadata = os.stat(
            temporary_name,
            dir_fd=namespace_fd,
            follow_symlinks=False,
        )
    except FileNotFoundError:
        return
    except OSError:
        _raise("manifest_backup_conflict")
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink not in {1, 2}
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or (hasattr(os, "geteuid") and metadata.st_uid != os.geteuid())
    ):
        _raise("manifest_backup_conflict")
    try:
        os.unlink(temporary_name, dir_fd=namespace_fd)
        os.fsync(namespace_fd)
    except OSError:
        _raise("manifest_backup_unavailable")


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
