"""OS-owned project lifecycle state, separate from the detection database.

This module is not an authentication UI. Production writes require an existing
administrator execution context and an OS-owned store. The agent-facing CLI
does not call the writer. Tests use an isolated store, never the machine store.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

AUTHORITY_DIRECTORY = Path("/Library/Application Support/ToolUseProxy/Authority")
MAX_STATE_BYTES = 8192
_REVISION = re.compile(r"[0-9a-f]{32}\Z")


class AuthorityError(ValueError):
    """A stable, content-free lifecycle rejection."""


@dataclass(frozen=True)
class Target:
    uid: int
    workspace: str
    data_dir: str

    def __post_init__(self) -> None:
        if type(self.uid) is not int or self.uid <= 0:
            raise AuthorityError("invalid_target_uid")
        for value in (self.workspace, self.data_dir):
            if not isinstance(value, str) or not value.startswith("/") or "\0" in value:
                raise AuthorityError("invalid_target_path")
            if os.path.normpath(value) != value:
                raise AuthorityError("noncanonical_target_path")

    @property
    def key(self) -> str:
        encoded = json.dumps(self.payload(), sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha256(encoded).hexdigest()

    def payload(self) -> dict[str, object]:
        return {"uid": self.uid, "workspace": self.workspace, "data_dir": self.data_dir}


@dataclass(frozen=True)
class State:
    target: Target
    generation: str
    phase: str
    operation: str
    action: str = "enroll"

    def payload(self) -> dict[str, object]:
        return {"schema_version": 1, "target": self.target.payload(),
                "generation": self.generation, "phase": self.phase,
                "operation": self.operation, "action": self.action}


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise AuthorityError("duplicate_authority_field")
        result[key] = value
    return result


def decode_state(raw: bytes, target: Target) -> State:
    if len(raw) > MAX_STATE_BYTES:
        raise AuthorityError("authority_state_too_large")
    try:
        value = json.loads(raw, object_pairs_hook=_unique_object)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise AuthorityError("invalid_authority_state") from exc
    if not isinstance(value, dict) or set(value) != {
        "schema_version", "target", "generation", "phase", "operation", "action",
    }:
        raise AuthorityError("invalid_authority_fields")
    if type(value["schema_version"]) is not int or value["schema_version"] != 1:
        raise AuthorityError("invalid_authority_version")
    binding = value["target"]
    if (not isinstance(binding, dict) or type(binding.get("uid")) is not int
            or binding != target.payload()):
        raise AuthorityError("authority_target_mismatch")
    for field in ("generation", "operation"):
        if not isinstance(value[field], str) or not _REVISION.fullmatch(value[field]):
            raise AuthorityError("invalid_authority_revision")
    if value["phase"] not in ("active", "deactivating", "inactive"):
        raise AuthorityError("invalid_authority_phase")
    if value["action"] not in ("enroll", "reactivate", "deactivate"):
        raise AuthorityError("invalid_authority_action")
    if (value["action"] == "deactivate") != (value["phase"] != "active"):
        raise AuthorityError("authority_action_phase_mismatch")
    return State(target, value["generation"], value["phase"], value["operation"], value["action"])


class _Store:
    """Descriptor-anchored store. The private owner argument is for fixtures.

    Public entry points always use the fixed OS-owned directory and uid 0.
    Files are never overwritten in place; lease inodes remain stable.
    """

    def __init__(self, directory: Path, *, owner: int = 0) -> None:
        if not directory.is_absolute() or str(directory) != os.path.normpath(directory):
            raise AuthorityError("invalid_authority_directory")
        self.directory = directory
        self.owner = owner

    def _check(self, metadata: os.stat_result, *, directory: bool = False) -> None:
        valid_type = stat.S_ISDIR if directory else stat.S_ISREG
        if (not valid_type(metadata.st_mode) or metadata.st_uid != self.owner
                or metadata.st_mode & 0o022):
            raise AuthorityError("untrusted_authority_storage")
        if not directory and metadata.st_nlink != 1:
            raise AuthorityError("linked_authority_file")

    @contextmanager
    def opened(self) -> Iterator[int]:
        # Walk from / with O_NOFOLLOW at every component. No ancestor can be
        # replaced by the unprivileged agent in a production installation.
        descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
        try:
            for part in self.directory.parts[1:]:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                dir_fd=descriptor)
                os.close(descriptor)
                descriptor = child
                if self.owner == 0:
                    self._check(os.fstat(descriptor), directory=True)
                    # Account for ACL grants not represented in POSIX mode.
                    if os.geteuid() != 0 and os.access(
                        f"/dev/fd/{descriptor}", os.W_OK,
                    ):
                        raise AuthorityError("authority_directory_writable_by_agent")
            self._check(os.fstat(descriptor), directory=True)
            yield descriptor
        finally:
            os.close(descriptor)

    def _open_file(self, directory: int, name: str, *, create: bool = False) -> int:
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
        created = False
        if create:
            try:
                descriptor = os.open(name, flags | os.O_CREAT | os.O_EXCL, 0o644,
                                     dir_fd=directory)
                created = True
            except FileExistsError:
                descriptor = os.open(name, flags, dir_fd=directory)
        else:
            descriptor = os.open(name, flags, dir_fd=directory)
        try:
            if created:
                os.fchmod(descriptor, 0o644)
            self._check(os.fstat(descriptor))
            if self.owner == 0 and os.geteuid() != 0 and os.access(
                f"/dev/fd/{descriptor}", os.W_OK,
            ):
                raise AuthorityError("authority_file_writable_by_agent")
        except BaseException:
            os.close(descriptor)
            raise
        return descriptor

    def read(self, directory: int, target: Target) -> State | None:
        try:
            descriptor = self._open_file(directory, target.key + ".json")
        except FileNotFoundError:
            return None
        try:
            return decode_state(os.read(descriptor, MAX_STATE_BYTES + 1), target)
        finally:
            os.close(descriptor)

    def _publish(self, directory: int, state: State) -> None:
        temporary = ".state-" + uuid.uuid4().hex
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o644, dir_fd=directory)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                os.fchmod(stream.fileno(), 0o644)
                stream.write(json.dumps(state.payload(), sort_keys=True).encode() + b"\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, state.target.key + ".json",
                       src_dir_fd=directory, dst_dir_fd=directory)
            os.fsync(directory)
        finally:
            try:
                os.unlink(temporary, dir_fd=directory)
            except FileNotFoundError:
                pass

    @contextmanager
    def _lock(self, directory: int, name: str, *, exclusive: bool,
              create: bool = False) -> Iterator[int]:
        import fcntl

        descriptor = self._open_file(directory, name, create=create)
        try:
            try:
                fcntl.flock(descriptor, (fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
                            | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise AuthorityError("authority_operation_in_progress") from exc
            yield descriptor
        finally:
            os.close(descriptor)

    @contextmanager
    def lease(self, target: Target) -> Iterator[State | None]:
        with self.opened() as directory:
            state = self.read(directory, target)
            if state is None:
                yield None
                return
            if state.phase != "active":
                yield state
                return
            with self._lock(directory, target.key + ".lease", exclusive=False):
                # Publication may have happened between the first read and lock.
                current = self.read(directory, target)
                if current is None:
                    raise AuthorityError("authority_state_disappeared")
                yield current

    def transition(self, target: Target, *, expected: str, operation: str,
                   action: str) -> State:
        # This check cannot be replaced by a caller-provided approval boolean.
        if os.geteuid() != self.owner:
            raise AuthorityError("administrator_context_required")
        if action not in ("enroll", "deactivate", "reactivate"):
            raise AuthorityError("invalid_authority_action")
        if not isinstance(operation, str) or not _REVISION.fullmatch(operation):
            raise AuthorityError("invalid_authority_operation")
        with self.opened() as directory:
            with self._lock(directory, target.key + ".admin", exclusive=True, create=True):
                current = self.read(directory, target)
                if current is None and action != "enroll":
                    # Legacy Hooks have no leases. Enrollment must happen while
                    # the operator has stopped/restarted them, never as a side
                    # effect of claiming a successful deactivation.
                    raise AuthorityError("authority_enrollment_required")
                if current is not None and action == "enroll":
                    raise AuthorityError("authority_already_enrolled")
                if current and current.operation == operation:
                    if current.action != action:
                        raise AuthorityError("authority_operation_conflict")
                    # A completed request is a result lookup, never a new action.
                    if action == "deactivate" and current.phase == "inactive":
                        return current
                    if action == "reactivate" and current.phase == "active":
                        return current
                if (current.generation if current else "absent") != expected:
                    raise AuthorityError("authority_generation_conflict")
                if current and current.operation == operation and action != "deactivate":
                    raise AuthorityError("authority_operation_conflict")
                lease = self._open_file(directory, target.key + ".lease", create=True)
                os.close(lease)
                if action in ("enroll", "reactivate"):
                    if current and current.phase == "deactivating":
                        raise AuthorityError("deactivation_not_drained")
                    result = State(target, uuid.uuid4().hex, "active", operation, action)
                    with self._lock(directory, target.key + ".lease", exclusive=True):
                        self._publish(directory, result)
                    return result
                if current is None or current.phase != "deactivating":
                    current = State(target, uuid.uuid4().hex, "deactivating", operation, action)
                    self._publish(directory, current)
                elif current.operation != operation:
                    raise AuthorityError("authority_operation_conflict")
                try:
                    with self._lock(directory, target.key + ".lease", exclusive=True):
                        result = State(target, current.generation, "inactive", operation, action)
                        self._publish(directory, result)
                        return result
                except AuthorityError as exc:
                    if str(exc) != "authority_operation_in_progress":
                        raise
                    # Durable deactivating state prevents new admissions. The
                    # administrator can retry this generation after leases end.
                    return current


def read_authority_state(target: Target) -> State | None:
    if not AUTHORITY_DIRECTORY.exists():
        if AUTHORITY_DIRECTORY.is_symlink():
            raise AuthorityError("untrusted_authority_storage")
        return None
    with _Store(AUTHORITY_DIRECTORY).opened() as directory:
        return _Store(AUTHORITY_DIRECTORY).read(directory, target)


def administrator_transition(target: Target, *, expected: str, operation: str,
                             action: str) -> State:
    """Only an isolated administrator entry point may use this writer.

    There is intentionally no install/store override or environment switch.
    No source file, user database or plugin configuration is opened here.
    """
    if os.geteuid() != 0:
        raise AuthorityError("administrator_context_required")
    return _Store(AUTHORITY_DIRECTORY).transition(
        target, expected=expected, operation=operation, action=action,
    )
