"""Resolve declared transmission targets without executing a tool or sending data.

Target declarations are inference. Byte snapshots are observations. Neither proves
that the eventual process transmitted those bytes; callers must preserve that boundary.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import re
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from tooluseproxy.engine.evidence import ContentVersion, EvidenceNeed, EvidenceStore, Resource

RESOLVER_VERSION = "payload-v3"


class ResolutionError(ValueError):
    pass


@dataclass(frozen=True)
class Part:
    version: ContentVersion
    content: bytes = field(repr=False)
    extent: dict
    observation: dict


@dataclass
class Resolution:
    parts: list[Part] = field(default_factory=list)
    needs: list[EvidenceNeed] = field(default_factory=list)
    coverage: str = "complete"


def pointer_value(document, pointer):
    if not isinstance(pointer, str) or not pointer.startswith("/tool_input/"):
        raise ResolutionError("input_pointer_required")
    value = document
    try:
        for raw in pointer.split("/")[1:]:
            key = raw.replace("~1", "/").replace("~0", "~")
            value = value[int(key)] if isinstance(value, list) else value[key]
    except (KeyError, IndexError, TypeError, ValueError):
        raise ResolutionError("input_pointer_missing") from None
    if not isinstance(value, str):
        raise ResolutionError("input_value_not_text")
    return value.encode("utf-8")


def safe_parts(path):
    if not isinstance(path, str) or not path or "\x00" in path:
        raise ResolutionError("invalid_resource_path")
    parsed = PurePosixPath(path)
    if parsed.is_absolute() or ".." in parsed.parts or str(parsed) != path or path == ".":
        raise ResolutionError("resource_path_not_canonical_relative")
    # Registration/configuration files are control state, not payload evidence.
    if parsed.name == "protected_sources.json":
        raise ResolutionError("control_state_not_payload")
    return parsed.parts


@contextmanager
def open_resource(root, path):
    parts = safe_parts(path)
    descriptors = []
    try:
        directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        descriptors.append(directory)
        for component in parts[:-1]:
            directory = os.open(
                component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory
            )
            descriptors.append(directory)
        descriptor = os.open(
            parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory
        )
        descriptors.append(descriptor)
        yield descriptor, directory, parts[-1]
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def fingerprint(stat):
    return [stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns]


class PayloadResolver:
    def __init__(
        self, store: EvidenceStore, scope, event, root, *, max_bytes=1_048_576, max_members=128
    ):
        self.store, self.scope, self.event = store, scope, event
        self.root = Path(root)
        self.max_bytes, self.max_members = max_bytes, max_members
        with store.transaction() as conn:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS flow_content_keys (scope TEXT PRIMARY KEY, key BLOB NOT NULL)"
            )
            conn.execute(
                "INSERT INTO flow_content_keys VALUES (?,?) ON CONFLICT DO NOTHING",
                (scope, secrets.token_bytes(32)),
            )
            self.key = conn.execute(
                "SELECT key FROM flow_content_keys WHERE scope=?", (scope,)
            ).fetchone()[0]
            row = conn.execute(
                "SELECT workspace_root,payload_json FROM events WHERE event_id=? AND workspace_id=?",
                (event, scope),
            ).fetchone()
            if not row or row[0] != str(self.root):
                raise ResolutionError("event_scope_root_mismatch")
            self.document = json.loads(row[1])

    def token(self, content):
        return hmac.new(self.key, content, hashlib.sha256).hexdigest()

    def resolve(self, target, document=None):
        if document is not None and document != self.document:
            raise ResolutionError("input_evidence_mismatch")
        document = self.document
        result = Resolution()
        budget = {"bytes": self.max_bytes, "members": self.max_members}

        def visit(item, depth=0):
            if depth > 8 or budget["members"] <= 0:
                result.needs.append(
                    EvidenceNeed("target_extent", "collection", "resolution_member_budget")
                )
                return
            budget["members"] -= 1
            try:
                if not isinstance(item, dict):
                    raise ResolutionError("invalid_target_description")
                kind = item.get("kind")
                if kind == "collection":
                    if (
                        set(item) != {"kind", "members", "complete"}
                        or not isinstance(item["members"], list)
                        or type(item["complete"]) is not bool
                    ):
                        raise ResolutionError("invalid_collection")
                    for member in item["members"][: self.max_members]:
                        visit(member, depth + 1)
                    if not item["complete"] or len(item["members"]) > self.max_members:
                        result.needs.append(
                            EvidenceNeed(
                                "target_extent", "collection", "collection_membership_incomplete"
                            )
                        )
                    return
                if kind in ("inline", "observed", "context"):
                    if set(item) not in (
                        {"kind", "pointer"},
                        {"kind", "pointer", "offset", "length"},
                    ):
                        raise ResolutionError("invalid_inline_target")
                    origin = None
                    if kind == "observed":
                        match = re.fullmatch(r'/previous_calls/(0|[1-9][0-9]*)/output(/.*)?', item['pointer'])
                        calls = getattr(self, 'observed_calls', ())
                        if not match or int(match[1]) >= len(calls):
                            raise ResolutionError('observed_pointer_missing')
                        origin = calls[int(match[1])]
                        if not origin.get('completed'):
                            raise ResolutionError('observed_output_not_completed')
                        # Reuse the strict string/range resolver without accepting
                        # arbitrary pointers into instructions or hidden metadata.
                        content = pointer_value({'tool_input': {'value': origin['output']}},
                                                '/tool_input/value' + (match[2] or ''))
                    elif kind == 'context':
                        context = getattr(self, 'definition_context', {}).get('invocation_context')
                        prefix = '/invocation_context/facts/'
                        if (not context or context['status'] != 'observed'
                                or not item['pointer'].startswith(prefix)):
                            raise ResolutionError('context_pointer_missing')
                        content = pointer_value({'tool_input': context['facts']},
                                                '/tool_input/' + item['pointer'][len(prefix):])
                    else:
                        content = pointer_value(document, item["pointer"])
                    if len(content) > budget["bytes"]:
                        raise ResolutionError("resolution_byte_budget")
                    budget["bytes"] -= len(content)
                    offset, length = item.get("offset", 0), item.get("length")
                    if (
                        type(offset) is not int
                        or offset < 0
                        or offset > len(content)
                        or (
                            length is not None
                            and (
                                type(length) is not int
                                or length < 0
                                or offset + length > len(content)
                            )
                        )
                    ):
                        raise ResolutionError("invalid_inline_extent")
                    selected = (
                        content[offset:] if length is None else content[offset : offset + length]
                    )
                    resource = Resource(self.scope, ('invocation_context' if kind == 'context' else
                                                     "event_output" if origin else "event_input"),
                                        (origin['event_id'] if origin else self.event) + item["pointer"])
                    value = ContentVersion(resource, self.token(content), self.event, len(content))
                    result.parts.append(
                        Part(
                            value,
                            selected,
                            {"offset": offset, "length": len(selected)},
                            {"event": origin['event_id'] if origin else self.event,
                             "pointer": item["pointer"],
                             **({'source_node_id': origin['node_id']} if origin else {})},
                        )
                    )
                    return
                if kind == "file":
                    if set(item) != {"kind", "path", "offset", "length"}:
                        raise ResolutionError("invalid_file_target")
                    offset, length = item["offset"], item["length"]
                    if (
                        type(offset) is not int
                        or offset < 0
                        or (length is not None and (type(length) is not int or length < 0))
                    ):
                        raise ResolutionError("invalid_extent")
                    content, observation = self.read_file(item["path"], budget)
                    if offset > len(content) or (
                        length is not None and offset + length > len(content)
                    ):
                        raise ResolutionError("extent_outside_content")
                    value = ContentVersion(
                        Resource(self.scope, "file", item["path"]),
                        self.token(content),
                        self.event,
                        len(content),
                    )
                    selected = (
                        content[offset:] if length is None else content[offset : offset + length]
                    )
                    result.parts.append(
                        Part(
                            value,
                            selected,
                            {"offset": offset, "length": len(selected)},
                            observation,
                        )
                    )
                    return
                if kind == "snapshot":
                    if set(item) != {"kind", "format", "path", "revision"} or item["format"] != "git":
                        raise ResolutionError("invalid_snapshot_target")
                    from tooluseproxy.engine.repository_evidence import snapshot, SnapshotUnavailable
                    path = item["path"]
                    if path != ".":
                        safe_parts(path)
                    root = self.root / path
                    if root.resolve() != root or not root.is_dir():
                        raise ResolutionError("repository_path_not_local")
                    try:
                        oid, parts = snapshot(root, item["revision"], max_bytes=budget["bytes"],
                                              max_objects=budget["members"])
                    except (ValueError, OSError, UnicodeError, SnapshotUnavailable) as exc:
                        raise ResolutionError(str(exc)) from None
                    for part in parts:
                        content = part["content"]
                        budget["bytes"] -= len(content)
                        budget["members"] -= 1
                        resource = Resource(self.scope, "repository_object", path + ":" + part["oid"])
                        value = ContentVersion(resource, self.token(content), self.event, len(content))
                        result.parts.append(Part(value, content, {"offset":0,"length":len(content)},
                            {"event":self.event,"repository":path,"revision":item["revision"],
                             "head":oid,"object":part["oid"],"object_kind":part["kind"],"paths":part["paths"]}))
                    return
                result.needs.append(
                    EvidenceNeed(
                        "execution_definition" if kind == "transform" else "resource_version",
                        "target",
                        "unsupported_target_kind",
                    )
                )
            except ResolutionError as exc:
                result.needs.append(EvidenceNeed("resource_version", "target", str(exc)))
            except OSError:
                result.needs.append(
                    EvidenceNeed("resource_version", "target", "resource_unavailable")
                )

        visit(target)
        if result.needs:
            result.coverage = "partial" if result.parts else "unsupported"
        return result

    def read_file(self, path, budget):
        import stat

        with open_resource(self.root, path) as (descriptor, directory, name):
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode):
                raise ResolutionError("resource_not_regular_file")
            if before.st_size > budget["bytes"]:
                raise ResolutionError("resolution_byte_budget")
            chunks = []
            remaining = before.st_size + 1
            while remaining:
                chunk = os.read(descriptor, min(65536, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            content = b"".join(chunks)
            after = os.fstat(descriptor)
            current = os.stat(name, dir_fd=directory, follow_symlinks=False)
            if (
                fingerprint(before) != fingerprint(after)
                or fingerprint(after) != fingerprint(current)
                or len(content) != before.st_size
            ):
                raise ResolutionError("resource_changed_during_read")
            budget["bytes"] -= len(content)
        return content, {"path": path, "fingerprint": fingerprint(after), "event": self.event}

    def unchanged(self, result):
        context = getattr(self, "definition_context", None)
        if context is not None:
            from tooluseproxy.engine.invocation_context import unchanged
            if not unchanged(context):
                return False
            from tooluseproxy.engine.requirements import acquire
            for receipt in context.get("execution_definitions", []):
                if receipt["status"] != "observed":
                    continue
                fresh = acquire(context, [{"path": receipt["path"], "reason": receipt["reason"]}])[0]
                if fresh["status"] != "observed" or fresh["sha256"] != receipt["sha256"]:
                    return False
        for part in result.parts:
            if part.version.resource.kind == "repository_object":
                from tooluseproxy.engine.repository_evidence import git_read
                try:
                    observed = part.observation
                    current = git_read(self.root/observed["repository"], 'rev-parse', '--verify',
                                       observed["revision"]+'^{commit}').decode().strip()
                    if current != observed["head"]:
                        return False
                except (ValueError, OSError):
                    return False
                continue
            if part.version.resource.kind != "file":
                continue
            try:
                with open_resource(self.root, part.version.resource.locator) as (descriptor, _, __):
                    if fingerprint(os.fstat(descriptor)) != part.observation["fingerprint"]:
                        return False
            except (OSError, ResolutionError):
                return False
        return True

    def persist(self, target, destination, result):
        unit = self.store.add_transmission(self.scope, self.event, target, destination)
        for part in result.parts:
            self.store.add_version(part.version)
        from tooluseproxy.engine.lineage import record_transmission_snapshots
        record_transmission_snapshots(self, result)
        identity = self.store.add_resolution(
            self.scope,
            unit,
            RESOLVER_VERSION,
            result.coverage,
            "resolved" if not result.needs else "additional_evidence_required",
            [part.observation for part in result.parts],
            [(part.version.identity, part.extent) for part in result.parts],
        )
        for need in result.needs:
            self.store.add_need(self.scope, self.event, need)
        return identity
