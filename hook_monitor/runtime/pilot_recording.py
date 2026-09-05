"""Project a completed policy decision into optional, content-free storage."""

from __future__ import annotations

import hashlib
import json
import time
import uuid
import os
import stat
import sqlite3
import tempfile
from dataclasses import dataclass, asdict, replace
from datetime import UTC, datetime
from pathlib import Path

from hook_monitor.runtime.incremental_analysis import RUNTIME_GRAPH_DETECTOR_VERSION
from hook_monitor.runtime.pilot_models import (
    EvidenceSource, Externality, PayloadResolution, PilotObservation, PolicyAction,
    ReasonCode, RecordState, ReviewState, StudyCohort, ToolFamily,
)
from hook_monitor.runtime.pilot_storage import store_pilot_observation, ENUM_FIELDS
from tooluseproxy import __version__


@dataclass
class PilotPolicyFacts:
    eligible: bool = False
    completed: bool = False
    resolution: PayloadResolution = PayloadResolution.UNRESOLVED
    evidence: EvidenceSource = EvidenceSource.FALLBACK
    reason: ReasonCode = ReasonCode.UNMAPPED

    def selected(self, decision: object) -> None:
        kind = getattr(decision, "evidence_kind", None)
        if kind == "resolved_file_exact":
            self.reason = ReasonCode.PROTECTED_EXACT_MATCH
            self.evidence = EvidenceSource.RESOLVED
        elif kind == "unresolved_external_payload":
            self.reason = ReasonCode.PROTECTED_PAYLOAD_UNRESOLVED
            self.resolution = PayloadResolution.UNRESOLVED
            self.evidence = EvidenceSource.FALLBACK
        elif decision is not None:
            self.reason = ReasonCode.PROTECTED_LINEAGE
            self.evidence = EvidenceSource.LINEAGE
        else:
            self.reason = ReasonCode.PUBLIC_FLOW_ABSENT


def record_completed_policy(
    db_path: Path, *, workspace_id: str, event_id: str,
    effective_settings: dict[str, bool], adapter: str | None,
    externality_state: str | None, hook_output: dict[str, object], started: float,
    facts: PilotPolicyFacts,
) -> bool:
    """Return false on evaluation failure; never modify the caller's decision."""
    item = None
    try:
        if not facts.eligible or effective_settings.get("pilot-recording") is not True:
            return True
        output = hook_output.get("hookSpecificOutput", {})
        blocked = isinstance(output, dict) and output.get("permissionDecision") == "deny"
        externality = {
            "known_local": Externality.LOCAL,
            "known_external": Externality.EXTERNAL,
        }.get(externality_state, Externality.UNKNOWN)
        item = PilotObservation(
            observation_id=uuid.uuid4().hex,
            observed_at=datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            workspace_id=workspace_id,
            event_ref_sha256=hashlib.sha256(event_id.encode()).hexdigest(),
            product_version=__version__,
            detector_version="pilot-v1-" + hashlib.sha256(
                (RUNTIME_GRAPH_DETECTOR_VERSION + ":" + __version__).encode()
            ).hexdigest()[:48],
            settings_revision=hashlib.sha256(json.dumps(
                effective_settings, sort_keys=True, separators=(",", ":")
            ).encode()).hexdigest(),
            tool_family={"bash": ToolFamily.SHELL, "mcp": ToolFamily.MCP,
                         "function": ToolFamily.FUNCTION}.get(adapter, ToolFamily.OTHER),
            externality=externality,
            payload_resolution=facts.resolution,
            evidence_source=facts.evidence,
            policy_action=PolicyAction.BLOCK if blocked else PolicyAction.ALLOW,
            reason_code=facts.reason,
            decision_ms=min(60_000.0, max(0.0, (time.monotonic() - started) * 1000)),
            review_state=ReviewState.PENDING if blocked else ReviewState.NOT_NEEDED,
            cause_candidate=None,
            record_state=RecordState.COMPLETE if facts.completed else RecordState.INCOMPLETE,
            study_cohort=StudyCohort.PILOT,
        )
        store_pilot_observation(db_path, item)
    except Exception:
        if item is not None:
            _save_pending(db_path, item)
        return False
    return True


def _pending_directory(db_path: Path) -> Path:
    return db_path.parent / (db_path.name + ".pilot-pending")


def _save_pending(db_path: Path, item: PilotObservation) -> None:
    """Keep the already value-free projection if SQLite alone is unavailable."""
    temporary = None
    try:
        directory = _pending_directory(db_path)
        directory.mkdir(mode=0o700, exist_ok=True)
        if directory.is_symlink() or not directory.is_dir():
            return
        path = directory / (item.event_ref_sha256 + ".json")
        descriptor, temporary = tempfile.mkstemp(prefix=".pending-", dir=directory)
        with os.fdopen(descriptor, "w") as stream:
            json.dump(asdict(item), stream, allow_nan=False)
            stream.flush()
            os.fsync(stream.fileno())
        # Publish only complete records; an interrupted write cannot occupy the
        # retry filename forever. Linking also preserves the first writer.
        os.link(temporary, path)
    except (OSError, ValueError):
        # Disk-full and permission failures can also prevent this recovery copy.
        return
    finally:
        if temporary is not None:
            try:
                os.unlink(temporary)
            except OSError:
                pass


def recover_pending_pilot(db_path: Path, *, limit: int = 32) -> int:
    """Bounded local retry; preserve recovered records rather than deleting them."""
    directory = _pending_directory(db_path)
    if directory.is_symlink() or not directory.is_dir():
        return 0
    recovered = 0
    try:
        for index, path in enumerate(directory.glob("*.json")):
            if index >= limit:
                break
            try:
                descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
                with os.fdopen(descriptor) as stream:
                    if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                        continue
                    data = stream.read(4097)
                if len(data) > 4096:
                    continue
                values = json.loads(data)
                for name, enum in ENUM_FIELDS.items():
                    if values.get(name) is not None:
                        values[name] = enum(values[name])
                original = PilotObservation(**values)
                if path.name != original.event_ref_sha256 + ".json":
                    continue
                item = replace(original, record_state=(
                    RecordState.INCOMPLETE if original.record_state == RecordState.INCOMPLETE
                    else RecordState.RECONSTRUCTED
                ))
                store_pilot_observation(db_path, item)
                path.rename(path.with_suffix(".recovered"))
                recovered += 1
            except (OSError, ValueError, TypeError, KeyError, sqlite3.Error):
                continue
    except OSError:
        return recovered
    return recovered
