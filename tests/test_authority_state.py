from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest

from tooluseproxy.authority_state import (
    AuthorityError, State, Target, _Store, administrator_transition, decode_state,
)


@pytest.fixture
def fixture_store(tmp_path):
    directory = tmp_path / "authority"
    directory.mkdir(mode=0o755)
    # Fixture owner is deliberately different from production uid 0. These
    # tests prove protocol behavior, not that administrator installation exists.
    return _Store(directory, owner=os.geteuid())


@pytest.fixture
def target(tmp_path):
    return Target(max(os.geteuid(), 1), str(tmp_path / "project"), str(tmp_path / "data"))


def enroll(store, target):
    return store.transition(target, expected="absent", operation="a" * 32, action="enroll")


def read(store, target):
    with store.opened() as directory:
        return store.read(directory, target)


def test_production_writer_rejects_agent_before_opening_anything(target, monkeypatch):
    monkeypatch.setattr(os, "geteuid", lambda: 501)
    with patch.object(_Store, "opened", side_effect=AssertionError("must not open")):
        with pytest.raises(AuthorityError, match="administrator_context_required"):
            administrator_transition(target, expected="absent", operation="b" * 32,
                                     action="deactivate")


def test_lifecycle_replay_and_reinitialization(fixture_store, target):
    store = fixture_store
    initial = enroll(store, target)
    with pytest.raises(AuthorityError, match="operation_conflict"):
        store.transition(target, expected=initial.generation, operation=initial.operation,
                         action="deactivate")
    stopped = store.transition(target, expected=initial.generation, operation="b" * 32,
                               action="deactivate")
    assert stopped.phase == "inactive"
    assert store.transition(target, expected=initial.generation, operation="b" * 32,
                            action="deactivate") == stopped
    restarted = store.transition(target, expected=stopped.generation, operation="c" * 32,
                                 action="reactivate")
    assert restarted.generation != stopped.generation
    assert restarted.phase == "active"
    with pytest.raises(AuthorityError, match="generation_conflict"):
        store.transition(target, expected=initial.generation, operation="b" * 32,
                         action="deactivate")
    assert read(store, target) == restarted


def test_enrollment_is_not_silently_inferred_from_legacy_state(fixture_store, target):
    with pytest.raises(AuthorityError, match="enrollment_required"):
        fixture_store.transition(target, expected="absent", operation="b" * 32,
                                 action="deactivate")
    assert read(fixture_store, target) is None


def test_deactivation_drains_existing_hooks_and_refuses_reactivation(fixture_store, target):
    store = fixture_store
    initial = enroll(store, target)
    with store.lease(target) as lease:
        assert lease == initial
        draining = store.transition(target, expected=initial.generation, operation="b" * 32,
                                    action="deactivate")
        assert draining.phase == "deactivating"
        with store.lease(target) as next_hook:
            assert next_hook.phase == "deactivating"
        with pytest.raises(AuthorityError, match="deactivation_not_drained"):
            store.transition(target, expected=draining.generation, operation="c" * 32,
                             action="reactivate")
    stopped = store.transition(target, expected=draining.generation, operation="b" * 32,
                               action="deactivate")
    assert stopped.phase == "inactive"
    assert stopped.generation == draining.generation


def test_interrupted_transition_resumes_without_reenabling(fixture_store, target, monkeypatch):
    store = fixture_store
    initial = enroll(store, target)
    publish = store._publish

    def interrupted(directory, state):
        if state.phase == "inactive":
            raise OSError("simulated interruption before final publication")
        publish(directory, state)

    with monkeypatch.context() as isolated:
        isolated.setattr(store, "_publish", interrupted)
        with pytest.raises(OSError):
            store.transition(target, expected=initial.generation, operation="b" * 32,
                             action="deactivate")
    current = read(store, target)
    assert current.phase == "deactivating"
    assert store.transition(target, expected=current.generation, operation="b" * 32,
                            action="deactivate").phase == "inactive"


def test_other_project_and_user_data_are_unchanged(fixture_store, target, tmp_path):
    store = fixture_store
    other = Target(target.uid, str(tmp_path / "other"), target.data_dir)
    untouched = enroll(store, other)
    source = Path(target.workspace)
    source.mkdir()
    # Artificial files only; never inspect the developer workspace manifest.
    (source / "protected_sources.json").write_bytes(b"synthetic source list")
    data = Path(target.data_dir)
    data.mkdir()
    (data / "events.db").write_bytes(b"broken database")
    initial = enroll(store, target)
    before = {p: p.read_bytes() for base in (source, data) for p in base.iterdir()}
    store.transition(target, expected=initial.generation, operation="b" * 32,
                     action="deactivate")
    assert read(store, other) == untouched
    assert before == {p: p.read_bytes() for base in (source, data) for p in base.iterdir()}
    with pytest.raises(AuthorityError, match="generation_conflict"):
        store.transition(other, expected=initial.generation, operation="b" * 32,
                         action="deactivate")


@pytest.mark.parametrize("damage", ["symlink", "hardlink", "writable", "corrupt", "other"])
def test_untrusted_state_fails_closed(fixture_store, target, tmp_path, damage):
    store = fixture_store
    initial = enroll(store, target)
    state_file = store.directory / (target.key + ".json")
    if damage == "symlink":
        state_file.unlink()
        state_file.symlink_to(tmp_path / "nonexistent")
    elif damage == "hardlink":
        os.link(state_file, tmp_path / "linked")
    elif damage == "writable":
        state_file.chmod(0o666)
    elif damage == "corrupt":
        state_file.write_bytes(b"not json")
    elif damage == "other":
        payload = initial.payload()
        payload["target"]["workspace"] = str(tmp_path / "other")
        state_file.write_text(json.dumps(payload))
    with pytest.raises((AuthorityError, OSError)):
        read(store, target)


@pytest.mark.parametrize("mutation", [
    lambda value: value.update(schema_version=True),
    lambda value: value.update(phase="unknown"),
    lambda value: value.update(generation="forged"),
    lambda value: value.update(extra=True),
    lambda value: value["target"].update(uid=True),
])
def test_strict_protocol(target, mutation):
    value = State(target, "a" * 32, "active", "b" * 32).payload()
    mutation(value)
    with pytest.raises(AuthorityError):
        decode_state(json.dumps(value).encode(), target)


def test_duplicate_fields_are_not_accepted(target):
    with pytest.raises(AuthorityError, match="duplicate_authority_field"):
        decode_state(b'{"schema_version":1,"schema_version":1}', target)


def test_state_rename_is_atomic_and_leases_keep_stable_inode(fixture_store, target):
    store = fixture_store
    current = enroll(store, target)
    lease_file = store.directory / (target.key + ".lease")
    inode = lease_file.stat().st_ino
    current = store.transition(target, expected=current.generation, operation="b" * 32,
                               action="deactivate")
    assert lease_file.stat().st_ino == inode
    assert not list(store.directory.glob(".state-*"))
    assert read(store, target) == current


def test_restrictive_administrator_umask_does_not_break_hook_reads(fixture_store, target):
    old_mask = os.umask(0o077)
    try:
        enroll(fixture_store, target)
    finally:
        os.umask(old_mask)
    for suffix in (".json", ".lease", ".admin"):
        assert (fixture_store.directory / (target.key + suffix)).stat().st_mode & 0o777 == 0o644


def test_oversized_state_is_rejected_before_publication(fixture_store, target):
    oversized = Target(target.uid, "/" + "x" * 9000, target.data_dir)
    with pytest.raises(AuthorityError, match="state_too_large"):
        enroll(fixture_store, oversized)
    assert read(fixture_store, oversized) is None
    assert not list(fixture_store.directory.glob(".state-*"))
