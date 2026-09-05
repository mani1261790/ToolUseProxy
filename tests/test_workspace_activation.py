from __future__ import annotations

import io
import json
import gc

import pytest

from hook_monitor.runtime.storage import EventStore
from hook_monitor.runtime.workspace import resolve_workspace
from tooluseproxy.integrations.activation import (
    activation_directory, activation_path, save_workspace_activations,
)
from tooluseproxy.integrations.codex import CODEX_HOOK_PHASES, run_codex_hook


def invoke(monkeypatch, capsys, database, cwd, phase):
    payload = {"cwd": str(cwd), "session_id": "test", "tool_name": "Bash",
               "tool_input": {"command": "printf public"}}
    monkeypatch.setattr("sys.stdin", io.TextIOWrapper(
        io.BytesIO(json.dumps(payload).encode())
    ))
    assert run_codex_hook(phase, db_path=database) == 0
    output = capsys.readouterr()
    assert output.err == ""
    return output.out


@pytest.mark.parametrize("phase", CODEX_HOOK_PHASES)
def test_fresh_project_is_silent_and_creates_nothing(tmp_path, monkeypatch, capsys, phase):
    database = tmp_path / "data" / "events.db"
    assert invoke(monkeypatch, capsys, database, tmp_path, phase) == ""
    assert not database.parent.exists()


@pytest.mark.parametrize("phase", CODEX_HOOK_PHASES)
@pytest.mark.parametrize("database_state", ["ready", "missing", "broken", "old"])
def test_unrelated_project_is_silent_even_when_enrolled_database_breaks(
    tmp_path, monkeypatch, capsys, phase, database_state,
):
    enrolled = tmp_path / "enrolled"
    unrelated = tmp_path / "unrelated"
    enrolled.mkdir()
    unrelated.mkdir()
    database = tmp_path / "events.db"
    store = EventStore(database)
    store.initialize()
    store.register_workspace(resolve_workspace(str(enrolled)))
    save_workspace_activations(database)
    gc.collect()  # Close SQLite handles/checkpoint WAL before simulating damage.
    if database_state == "missing":
        database.unlink()
    elif database_state == "broken":
        database.write_bytes(b"broken database")
    elif database_state == "old":
        import sqlite3
        with sqlite3.connect(database) as connection:
            connection.execute("PRAGMA user_version=1")
    before = {
        str(path.relative_to(tmp_path)): path.read_bytes()
        for path in tmp_path.rglob("*")
        if path.is_file()
    }
    monkeypatch.setenv("TOOLUSEPROXY_WORKSPACE_ROOT", str(enrolled))
    assert invoke(monkeypatch, capsys, database, unrelated, phase) == ""
    assert before == {
        str(path.relative_to(tmp_path)): path.read_bytes()
        for path in tmp_path.rglob("*")
        if path.is_file()
    }


@pytest.mark.parametrize("damage", ["missing", "broken", "index"])
def test_enrolled_project_fails_closed_on_damage(tmp_path, monkeypatch, capsys, damage):
    database = tmp_path / "events.db"
    store = EventStore(database)
    store.initialize()
    store.register_workspace(resolve_workspace(str(tmp_path)))
    save_workspace_activations(database)
    gc.collect()
    if damage == "missing":
        database.unlink()
    elif damage == "broken":
        for suffix in ("-wal", "-shm"):
            database.with_name(database.name + suffix).unlink(missing_ok=True)
        database.write_bytes(b"broken database")
    else:
        activation_path(database, str(tmp_path)).write_text("broken marker")
    if damage == "broken":
        from hook_monitor.runtime.storage import SchemaCompatibilityError
        with pytest.raises(SchemaCompatibilityError):
            store.require_runtime_schema()
    output = json.loads(invoke(monkeypatch, capsys, database, tmp_path, "pre-tool-use"))
    assert output["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_legacy_registration_still_protects_and_sibling_stays_silent(
    tmp_path, monkeypatch, capsys,
):
    database = tmp_path / "events.db"
    enrolled = tmp_path / "enrolled"
    sibling = tmp_path / "sibling"
    enrolled.mkdir()
    sibling.mkdir()
    store = EventStore(database)
    store.initialize()
    store.register_workspace(resolve_workspace(str(enrolled), discovered_by="init"))
    import shutil
    shutil.rmtree(activation_directory(database))  # Existing installation before this fix.
    assert invoke(monkeypatch, capsys, database, sibling, "session-start") == ""
    assert "WebSearch" in invoke(monkeypatch, capsys, database, enrolled, "session-start")
    assert not activation_directory(database).exists()


def test_old_automatic_observation_is_not_enrollment(tmp_path, monkeypatch, capsys):
    from hook_monitor.runtime.parser import normalize_event

    database = tmp_path / "events.db"
    store = EventStore(database)
    store.initialize()
    event = normalize_event("session_start", {"cwd": str(tmp_path), "session_id": "old"})
    store.record(event, [])
    assert invoke(monkeypatch, capsys, database, tmp_path, "session-start") == ""


def test_lost_registration_is_not_silently_replaced_with_defaults(tmp_path, monkeypatch, capsys):
    import sqlite3

    database = tmp_path / "events.db"
    store = EventStore(database)
    store.initialize()
    store.register_workspace(resolve_workspace(str(tmp_path)))
    with sqlite3.connect(database) as connection:
        connection.execute("DELETE FROM workspaces")
    output = json.loads(invoke(monkeypatch, capsys, database, tmp_path, "pre-tool-use"))
    assert output["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_input_replay_preserves_bytes_and_bounded_read():
    from tooluseproxy.integrations.codex import _ReplayInput

    remainder = io.BytesIO(b"tail")
    replay = _ReplayInput(b"prefix", remainder)
    assert replay.read(3) == b"pre"
    assert remainder.tell() == 0
    assert replay.read(4) == b"fixt"
    assert replay.read() == b"ail"


def test_enrollment_updates_keep_previous_projects(tmp_path):
    from tooluseproxy.integrations.activation import enabled_workspace_root

    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir()
    second.mkdir()
    database = tmp_path / "events.db"
    store = EventStore(database)
    store.initialize()
    store.register_workspace(resolve_workspace(str(first)))
    store.register_workspace(resolve_workspace(str(second)))
    assert enabled_workspace_root(database, str(first)) == str(first)
    assert enabled_workspace_root(database, str(second)) == str(second)
    assert activation_path(database, str(first)).stat().st_mode & 0o777 == 0o600


def test_automatic_child_registration_cannot_replace_enabled_parent(tmp_path, monkeypatch, capsys):
    import sqlite3
    from hook_monitor.runtime.parser import normalize_event

    child = tmp_path / "child"
    child.mkdir()
    database = tmp_path / "events.db"
    store = EventStore(database)
    store.initialize()
    store.register_workspace(resolve_workspace(str(tmp_path)))
    store.record(normalize_event("session_start", {
        "cwd": str(child), "session_id": "old-child",
    }), [])
    monkeypatch.setenv("TOOLUSEPROXY_WORKSPACE_ROOT", str(child))
    assert "WebSearch" in invoke(monkeypatch, capsys, database, child, "session-start")
    with sqlite3.connect(database) as connection:
        root = connection.execute(
            "SELECT workspace_root FROM events WHERE session_id='test'"
        ).fetchone()[0]
    assert root == str(tmp_path)


def test_enabled_parent_does_not_activate_nested_repository(tmp_path, monkeypatch, capsys):
    parent = tmp_path / "parent"
    child = parent / "child-repository"
    child.mkdir(parents=True)
    (child / ".git").mkdir()
    database = tmp_path / "events.db"
    store = EventStore(database)
    store.initialize()
    store.register_workspace(resolve_workspace(str(parent)))
    assert invoke(monkeypatch, capsys, database, child, "session-start") == ""


def test_corrupt_marker_affects_only_its_project(tmp_path, monkeypatch, capsys):
    enabled = tmp_path / "enabled"
    unrelated = tmp_path / "unrelated"
    enabled.mkdir()
    unrelated.mkdir()
    database = tmp_path / "events.db"
    store = EventStore(database)
    store.initialize()
    store.register_workspace(resolve_workspace(str(enabled)))
    activation_path(database, str(enabled)).write_text("broken marker")
    assert invoke(monkeypatch, capsys, database, unrelated, "session-start") == ""
    output = json.loads(invoke(monkeypatch, capsys, database, enabled, "pre-tool-use"))
    assert output["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_concurrent_enrollment_keeps_every_project(tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    from tooluseproxy.integrations.activation import enabled_workspace_root

    database = tmp_path / "events.db"
    EventStore(database).initialize()
    roots = [tmp_path / f"project-{index}" for index in range(8)]
    for root in roots:
        root.mkdir()

    def enroll(root):
        EventStore(database).register_workspace(resolve_workspace(str(root)))

    with ThreadPoolExecutor(max_workers=4) as executor:
        list(executor.map(enroll, roots))
    assert all(
        enabled_workspace_root(database, str(root)) == str(root)
        for root in roots
    )


def test_missing_payload_cwd_uses_current_unconfigured_project(
    tmp_path, monkeypatch, capsys,
):
    enabled = tmp_path / "enabled"
    unrelated = tmp_path / "unrelated"
    enabled.mkdir()
    unrelated.mkdir()
    database = tmp_path / "events.db"
    store = EventStore(database)
    store.initialize()
    store.register_workspace(resolve_workspace(str(enabled)))
    monkeypatch.chdir(unrelated)
    monkeypatch.setattr("sys.stdin", io.TextIOWrapper(
        io.BytesIO(b'{"hook_event_name":"SessionStart"}')
    ))
    assert run_codex_hook("session-start", db_path=database) == 0
    assert capsys.readouterr().out == ""


def test_activation_directory_creation_without_marker_keeps_legacy_protection(
    tmp_path, monkeypatch, capsys,
):
    database = tmp_path / "events.db"
    store = EventStore(database)
    store.initialize()
    store.register_workspace(resolve_workspace(str(tmp_path), discovered_by="init"))
    import shutil
    shutil.rmtree(activation_directory(database))
    activation_directory(database).mkdir()
    assert "WebSearch" in invoke(
        monkeypatch, capsys, database, tmp_path, "session-start"
    )
