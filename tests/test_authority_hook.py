from __future__ import annotations

import io
import json
import os

import pytest

from tooluseproxy.authority_state import Target, _Store
from tooluseproxy.integrations.codex import CODEX_HOOK_PHASES, run_codex_hook


@pytest.fixture
def enrolled(tmp_path, monkeypatch):
    directory = tmp_path / "authority"
    directory.mkdir(mode=0o755)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    store = _Store(directory, owner=os.geteuid())
    target = Target(os.getuid(), str(workspace), str(data_dir))
    state = store.transition(target, expected="absent", operation="a" * 32, action="enroll")
    monkeypatch.setattr("tooluseproxy.authority_state.AUTHORITY_DIRECTORY", directory)
    monkeypatch.setattr("tooluseproxy.integrations.authority._Store", lambda _: store)
    return store, target, state


@pytest.mark.parametrize("phase", CODEX_HOOK_PHASES)
@pytest.mark.parametrize("damaged_database", [False, True])
def test_inactive_hooks_do_not_touch_database_or_legacy_activation(
    enrolled, monkeypatch, capsys, phase, damaged_database,
):
    from pathlib import Path

    store, target, initial = enrolled
    database = Path(target.data_dir) / "events.db"
    if damaged_database:
        database.write_bytes(b"damaged fixture database")
    store.transition(target, expected=initial.generation, operation="b" * 32,
                     action="deactivate")

    def forbidden(*args, **kwargs):
        raise AssertionError("inactive project must not access runtime state")

    monkeypatch.setattr("tooluseproxy.integrations.codex.enabled_workspace_root", forbidden)
    monkeypatch.setattr("sqlite3.connect", forbidden)
    monkeypatch.setattr("sys.stdin", io.TextIOWrapper(io.BytesIO(
        json.dumps({"cwd": target.workspace}).encode(),
    )))
    assert run_codex_hook(phase, db_path=database) == 0
    captured = capsys.readouterr()
    assert captured.out == captured.err == ""
    assert list(Path(target.data_dir).iterdir()) == ([database] if damaged_database else [])
    if damaged_database:
        assert database.read_bytes() == b"damaged fixture database"


def test_hook_lease_covers_legacy_activation_and_releases_on_error(enrolled, monkeypatch, capsys):
    from pathlib import Path

    store, target, initial = enrolled
    states = []

    def concurrent_deactivation(*args):
        states.append(store.transition(target, expected=initial.generation, operation="b" * 32,
                                       action="deactivate"))
        raise ValueError("simulated runtime error")

    monkeypatch.setattr("tooluseproxy.integrations.codex.enabled_workspace_root",
                        concurrent_deactivation)
    monkeypatch.setattr("sys.stdin", io.TextIOWrapper(io.BytesIO(
        json.dumps({"cwd": target.workspace}).encode(),
    )))
    assert run_codex_hook("pre-tool-use", db_path=Path(target.data_dir) / "events.db") == 0
    assert states[0].phase == "deactivating"
    output = json.loads(capsys.readouterr().out)
    assert output["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert store.transition(target, expected=states[0].generation, operation="b" * 32,
                            action="deactivate").phase == "inactive"


def test_nested_repository_does_not_inherit_parent_deactivation(enrolled):
    from pathlib import Path
    from tooluseproxy.integrations.authority import workspace_authority_lease

    store, target, initial = enrolled
    store.transition(target, expected=initial.generation, operation="b" * 32,
                     action="deactivate")
    child = Path(target.workspace) / "nested"
    child.mkdir()
    database = Path(target.data_dir) / "events.db"
    with workspace_authority_lease(database, str(child)) as state:
        assert state.phase == "inactive"
    (child / ".git").mkdir()
    with workspace_authority_lease(database, str(child)) as state:
        assert state is None


@pytest.mark.parametrize("command,exit_code", [
    (["status"], 0),
    (["doctor"], 0),
    (["init"], 1),
    (["config", "show"], 1),
    (["protect", "scan"], 1),
    (["protect", "remove", "apply", "--path", "fixture.txt",
      "--removal-revision", "fixture", "--expected-manifest-sha256", "fixture"], 1),
    (["setup", "apply", "file-payload-exact", "--expect-empty-settings"], 1),
])
@pytest.mark.parametrize("draining", [False, True])
def test_stopped_cli_does_not_open_database_or_dispatch(
    enrolled, monkeypatch, capsys, command, exit_code, draining,
):
    from contextlib import ExitStack
    from pathlib import Path
    from tooluseproxy import cli

    store, target, initial = enrolled
    database = Path(target.data_dir) / "events.db"
    database.write_bytes(b"broken fixture database")

    def forbidden(*args, **kwargs):
        raise AssertionError("stopped CLI must not open database or dispatch")

    for handler in ("_run_status", "_run_doctor", "_run_init", "_run_config",
                    "_run_protect", "_run_setup"):
        monkeypatch.setattr(cli, handler, forbidden)
    monkeypatch.setattr("sqlite3.connect", forbidden)
    with ExitStack() as leases:
        if draining:
            leases.enter_context(store.lease(target))
        stopped = store.transition(target, expected=initial.generation,
                                   operation="b" * 32, action="deactivate")
        assert cli.main([*command, "--workspace", target.workspace,
                         "--data-dir", target.data_dir, "--json"]) == exit_code
        payload = json.loads(capsys.readouterr().out)
        assert payload["status"] == stopped.phase
        assert payload["database_opened"] is False
        assert payload["source_manifest_opened"] is False
        assert payload["configuration_state"] == "not_inspected"
        assert payload["code"] == ("administrator_drain_required" if draining
                                   else "administrator_reactivation_required")
    assert database.read_bytes() == b"broken fixture database"
    assert list(Path(target.workspace).iterdir()) == []


def test_cli_holds_lease_until_dispatch_finishes_and_reactivation_restores_dispatch(
    enrolled, monkeypatch, capsys,
):
    from tooluseproxy import cli

    store, target, initial = enrolled
    observed = []

    def dispatch(args):
        observed.append(store.transition(target, expected=initial.generation,
                                         operation="b" * 32, action="deactivate"))
        raise ValueError("fixture failure")

    monkeypatch.setattr(cli, "_run_init", dispatch)
    arguments = ["init", "--workspace", target.workspace, "--data-dir", target.data_dir]
    assert cli.main(arguments) == 1
    assert "fixture failure" in capsys.readouterr().err
    assert observed[0].phase == "deactivating"
    stopped = store.transition(target, expected=observed[0].generation,
                               operation="b" * 32, action="deactivate")
    assert stopped.phase == "inactive"
    store.transition(target, expected=stopped.generation, operation="c" * 32,
                     action="reactivate")
    monkeypatch.setattr(cli, "_run_init", lambda args: 17)
    assert cli.main(arguments) == 17


def test_externality_worker_skips_inactive_jobs_and_drains_active_provider_call(
    enrolled, monkeypatch,
):
    import sqlite3
    from pathlib import Path
    from types import SimpleNamespace
    from hook_monitor.runtime.externality_rules import (
        prepare_externality_hook_decision, process_externality_jobs,
    )
    from hook_monitor.runtime.parser import normalize_event
    from hook_monitor.runtime.storage import EventStore
    from hook_monitor.runtime.workspace import make_workspace_id

    store, target, initial = enrolled
    database = Path(target.data_dir) / "events.db"
    EventStore(database).initialize()
    other = Path(target.workspace).parent / "other"
    other.mkdir()
    other_target = Target(target.uid, str(other), target.data_dir)
    other_initial = store.transition(other_target, expected="absent", operation="c" * 32,
                                     action="enroll")
    for workspace in (Path(target.workspace), other):
        event = normalize_event("pre_tool_use", {
            "session_id": "fixture", "turn_id": "turn", "tool_use_id": "tool",
            "tool_name": "Bash", "cwd": str(workspace),
            "tool_input": {"command": "./opaque-agent"},
        }, workspace_root=str(workspace))
        with sqlite3.connect(database) as conn:
            conn.execute("INSERT INTO workspaces "
                         "(workspace_id, canonical_root, lexical_root, discovered_by) "
                         "VALUES (?, ?, ?, 'fixture')",
                         (make_workspace_id(str(workspace)), str(workspace), str(workspace)))
        assert prepare_externality_hook_decision(
            database, event, workspace_root=workspace,
        ).state == "queued"
    store.transition(target, expected=initial.generation, operation="b" * 32,
                     action="deactivate")
    with sqlite3.connect(database) as conn:
        conn.execute("UPDATE externality_classification_jobs SET created_at = '2000-01-01' "
                     "WHERE workspace_id = ?", (make_workspace_id(target.workspace),))
        before = conn.execute("SELECT * FROM externality_classification_jobs "
                              "WHERE workspace_id = ?",
                              (make_workspace_id(target.workspace),)).fetchone()
    observed = []

    def judge(envelope):
        observed.append(store.transition(other_target, expected=other_initial.generation,
                                         operation="d" * 32, action="deactivate"))
        raise RuntimeError("fixture provider failure")

    monkeypatch.setattr("hook_monitor.runtime.externality_rules.resolve_judge_configuration",
                        lambda _: SimpleNamespace(status="ready", failure_code=None,
                                                   chain=SimpleNamespace(judge=judge)))
    result = process_externality_jobs(database, environ={})
    assert result["processed"] == result["failed"] == 1
    assert observed[0].phase == "deactivating"
    assert store.transition(other_target, expected=observed[0].generation,
                            operation="d" * 32, action="deactivate").phase == "inactive"
    with sqlite3.connect(database) as conn:
        assert conn.execute("SELECT * FROM externality_classification_jobs "
                            "WHERE workspace_id = ?",
                            (make_workspace_id(target.workspace),)).fetchone() == before
    result = process_externality_jobs(database, environ={}, retry_failed=True)
    assert result["processed"] == 0
    assert result["network_used"] is False


@pytest.mark.parametrize("root", [None, "/wrong-fixture-root"])
def test_worker_requires_resolvable_registered_identity_when_authority_installed(enrolled, root):
    import sqlite3
    from pathlib import Path
    from hook_monitor.runtime.workspace import make_workspace_id
    from tooluseproxy.authority_state import AuthorityError
    from tooluseproxy.integrations.authority import registered_workspace_authority_lease

    _, target, _ = enrolled
    with sqlite3.connect(":memory:") as conn:
        conn.execute("CREATE TABLE workspaces (workspace_id TEXT, canonical_root TEXT)")
        identity = make_workspace_id(target.workspace)
        if root is not None:
            conn.execute("INSERT INTO workspaces VALUES (?, ?)", (identity, root))
        with pytest.raises(AuthorityError, match="authority_workspace_unresolved"):
            with registered_workspace_authority_lease(
                Path(target.data_dir) / "events.db", conn, identity,
            ):
                pytest.fail("unresolved target must not authorize provider work")


@pytest.mark.parametrize("projects", [
    None, [], [{"project": "project_1"}],
    [{"project": "project_1"}, {"project": "project_1"}],
    [{"project": "project_1"}, {"project": "project_2"}],
    [{"project": "project_1"}, {"project": "../invalid"}],
])
def test_pilot_does_not_authorize_missing_or_invalid_participant_bindings(enrolled, projects):
    import sqlite3
    from pathlib import Path
    from tooluseproxy.authority_state import AuthorityError
    from tooluseproxy.pilot_authority import comparison_authority_lease

    _, target, _ = enrolled
    with sqlite3.connect(":memory:") as conn:
        conn.execute("CREATE TABLE pilot_comparisons (comparison_id TEXT, report_json TEXT)")
        conn.execute("CREATE TABLE pilot_project_aliases (alias_number INTEGER, workspace_id TEXT)")
        conn.execute("INSERT INTO pilot_comparisons VALUES ('fixture', ?)",
                     (json.dumps({"projects": projects}),))
        with pytest.raises(AuthorityError, match="authority_comparison_unresolved"):
            with comparison_authority_lease(Path(target.data_dir) / "events.db", conn, "fixture"):
                pytest.fail("invalid participants must not authorize synchronization")
