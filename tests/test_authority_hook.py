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
