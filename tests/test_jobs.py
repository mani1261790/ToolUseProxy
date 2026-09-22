import json
import sqlite3
from contextlib import contextmanager

from tooluseproxy.engine.jobs import claim, drain, enqueue, finish
from tooluseproxy.engine.journal import Journal, event_from
from tooluseproxy.engine.runtime import session_lock


def fixture(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    root = root.resolve()
    store = Journal(tmp_path / "events.db")
    store.initialize()
    workspace = store.register_workspace(str(root)).workspace_id
    event = None
    for phase in ("pre_tool_use", "post_tool_use"):
        event = event_from(
            phase,
            dict(
                cwd=str(root), session_id="s", tool_use_id="one", tool_name="fixture", tool_input={}
            ),
            str(root),
        )
        store.record(event)
    (tmp_path / "semantic-flow.json").write_text(
        json.dumps(
            {
                "workspaces": {
                    workspace: dict(
                        provider="codex_exec",
                        send_recorded_content=True,
                        mode="enforce",
                        failure_policy="allow_with_warning",
                        background_provenance=True,
                    )
                }
            }
        )
    )
    return root, store, event


@contextmanager
def no_authority(*_):
    yield None


def test_expired_lease_recovery_and_owner_fencing(tmp_path):
    _, store, event = fixture(tmp_path)
    enqueue(store.db_path, event, "codex_default")
    enqueue(store.db_path, event, "codex_default")
    first = claim(store.db_path, event.workspace_id, now=0)
    assert claim(store.db_path, event.workspace_id, now=1) is None
    second = claim(store.db_path, event.workspace_id, now=601)
    assert second["owner"] != first["owner"]
    assert not finish(store.db_path, first, "done")
    assert finish(store.db_path, second, "done")
    assert claim(store.db_path, event.workspace_id, now=1202) is None


def test_worker_judges_outside_write_transaction_and_respects_activation(tmp_path, monkeypatch):
    root, store, event = fixture(tmp_path)
    enqueue(store.db_path, event, "codex_default")
    monkeypatch.setattr(
        "tooluseproxy.integrations.activation.enabled_workspace_root", lambda *_: str(root)
    )
    calls = []

    def provider(_):
        with sqlite3.connect(store.db_path, timeout=0.1) as conn:
            conn.execute("BEGIN IMMEDIATE")
        calls.append(True)
        return dict(
            externality="local", complete=True, reason="fixture", accesses=[], dependencies=[]
        )

    assert (
        drain(store.db_path, event.workspace_id, provider=provider, lease_factory=no_authority) == 1
    )
    assert calls == [True]
    with sqlite3.connect(store.db_path) as conn:
        assert conn.execute("SELECT status FROM flow_jobs").fetchone()[0] == "done"


def test_inactive_authority_does_not_invoke_model(tmp_path, monkeypatch):
    from types import SimpleNamespace

    root, store, event = fixture(tmp_path)
    enqueue(store.db_path, event, "codex_default")
    monkeypatch.setattr(
        "tooluseproxy.integrations.activation.enabled_workspace_root", lambda *_: str(root)
    )

    @contextmanager
    def inactive(*_):
        yield SimpleNamespace(phase="inactive")

    assert (
        drain(store.db_path, event.workspace_id, provider=lambda _: 1 / 0, lease_factory=inactive)
        == 0
    )
    with sqlite3.connect(store.db_path) as conn:
        assert conn.execute("SELECT status FROM flow_jobs").fetchone()[0] == "paused"


def test_foreground_session_wins_over_background(tmp_path, monkeypatch):
    root, store, event = fixture(tmp_path)
    enqueue(store.db_path, event, "codex_default")
    monkeypatch.setattr(
        "tooluseproxy.integrations.activation.enabled_workspace_root", lambda *_: str(root)
    )
    with session_lock(store.db_path, event.workspace_id, event.session_id):
        assert (
            drain(
                store.db_path,
                event.workspace_id,
                provider=lambda _: 1 / 0,
                lease_factory=no_authority,
            )
            == 0
        )
    with sqlite3.connect(store.db_path) as conn:
        assert conn.execute("SELECT status,attempts FROM flow_jobs").fetchone() == ("pending", 0)


def test_repeated_crash_does_not_leave_permanent_running_state(tmp_path):
    _, store, event = fixture(tmp_path)
    enqueue(store.db_path, event, "codex_default")
    for now in (0, 601, 1202):
        assert claim(store.db_path, event.workspace_id, now=now)
    assert claim(store.db_path, event.workspace_id, now=1803) is None
    with sqlite3.connect(store.db_path) as conn:
        assert conn.execute("SELECT status FROM flow_jobs").fetchone()[0] == "failed"
