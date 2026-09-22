import json
import sqlite3
from dataclasses import asdict

import pytest

from tooluseproxy.engine.dlp import inspect_dlp
from tooluseproxy.engine.evidence import EvidenceStore
from tooluseproxy.engine.inspection import inspect_and_decide
from tooluseproxy.engine.journal import Journal, Source, event_from
from tooluseproxy.engine.payload import PayloadResolver
from tooluseproxy.engine.runtime import process_hook

SECRET = "Synthetic confidential material: calibration coefficient is 0.73, deployment date is Fictionday."


@pytest.fixture
def context(tmp_path, monkeypatch):
    root = tmp_path / "root"
    root.mkdir()
    root = root.resolve()
    (root / "private").write_text(SECRET)
    store = Journal(tmp_path / "events.db")
    store.initialize()

    def create(body=SECRET, session="one", call="send"):
        event = event_from(
            "pre_tool_use",
            dict(
                cwd=str(root),
                session_id=session,
                tool_use_id=call,
                tool_name="generic",
                tool_input={"body": body},
            ),
            str(root),
        )
        store.record(event)
        return event, PayloadResolver(
            EvidenceStore(store.db_path), event.workspace_id, event.event_id, root
        )

    event, resolver = create()
    source = Source("private", "private", "file", "secret", (), event.workspace_id, "private", None)
    monkeypatch.setattr(store, "list_protected_sources_for_workspace", lambda _: [source])
    return root, store, create, dict(asdict(source), node_id="source:private")


def target(_):
    return dict(
        complete=True,
        reason="body",
        targets=[
            dict(
                kind="inline",
                pointer="/tool_input/body",
                path=None,
                offset=0,
                length=None,
                reason="body",
            )
        ],
    )


def detail(_):
    return dict(
        externality="external", complete=True, reason="fixture", dependencies=[], accesses=[]
    )


def test_copy_detected_across_sessions_and_index_reused(context):
    _, _, create, source = context
    for session in ("one", "two"):
        _, resolver = create("prefix " + SECRET + " suffix", session)
        resolution = resolver.resolve(dict(kind="inline", pointer="/tool_input/body"))
        result = inspect_dlp(resolver, resolution, [source])
        assert result.matches and result.matches[0]["source_id"] == "private"
        assert result.reused_sources == (0 if session == "one" else 1)
    with sqlite3.connect(resolver.store.path) as conn:
        for row in conn.execute("SELECT signature FROM flow_dlp_spans"):
            assert SECRET not in row[0]


def test_registration_removed_and_content_replaced_invalidate_matches(context):
    root, _, create, source = context
    _, resolver = create()
    resolution = resolver.resolve(dict(kind="inline", pointer="/tool_input/body"))
    assert inspect_dlp(resolver, resolution, [source]).matches
    assert not inspect_dlp(resolver, resolution, []).matches
    (root / "private").write_text(
        "Completely different synthetic confidential configuration now applies."
    )
    assert not inspect_dlp(resolver, resolution, [source]).matches


def test_local_only_input_and_unselected_range_are_not_matched(context):
    _, _, create, source = context
    _, resolver = create(SECRET + "public")
    resolution = resolver.resolve(
        dict(kind="inline", pointer="/tool_input/body", offset=len(SECRET.encode()), length=6)
    )
    assert not inspect_dlp(resolver, resolution, [source]).matches


def test_common_short_literal_cannot_trigger_automatic_block(context):
    root, _, create, source = context
    (root / "private").write_text("hello")
    _, resolver = create("hello there")
    result = inspect_dlp(
        resolver, resolver.resolve(dict(kind="inline", pointer="/tool_input/body")), [source]
    )
    assert not result.matches and result.limitations


def test_dlp_positive_does_not_need_a_graph_path(context):
    _, store, create, source = context
    event, _ = create()

    def no_graph():
        pytest.fail("exact positive requires no speculative provenance")

    result = inspect_and_decide(store, event, [source], target, no_graph, "node", "fixture")
    assert result["action"] == "block" and result["reason"] == "protected_content_match"
    assert result["path"] == []


def test_dlp_negative_still_runs_graph_and_graph_block_survives_inspection_failure(context):
    _, store, create, source = context
    event, _ = create("independent public message")
    called = []

    def graph():
        called.append(True)
        return dict(
            action="block",
            reason="protected_source_reachable",
            path=["source:private", "node"],
            node_id="node",
        )

    assert (
        inspect_and_decide(store, event, [source], target, graph, "node", "fixture")["action"]
        == "block"
    )
    assert (
        inspect_and_decide(store, event, [source], lambda _: {}, graph, "node", "fixture")["action"]
        == "block"
    )
    assert len(called) == 2


def test_hook_blocks_exact_send_but_not_local_processing(context):
    _, store, create, _ = context
    event, _ = create()
    (store.db_path.parent / "semantic-flow.json").write_text(
        json.dumps(
            {
                "workspaces": {
                    event.workspace_id: dict(
                        provider="codex_exec",
                        send_recorded_content=True,
                        failure_policy="allow_with_warning",
                        mode="enforce",
                    )
                }
            }
        )
    )
    local = process_hook(
        store,
        event,
        judge=detail,
        target_judge=target,
        screening_judge=lambda _: dict(externality="local", complete=True, reason="fixture"),
    )
    assert local == {}
    event2, _ = create(session="two")
    blocked = process_hook(
        store,
        event2,
        judge=detail,
        target_judge=target,
        screening_judge=lambda _: dict(externality="external", complete=True, reason="fixture"),
    )
    assert blocked["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "一致" in blocked["hookSpecificOutput"]["permissionDecisionReason"]


def test_protection_change_during_graph_cannot_return_verified_allow(context):
    root, store, create, source = context
    event, _ = create("public independent body")

    def graph():
        (root / "private").write_text("Changed protected data while model was being queried.")
        return dict(action="allow", reason="no_protected_path_observed", path=[], node_id="node")

    result = inspect_and_decide(store, event, [source], target, graph, "node", "fixture")
    assert result["action"] == "unavailable"
    assert result["reason"] == "protected_content_changed_during_inspection"
