import pytest
from test_lineage import make_history, judge

from tooluseproxy.engine.evidence import EvidenceStore
from tooluseproxy.engine.fast_path import known_protected_generation
from tooluseproxy.engine.payload import PayloadResolver
from tooluseproxy.engine.property_graph import analyze_properties


@pytest.fixture
def generation_history(tmp_path):
    return make_history(tmp_path)


def prepare(data):
    root, store, record, writer = data
    sources = [dict(node_id="source:private", source_id="private", path="private")]
    analyze_properties(
        store.db_path, writer.workspace_id, writer.session_id, writer.event_id, sources, judge
    )
    return root, store, record, sources


def test_positive_generation_does_not_reload_long_history(generation_history, monkeypatch):
    root, store, record, sources = prepare(generation_history)
    # Exceed the old raw history event/byte limits without analyzing irrelevant entries.
    for index in range(520):
        record("b", f"noise-{index}", "pre_tool_use", "x" * 600)
    event = record("b", "send", "pre_tool_use", "send", [{"path": "derived", "mode": "read"}])
    resolver = PayloadResolver(
        EvidenceStore(store.db_path), event.workspace_id, event.event_id, root
    )
    resolution = resolver.resolve(dict(kind="file", path="derived", offset=0, length=None))
    resolver.persist(dict(kind="file", path="derived", offset=0, length=None), {}, resolution)
    monkeypatch.setattr(
        "tooluseproxy.engine.property_graph.load_calls",
        lambda *args: pytest.fail("must not replay history"),
    )
    result = known_protected_generation(
        store, event, resolver, resolution, sources, "codex_default"
    )
    assert result["action"] == "block" and len(result["path"]) == 4


def test_candidate_miss_and_model_change_never_allow(generation_history):
    root, store, record, sources = prepare(generation_history)
    event = record("b", "send", "pre_tool_use", "send", [{"path": "derived", "mode": "read"}])
    resolver = PayloadResolver(
        EvidenceStore(store.db_path), event.workspace_id, event.event_id, root
    )
    resolution = resolver.resolve(dict(kind="file", path="derived", offset=0, length=None))
    assert (
        known_protected_generation(store, event, resolver, resolution, [], "codex_default") is None
    )
    assert (
        known_protected_generation(store, event, resolver, resolution, sources, "different-model")
        is None
    )
    (root / "derived").write_text("replacement")
    assert (
        known_protected_generation(store, event, resolver, resolution, sources, "codex_default")
        is None
    )
