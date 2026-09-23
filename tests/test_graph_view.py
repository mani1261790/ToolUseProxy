import sqlite3

from tooluseproxy.log_viewer import LogReader
from test_lineage import make_history, inspect


def test_graph_uses_pinned_cross_session_ancestry_without_payload(tmp_path):
    _, store, record, _ = make_history(tmp_path)
    send = record('b', 'send', 'pre_tool_use', 'send', [{'path':'derived','mode':'read'}])
    inspect(store, send)
    reader = LogReader(store.db_path, send.workspace_id)
    graph = reader.graph(send.event_id)
    assert len(graph['nodes']) == 3
    assert len(graph['edges']) == 2
    assert any(a['protected'] for n in graph['nodes'] for a in n['accesses'])
    assert {n['session'] for n in graph['nodes']} == {'a','b'}
    assert '0.73' not in str(graph)
    assert all('input' not in n and 'output' not in n for n in graph['nodes'])
    assert LogReader(store.db_path, 'different').graph(send.event_id)['nodes'] == []
    with sqlite3.connect(store.db_path) as conn:
        conn.execute('DELETE FROM graph_heads')
    assert reader.graph(send.event_id)['nodes'] == graph['nodes']


def test_unanalysed_is_not_safe_and_read_only(tmp_path):
    _, store, record, _ = make_history(tmp_path)
    event = record('b','new','pre_tool_use','other')
    before = store.db_path.read_bytes()
    assert LogReader(store.db_path).graph(event.event_id)['state'] == 'not_analyzed'
    assert store.db_path.read_bytes() == before


def test_pending_and_recovered_judgment_is_scoped_and_distinct_from_execution(tmp_path):
    from tooluseproxy.engine.pending import decide
    _, store, record, _ = make_history(tmp_path)
    event = record('b','waiting','pre_tool_use','other')
    decide(store.db_path, event, lambda _: {'action':'unavailable','reason':'offline'}, sleep=lambda _:None)
    reader = LogReader(store.db_path, event.workspace_id)
    judgment = reader.graph(event.event_id)['judgments'][0]
    assert judgment['state'] == 'waiting' and judgment['held'] == 1
    assert reader.detail(event.event_id)['judgments'][0]['state'] == 'waiting'
    assert not LogReader(store.db_path, 'different').graph(event.event_id).get('judgments')
    decide(store.db_path, event, lambda _: {'action':'allow','reason':'recovered'})
    judgment = reader.graph(event.event_id)['judgments'][0]
    assert judgment['state'] == 'complete' and judgment['held'] == 1
    assert len(reader.detail(event.event_id)['events']) == 1
