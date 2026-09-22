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
