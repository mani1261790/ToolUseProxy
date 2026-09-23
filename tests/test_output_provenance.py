import json
import sqlite3

import pytest

from tooluseproxy.engine.graph import GraphUnavailable
from tooluseproxy.engine.journal import Journal, event_from
from tooluseproxy.engine.property_graph import analyze_properties
from tooluseproxy.engine.requirements import inspect


def fixture(tmp_path, output):
    root = tmp_path / 'workspace'
    root.mkdir()
    db = tmp_path / 'events.db'
    store = Journal(db)
    store.initialize()
    for call, phase in [('producer', 'post_tool_use'), ('consumer', 'pre_tool_use')]:
        event = event_from(phase, dict(cwd=str(root), session_id='s', tool_use_id=call,
            tool_name='arbitrary-tool', tool_input={'call': call}, tool_response=output), str(root))
        store.record(event, [])
    return root, db, event


def verdict(*, complete=True, deps=(), accesses=(), **extra):
    return dict(externality='external', complete=complete, reason='fixture',
                dependencies=list(deps), accesses=list(accesses), **extra)


def test_selected_output_has_own_revision_and_preserves_incomplete_operation(tmp_path):
    root, db, event = fixture(tmp_path, {'address': 'generated-value-123', 'other': 'opaque'})
    def judge(records):
        node = records['current_call']
        if node.get('required_output'):
            assert node['required_output']['text'] == 'generated-value-123'
            return verdict()  # fixture evidence: this output is independently generated
        if node['input']['call'] == 'producer':
            return verdict(complete=False)
        return verdict(deps=[dict(node_id=records['previous_calls'][0]['node_id'],
                                   reason='uses generated value', selection={'text': 'generated-value-123'})])
    with sqlite3.connect(db) as conn:
        producer_event = conn.execute("select event_id from events where tool_use_id='producer'").fetchone()[0]
    analyze_properties(db, event.workspace_id, 's', producer_event, [], judge)
    result = analyze_properties(db, event.workspace_id, 's', event.event_id, [], judge)
    assert result['action'] == 'allow'
    with sqlite3.connect(db) as conn:
        assert conn.execute('select count(*) from graph_output_selections').fetchone()[0] == 1
        whole = conn.execute('select r.verdict from graph_heads h join graph_revisions r on r.revision=h.revision where r.event != ?', (event.event_id,)).fetchone()
        assert json.loads(whole[0])['complete'] is False


@pytest.mark.parametrize('selected_access', [True, False])
def test_selection_never_means_public_or_complete(tmp_path, selected_access):
    root, db, event = fixture(tmp_path, 'derived-private-value')
    def judge(records):
        if records['current_call'].get('required_output'):
            return verdict(complete=selected_access, accesses=[{'path':'private.txt','mode':'read','reason':'derives selected bytes'}] if selected_access else [])
        if not records['previous_calls']:
            return verdict(complete=False)
        return verdict(deps=[dict(node_id=records['previous_calls'][0]['node_id'], reason='derived', selection={'text':'derived-private-value'})])
    result = analyze_properties(db, event.workspace_id, 's', event.event_id,
        [{'node_id':'source:p','path':'private.txt'}], judge)
    assert result['action'] == ('block' if selected_access else 'unavailable')


@pytest.mark.parametrize('text', ['absent', 'repeat'])
def test_selection_must_identify_one_actual_observation(tmp_path, text):
    root, db, event = fixture(tmp_path, 'repeat repeat')
    def judge(records):
        return verdict(deps=[dict(node_id=records['previous_calls'][0]['node_id'], reason='test', selection={'text':text})] if records['previous_calls'] else [])
    with pytest.raises(GraphUnavailable, match='selection_missing_or_ambiguous'):
        analyze_properties(db, event.workspace_id, 's', event.event_id, [], judge)


def test_requirement_acquisition_adds_real_evidence_before_retry(tmp_path):
    (tmp_path/'transform.py').write_text('value = 42\n')
    records={'current_call':{'workspace_root':str(tmp_path),'input':{'command':'python transform.py'}},'previous_calls':[]}
    seen=[]
    def judge(context):
        seen.append(context)
        if context.get('execution_definitions'):
            assert context['execution_definitions'][0]['content']=='value = 42\n'
            return verdict()
        return verdict(complete=False,evidence_requests=[{'path':'transform.py','reason':'resolve calculation'}])
    result=inspect(records,judge,lambda x,c:x,set())
    assert result['complete'] and len(seen)==2
    assert result['evidence_receipts'][0]['sha256']
    assert 'content' not in result['evidence_receipts'][0]


def test_unobtainable_requirement_stops_without_identical_model_retries(tmp_path):
    seen=[]
    def judge(records):
        seen.append(records)
        return verdict(complete=False,evidence_requests=[{'path':'../outside','reason':'missing code'}])
    result=inspect({'current_call':{'workspace_root':str(tmp_path),'input':{}},'previous_calls':[]},judge,lambda x,c:x,set())
    assert not result['complete'] and len(seen)==2
    assert result['evidence_receipts'][0]['status']=='unavailable'
    assert 'content' not in result['evidence_receipts'][0]


def test_cached_definition_is_invalidated_by_content_change(tmp_path):
    from tooluseproxy.engine.requirements import reusable
    path=tmp_path/'code.py'
    path.write_text('answer = 1\n')
    node={'workspace_root':str(tmp_path),'input':{}}
    def judge(records):
        return verdict() if records.get('execution_definitions') else verdict(complete=False,evidence_requests=[{'path':'code.py','reason':'value origin'}])
    result=inspect({'current_call':node,'previous_calls':[]},judge,lambda x,c:x,set())
    assert reusable(result,node)
    path.write_text('answer = secret\n')
    assert not reusable(result,node)


def test_historical_definition_mismatch_is_not_substituted(tmp_path):
    from tooluseproxy.engine.requirements import acquire
    (tmp_path/'code.py').write_text('new code\n')
    node={'workspace_root':str(tmp_path),'input':{},'definition_observations':{str(tmp_path/'code.py'):'old-hash'}}
    result=acquire({'current_call':node},[{'path':'code.py','reason':'historical origin'}])
    assert result[0]['status']=='unavailable' and 'content' not in result[0]


def test_forbidden_and_symlink_resources_are_never_read(tmp_path):
    from tooluseproxy.engine.requirements import acquire
    outside=tmp_path.parent/'outside-code'
    outside.write_text('must not be read')
    (tmp_path/'link.py').symlink_to(outside)
    (tmp_path/'protected_sources.json').write_text('must not be read')
    result=acquire({'current_call':{'workspace_root':str(tmp_path),'input':{}}},[{'path':p,'reason':'test'} for p in ('link.py','protected_sources.json')])
    assert all(r['status']=='unavailable' and 'content' not in r for r in result)


def test_catalog_is_metadata_only_and_excludes_control_file(tmp_path):
    from tooluseproxy.engine.requirements import observe_managed_resources
    (tmp_path/'state.json').write_text('secret content is not emitted')
    (tmp_path/'protected_sources.json').write_text('must not be read')
    data=observe_managed_resources(tmp_path)
    assert data['complete']
    assert [PathName['path'].rsplit('/',1)[-1] for PathName in data['entries']]==['state.json']
    assert 'secret content' not in json.dumps(data)
    assert not observe_managed_resources(tmp_path,limit=0)['complete']


def test_invalid_model_shape_receives_feedback_without_infinite_retry(tmp_path):
    from tooluseproxy.engine.property_graph import validate
    seen=[]
    def judge(records):
        seen.append(dict(records))
        if len(seen)==1:
            return verdict(accesses=[{'path':'https://example.invalid/','mode':'read','reason':'invalid filesystem resource'}])
        assert records['validation_feedback']['error']=='invalid_access'
        return verdict()
    result=inspect({'current_call':{'workspace_root':str(tmp_path),'input':{}},'previous_calls':[]},judge,validate,set())
    assert result['complete'] and len(seen)==2
