from copy import deepcopy
import hashlib
import importlib
import json

import pytest

from hook_monitor.evaluation.flow_forecast.prefix import ForecastDataError, canonical
from research.flow_forecast import api_task_strata as api, task_catalog, compare


def collection(tmp_path, monkeypatch, family='message', checked=False):
    fixture = importlib.import_module('test_flow_forecast_bfcl_' + family + '_import')
    sha = hashlib.sha256(fixture.SOURCE.encode()).hexdigest()
    for name in ('bfcl_' + family + '_import', 'bfcl_' + family + '_reference',
                 'bfcl_' + family + '_transport', 'checked_' + family):
        monkeypatch.setattr(importlib.import_module('research.flow_forecast.' + name), 'SOURCE_SHA', sha)
    source = tmp_path / 'source.py'
    source.write_text(fixture.SOURCE)
    paths = []
    for n, variant in enumerate(('public', 'include_private'), 1):
        path = tmp_path / variant
        fixture.capture(path, variant, str(n + 3) * 32)
        paths.append(path)
    if checked:
        checker = importlib.import_module('research.flow_forecast.checked_' + family)
        importer = importlib.import_module('research.flow_forecast.bfcl_' + family + '_import')
        def binding(path, *args):
            _, audit = importer.read_capture(path, fixture.SOURCE)
            return {'capture_root':audit['intent']['root'], 'capture_report_sha':api.digest(audit['report']),
                    'source_sha':sha, 'semantic_truth_promoted':False}
        monkeypatch.setattr(checker, 'bind_capture', binding)
        entries = [{'capture':str(p), 'interventions':'fixture'} for p in paths]
    else:
        entries = list(map(str, paths))
    inputs = tmp_path / 'inputs.json'
    inputs.write_text(json.dumps(entries))
    directory = tmp_path / 'collection'
    flag = '--' + ('checked-' if checked else '') + family + '-captures'
    task_catalog.main([flag, str(inputs), '--' + family + '-source', str(source), '--output', str(directory)])
    return directory, task_catalog.read_collection(directory)


@pytest.mark.parametrize('family', ['message','ticket'])
@pytest.mark.parametrize('checked', [False, True])
def test_source_bound_strata_preserve_prefix_and_censored_dispatch(tmp_path, monkeypatch, family, checked):
    directory, (data, _, _) = collection(tmp_path, monkeypatch, family, checked)
    before = [canonical(p.model_input()) for p in data.prefixes]
    result = api.load(data, directory, api.collection_identity(directory))
    assert before == [canonical(p.model_input()) for p in data.prefixes]
    assert result['summary']['independence_verified'] is False
    for branch in data.branches:
        labels = result['branch_labels'][api.branch_key(branch)]
        assert 'task-api/bfcl-' + family in labels
        sent = 'tool-api/mcp__lab__send_message' in labels
        assert sent == (branch.termination == 'completed')


@pytest.mark.parametrize('changed', ['call', 'design', 'source', 'proof', 'duplicate'])
def test_rehashed_but_inconsistent_evidence_is_rejected(tmp_path, monkeypatch, changed):
    directory, (data, catalog, audit) = collection(tmp_path, monkeypatch, checked=True)
    audit = deepcopy(audit)
    item = audit['message_captures'][0]
    if changed == 'call':
        item['report']['conditions'][0]['steps'][0]['call']['name'] = 'mcp__other__login'
    elif changed == 'design':
        audit['bindings'][0]['design_id'] = 'renamed-task'
    elif changed == 'source':
        item['source_text'] += '# changed'
    elif changed == 'proof':
        item['closed_message_projection_evidence']['query'] = 'different semantics'
    else:
        audit['message_captures'].append(deepcopy(item))
    monkeypatch.setattr(api, 'read_collection', lambda *a:(data, catalog, audit))
    with pytest.raises(ForecastDataError):
        api.load(data, directory, api.collection_identity(directory))


def test_legacy_without_original_source_does_not_gain_verified_api_labels(tmp_path, monkeypatch):
    directory, (data, catalog, audit) = collection(tmp_path, monkeypatch)
    for item in audit['message_captures']:
        item.pop('source_text')
    monkeypatch.setattr(api, 'read_collection', lambda *a:(data, catalog, audit))
    result = api.load(data, directory, api.collection_identity(directory))
    assert not result['branch_labels']
    assert sum(p['roots_without_evidence'] for p in result['summary']['partitions'].values()) == 2


def test_comparison_scores_api_strata_with_frozen_thresholds(tmp_path, monkeypatch):
    directory, _ = collection(tmp_path, monkeypatch, checked=True)
    plan, report = tmp_path / 'plan.json', tmp_path / 'report.json'
    common = ['--dataset',str(directory / 'dataset'),'--collection',str(directory)]
    compare.main(['prepare',*common,'--output',str(plan)])
    compare.main(['evaluate',*common,'--plan',str(plan),'--partition','train','--output',str(report)])
    result = json.loads(report.read_text())
    assert result['acceptance']['status'] == 'inconclusive_do_not_adopt'
    for model in result['models'].values():
        section = model['observe/4']
        strata = section['strata']['task-api/bfcl-message']
        assert strata['probability']['row_count'] > 0
        assert strata['operating_points']['0.01']['threshold'] == section['operating_points']['0.01']['threshold']
