from copy import deepcopy
import json

import pytest

from hook_monitor.evaluation.flow_forecast.labels import label_future
from hook_monitor.evaluation.flow_forecast.prefix import ForecastDataError, digest
from research.flow_forecast import task_world_collection, task_world_import, task_catalog, generator_strata
from test_flow_forecast_task_world_collection import lab as lab


@pytest.mark.parametrize('variant', ['public', 'include_private'])
def test_exact_task_completion_never_promotes_semantic_truth(lab, tmp_path, variant):
    output = tmp_path / 'capture'
    task_world_collection.run(tmp_path, 'inventory', variant, output)
    data, audit = task_world_import.read_capture(output)
    assert len(data.branches) == 8
    assert audit['generator_evidence'] is None
    assert {p.task_kind for p in data.prefixes} == {'inventory_allocation'}
    for branch in data.branches:
        label = label_future(branch, 4)
        assert label.protected_arrival == 'unknown'
        assert label.unknown_edges >= 1
        for edge in branch.transfers:
            if edge.relation in ('semantic', 'selection'):
                assert edge.evidence == 'unknown' and edge.evidence_digest is None


@pytest.mark.parametrize('part', ['receipt', 'observation', 'controls', 'completion', 'termination', 'charges'])
def test_rehashed_report_still_rejects_inconsistent_evidence(lab, tmp_path, part):
    output = tmp_path / 'capture'
    task_world_collection.run(tmp_path, 'calendar', 'public', output)
    _, audit = task_world_import.read_capture(output)
    report = deepcopy(audit['report'])
    row = report['conditions'][0]
    if part == 'receipt':
        row['steps'][0]['receipt']['receipt_count'] = 2
    elif part == 'observation':
        row['steps'][1]['observation']['information_flow_truth'] = 'known'
    elif part == 'controls':
        row['controls'][2]['process_started'] = 'yes'
    elif part == 'completion':
        row['task_achieved'] = False
    elif part == 'termination':
        row['termination'] = 'blocked'
    else:
        report['trial_charges'] = 1
    with pytest.raises(ForecastDataError):
        task_world_import.dataset_from_evidence(audit['intent'], audit['execution'], report)


def test_sealed_collection_groups_variants_without_invented_generators(lab, tmp_path):
    paths = []
    for name, variant in [('inventory', 'public'), ('inventory', 'include_private'), ('ledger', 'public')]:
        output = tmp_path / (name + '-' + variant)
        task_world_collection.run(tmp_path, name, variant, output)
        paths.append(str(output))
    source = tmp_path / 'paths.json'
    source.write_text(json.dumps(paths))
    output = tmp_path / 'collection'
    task_catalog.main(['--task-worlds', str(source), '--output', str(output)])
    data, catalog, audit = task_catalog.read_collection(output)
    assert audit['grouped_root_count'] == 2
    assert {p.task_kind for p in data.prefixes} == {'inventory_allocation', 'ledger_reconciliation'}
    assert audit['independence_verified'] is False and audit['prior_nonuse_verified'] is False
    assert digest(catalog) == audit['catalog_sha']
    strata = generator_strata.load(data, output, generator_strata.collection_identity(output))
    assert set(strata['group_labels'].values()) == {generator_strata.UNKNOWN}
    assert strata['summary']['validated_plan_receipts'] == 0


def test_saved_step_cannot_be_changed_independently(lab, tmp_path):
    output = tmp_path / 'capture'
    task_world_collection.run(tmp_path, 'ledger', 'public', output)
    (output / 'observe-step-2.json').write_text('{}')
    with pytest.raises(ForecastDataError, match='step_mismatch'):
        task_world_import.read_capture(output)
