"""Synthetic receipts exercise wiring; they are not provider attestations."""
from copy import deepcopy
from dataclasses import replace
import json
import uuid

import pytest

from hook_monitor.evaluation.flow_forecast.dataset import assemble
from hook_monitor.evaluation.flow_forecast.prefix import ForecastDataError
from hook_monitor.evaluation.flow_lab.agent import Proposal
from hook_monitor.evaluation.flow_lab.generation_evidence import capture
from research.flow_forecast import generator_strata as gs
from research.flow_forecast import compare, compare_holdout
from research.flow_forecast.experiment import build_models, evaluate, freeze_plan
from research.flow_forecast.holdout import HoldoutLedger
from test_flow_forecast_baselines import dataset
from test_flow_forecast_partition_bundle import bundle


def seal_only(tmp_path):
    path = tmp_path / 'collection'
    path.mkdir()
    (path / 'collection.json').write_text(json.dumps({
        'schema': 1, 'dataset_digest': 'a' * 64, 'catalog_sha': 'b' * 64,
        'evidence_sha': 'c' * 64, 'origin_shas': ['d' * 64]}))
    return path


def evidence(data, model_by_root=None):
    result = []
    for index, root in enumerate(sorted({p.root_case_id for p in data.prefixes})):
        requested = model_by_root[root] if model_by_root is not None else f'fixture-model-{index}'
        records = []
        for branch_id in sorted({b.branch_id for b in data.branches if b.prefix.root_case_id == root}):
            action = {'source': 'public', 'encoding': 'plain'}
            proposal = Proposal.parse({'status': 'propose', 'actions': [action]})
            receipt = capture(events=b'{"type":"turn.completed"}', prompt=b'fixture', proposal=proposal,
                              model=requested, cli_version='codex-cli 0.153.4',
                              call_id=uuid.uuid4().hex, elapsed_ms=1)
            records.append({'branch_id': branch_id, 'attempt_id': uuid.uuid4().hex,
                            'action': action, 'generation': receipt})
        result.append({'run_id': root, 'import_evidence': {
            'run': {'run_id': root}, 'generator': {'requested_model': requested}, 'records': records}})
    return {'assigned_searches': result}


def test_aliases_are_descriptive_and_related_roots_are_not_split(tmp_path, monkeypatch):
    data = dataset()
    roots = sorted({p.root_case_id for p in data.prefixes})
    data = assemble(data.branches, related_roots=((roots[0], roots[1]),))
    audit = evidence(data)
    path = seal_only(tmp_path)
    monkeypatch.setattr(gs, 'read_collection', lambda _: (data, {}, audit))
    result = gs.load(data, path, gs.collection_identity(path))
    assert set(result['group_labels'].values()) == {gs.MIXED}
    assert result['summary']['groups_with_mixed_requested_models'] == 1
    assert result['summary']['resolved_model_versions_verified'] is False
    assert result['summary']['evaluated'] is False
    assert all(not names for names in result['summary']['requested_models_by_partition'].values())
    observed = result['summary']['observed_requested_models_by_partition']
    assert {name for names in observed.values() for name in names} == {'fixture-model-0', 'fixture-model-1'}
    audit['assigned_searches'].pop()
    assert set(gs.load(data, path, gs.collection_identity(path))['group_labels'].values()) == {gs.UNKNOWN}


@pytest.mark.parametrize('change', ['alias', 'duplicate_branch', 'reuse_call', 'mixed_receipt', 'dataset', 'seal'])
def test_mismatched_or_reused_evidence_fails_closed(tmp_path, monkeypatch, change):
    data = dataset()
    audit = evidence(data)
    path = seal_only(tmp_path)
    identity = gs.collection_identity(path)
    rows = audit['assigned_searches'][0]['import_evidence']['records']
    if change == 'alias':
        rows[0]['generation']['requested_model'] = 'different'
    elif change == 'duplicate_branch':
        rows.append(deepcopy(rows[0]))
    elif change == 'reuse_call':
        rows[1]['generation']['call_id'] = rows[0]['generation']['call_id']
    elif change == 'mixed_receipt':
        rows[0]['generation'] = None
        rows[1]['attempt_id'] = rows[0]['attempt_id']
    elif change == 'seal':
        identity = '0' * 64
    other = replace(data, provenance='synthetic-flow-lab-v1') if change == 'dataset' else data
    monkeypatch.setattr(gs, 'read_collection', lambda _: (other, {}, audit))
    with pytest.raises(ForecastDataError):
        gs.load(data, path, identity)


def test_strata_use_frozen_global_thresholds_and_do_not_certify_model_versions():
    data = dataset()
    models, costs = build_models(data)
    plan = freeze_plan(data, models)
    labels = {group: gs.PREFIX + 'fixture' for _, group, _ in data.split.assignments}
    report = evaluate(data, models, plan, partition='train', generator_groups=labels)
    for name, conditions in report['models'].items():
        for key, condition in conditions.items():
            stratum = condition['strata'][gs.PREFIX + 'fixture']
            assert stratum['probability'] == condition['probability']
            assert stratum['operating_points'] == condition['operating_points']
            for target, point in stratum['operating_points'].items():
                assert point['threshold'] == plan['models'][name]['conditions'][key]['thresholds'][target]['threshold']
    compare.attach_assessment(report, data, models, costs, {'peak_process_memory_bytes': 1}, plan,
                              generator_evidence={'summary': {'evaluated': False,
                                                              'resolved_model_versions_verified': False}})
    summary = report['generalization']['agent_models']
    assert summary['scored_requested_aliases'] == ['fixture']
    assert summary['evaluated'] is False
    assert 'different_agent_models_evaluated' in report['acceptance']['missing_or_insufficient']


def test_holdout_prepares_with_only_seal_and_reserves_before_provenance_read(tmp_path, monkeypatch):
    directory, manifest = bundle(tmp_path)
    collection = seal_only(tmp_path)
    plan = compare_holdout.prepare(directory, collection=collection)
    ledger = HoldoutLedger.create(tmp_path / 'ledger.db')
    seal = manifest['partitions']['test']
    ledger.seal(**seal)
    with pytest.raises(ForecastDataError, match='plan_mismatch'):
        compare_holdout.evaluate_once(directory, plan, ledger)
    assert ledger.status(seal['dataset_sha'])['state'] == 'sealed'

    def fail_after_open(*args, **kwargs):
        assert ledger.status(seal['dataset_sha'])['state'] == 'opened'
        raise ForecastDataError('invalid_source_evidence')

    monkeypatch.setattr(gs, 'load', fail_after_open)
    with pytest.raises(ForecastDataError, match='invalid_source_evidence'):
        compare_holdout.evaluate_once(directory, plan, ledger, collection=collection)
    with pytest.raises(ForecastDataError, match='already_consumed'):
        compare_holdout.evaluate_once(directory, plan, ledger, collection=collection)


def test_collected_receipts_reach_cli_without_promoting_adaptive_samples(tmp_path):
    from hook_monitor.evaluation.flow_lab.budget import Budget
    from hook_monitor.evaluation.flow_lab.controller import run_search
    from hook_monitor.evaluation.flow_lab.models import RunSpec, utc_now
    from hook_monitor.evaluation.flow_lab.search_state import SearchJournal
    from hook_monitor.evaluation.flow_lab.storage import TrialStore
    from research.flow_forecast.task_catalog import main as collect_main, read_collection
    from test_flow_forecast_import import Provider, Transport
    from test_flow_lab_task_assignment import binding

    class Recorded(Provider):
        def propose(self, *args, **kwargs):
            value = super().propose(*args, **kwargs)
            self.last_evidence = capture(
                events=b'{"type":"turn.completed"}', prompt=b'fixture', proposal=Proposal.parse(value),
                model=self.model_id, cli_version='codex-cli 0.153.4', call_id=uuid.uuid4().hex, elapsed_ms=1)
            return value

    search = tmp_path / 'search'
    spec = RunSpec(uuid.uuid4().hex, 'adaptive-v1', 'source-test', 'policy-test',
                   'a' * 64, utc_now(), mode='adaptive_search')
    with SearchJournal(search) as journal, TrialStore(search / 'trials') as store:
        assert run_search(journal, store, spec, Transport(), Recorded(), Budget(),
                          task_assignment=binding())['status'] == 'completed'
    sources = tmp_path / 'sources.json'
    sources.write_text(json.dumps([str(search)]))
    collection = tmp_path / 'collection'
    collect_main(['--assigned-searches', str(sources), '--output', str(collection)])
    data = read_collection(collection)[0]
    proof = gs.load(data, collection, gs.collection_identity(collection))
    assert proof['summary']['validated_plan_receipts'] == 1
    assert set(proof['group_labels'].values()) == {gs.PREFIX + 'synthetic-test'}
    plan = tmp_path / 'plan.json'
    with pytest.raises(ForecastDataError, match='no_fixed_distribution_training_roots'):
        compare.main(['prepare', '--dataset', str(collection / 'dataset'), '--collection', str(collection),
                      '--output', str(plan)])
    assert not plan.exists()


def test_comparison_cli_pins_evidence_and_reports_requested_aliases(tmp_path, monkeypatch):
    from hook_monitor.evaluation.flow_forecast.dataset import write_dataset
    data = dataset()
    source = tmp_path / 'data'
    write_dataset(data, source)
    collection = seal_only(tmp_path)
    audit = evidence(data)
    monkeypatch.setattr(gs, 'read_collection', lambda _: (data, {}, audit))
    plan, report = tmp_path / 'plan.json', tmp_path / 'report.json'
    common = ['--dataset', str(source), '--collection', str(collection)]
    compare.main(['prepare', *common, '--output', str(plan)])
    compare.main(['evaluate', *common, '--plan', str(plan), '--output', str(report), '--partition', 'train'])
    result = json.loads(report.read_text())
    assert result['generalization']['agent_models']['requested_alias_strata_scored'] is True
    assert result['generalization']['agent_models']['evaluated'] is False
    assert result['acceptance']['status'] == 'inconclusive_do_not_adopt'
    with pytest.raises(ForecastDataError, match='plan_mismatch'):
        compare.main(['evaluate', '--dataset', str(source), '--plan', str(plan),
                      '--output', str(tmp_path / 'removed-collection.json')])
    seal = json.loads((collection / 'collection.json').read_text())
    seal['evidence_sha'] = 'e' * 64
    (collection / 'collection.json').write_text(json.dumps(seal))
    with pytest.raises(ForecastDataError, match='generator_plan_mismatch'):
        compare.main(['evaluate', *common, '--plan', str(plan), '--output', str(tmp_path / 'changed.json')])


def test_holdout_report_binds_reordered_dataset_and_receipts(tmp_path, monkeypatch):
    from test_flow_forecast_partition_bundle import fixture_dataset
    directory, manifest = bundle(tmp_path)
    data = fixture_dataset()
    collection = seal_only(tmp_path)
    audit = evidence(data)
    monkeypatch.setattr(gs, 'read_collection', lambda _: (data, {}, audit))
    plan = compare_holdout.prepare(directory, collection=collection)
    ledger = HoldoutLedger.create(tmp_path / 'ledger.db')
    seal = manifest['partitions']['test']
    ledger.seal(**seal)
    result = compare_holdout.evaluate_once(directory, plan, ledger, collection=collection)
    summary = result['generalization']['agent_models']
    assert summary['collection_identity'] == plan['generator_collection_sha']
    assert summary['scored_partition'] == 'test'
    assert summary['requested_alias_strata_scored'] is True
    assert summary['evaluated'] is False
    assert ledger.status(seal['dataset_sha'])['report_sha']


def test_training_mixed_group_prevents_false_unseen_test_alias(tmp_path, monkeypatch):
    from test_flow_forecast_partition_bundle import fixture_dataset
    original = fixture_dataset()
    train_root = next(p.root_case_id for p in original.prefixes if original.split.partition(p) == 'train')
    # A related second training run uses another model. It must stay in the same
    # group without hiding the first model from the test novelty check.
    copies = tuple(replace(b, prefix=replace(b.prefix, root_case_id='zz-related-run',
                                            source_version='zz-related-run'))
                   for b in original.branches if b.prefix.root_case_id == train_root)
    data = assemble(original.branches + copies, related_roots=((train_root, 'zz-related-run'),))
    assert all(data.split.partition(p) == 'train' for p in data.prefixes
               if p.root_case_id in (train_root, 'zz-related-run'))
    names = {p.root_case_id: 'model-B' if p.root_case_id == 'zz-related-run' else 'model-A'
             for p in data.prefixes}
    audit = evidence(data, names)
    path = seal_only(tmp_path)
    monkeypatch.setattr(gs, 'read_collection', lambda _: (data, {}, audit))
    summary = gs.load(data, path, gs.collection_identity(path))['summary']
    assert summary['requested_models_by_partition']['train'] == []
    assert summary['requested_models_by_partition']['test'] == ['model-A']
    assert summary['observed_requested_models_by_partition']['train'] == ['model-A', 'model-B']
    assert summary['unseen_test_requested_aliases'] == []
