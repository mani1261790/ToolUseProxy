from copy import deepcopy
import hashlib
import json
import os

import pytest

from hook_monitor.evaluation.flow_lab import search_runner
from hook_monitor.evaluation.flow_lab.preflight import LabError
from hook_monitor.evaluation.flow_lab.task_assignment import load, main, prepare, validate
from test_flow_forecast_task_catalog import catalog, design
from test_flow_lab_controller import Provider, context as context, run
from test_flow_lab_search_runner import lab as lab


def binding(tool='http'):
    raw = b'Synthetic design used only by this test; not an independent research sample.'
    origin = hashlib.sha256(raw).hexdigest()
    row = design('task-one', tool=tool)
    row['origin']['artifact_sha'] = origin
    return prepare(catalog(row), {origin: raw}, 'task-one')


def test_assignment_is_recorded_before_provider_and_context_does_not_mutate_it(context):
    assignment = binding()
    class Inspecting(Provider):
        def propose(self, feedback, **kwargs):
            saved = context[0].read()
            assert saved['identity']['task_assignment'] == assignment
            assert saved['call_records'][-1]['outcome'] == 'pending'
            current = kwargs['task_context']
            assert current['assignment_sha'] == assignment['assignment_sha']
            assert current['design']['id'] == 'task-one'
            current['design']['objective'] = 'changed inside provider'
            return {'status': 'complete', 'actions': []}
    assert run(context, Inspecting([]), task_assignment=assignment)['status'] == 'completed'
    assert context[0].read()['identity']['task_assignment'] == assignment
    changed = deepcopy(assignment['catalog'])
    changed['designs'][0]['objective'] = 'different task'
    replacement = prepare(changed, {key: raw.encode() for key, raw in assignment['origins'].items()}, 'task-one')
    with pytest.raises(LabError, match='search_revision_mismatch'):
        run(context, Provider([]), task_assignment=replacement)


def test_runner_cannot_add_or_remove_assignment_from_a_completed_run(lab, tmp_path):
    folder, calls, _, _ = lab
    assignment = binding()
    result = search_runner.execute(tmp_path, folder, 'synthetic-model', task_assignment=assignment)
    assert result['status'] == 'completed' and len(calls) == 1
    assert search_runner.execute(tmp_path, folder, 'synthetic-model', task_assignment=assignment)['status'] == 'completed'
    with pytest.raises(LabError, match='search_task_assignment_mismatch'):
        search_runner.execute(tmp_path, folder, 'synthetic-model')
    assert len(calls) == 1


def test_unsupported_tools_and_tampered_origin_rejected_before_run(lab, tmp_path):
    for tool in ('mail', 'tool_output'):
        with pytest.raises(LabError, match='unsupported_task_tools'):
            binding(tool)
    assignment = binding()
    key = next(iter(assignment['origins']))
    assignment['origins'][key] = 'changed'
    with pytest.raises(LabError, match='invalid_task_assignment'):
        search_runner.execute(tmp_path, lab[0], 'synthetic-model', task_assignment=assignment)
    assert not lab[0].exists()
    assert not lab[1]


def test_cli_seals_and_reloads_bounded_origin_documents(tmp_path):
    assignment = binding()
    origins = tmp_path / 'origins'
    origins.mkdir()
    for key, raw in assignment['origins'].items():
        (origins / (key + '.md')).write_text(raw)
    source = tmp_path / 'catalog.json'
    source.write_text(json.dumps(assignment['catalog']))
    output = tmp_path / 'assignment.json'
    args = ['--catalog', str(source), '--origins', str(origins), '--design-id', 'task-one', '--output', str(output)]
    main(args)
    assert load(output) == assignment
    assert validate(load(output))['independence_verified'] is False
    with pytest.raises(FileExistsError):
        main(args)
    link = tmp_path / 'link'
    link.symlink_to(output)
    with pytest.raises(OSError):
        load(link)
    pipe = tmp_path / 'pipe'
    os.mkfifo(pipe)
    with pytest.raises(LabError, match='invalid_task_assignment_file'):
        load(pipe)


def test_import_and_collection_use_pretrial_design_without_posthoc_mapping(tmp_path):
    from hook_monitor.evaluation.flow_lab.budget import Budget
    from hook_monitor.evaluation.flow_lab.controller import run_search
    from hook_monitor.evaluation.flow_lab.models import RunSpec, utc_now
    from hook_monitor.evaluation.flow_lab.search_state import SearchJournal
    from hook_monitor.evaluation.flow_lab.storage import TrialStore
    from research.flow_forecast.task_catalog import collect_assigned_searches, main as collect_main, read_collection
    from test_flow_forecast_import import Provider as Proposals, Transport
    import uuid
    paths = []
    assignment = binding()
    for _ in range(2):
        path = tmp_path / uuid.uuid4().hex
        spec = RunSpec(uuid.uuid4().hex, 'adaptive-v1', 'source-test', 'policy-test',
                       'a' * 64, utc_now(), mode='adaptive_search')
        with SearchJournal(path) as journal, TrialStore(path / 'trials') as store:
            assert run_search(journal, store, spec, Transport(), Proposals(), Budget(),
                              task_assignment=assignment)['status'] == 'completed'
        paths.append(path)
    data, audit, saved_catalog, origins = collect_assigned_searches(tuple(paths))
    assert audit['grouped_root_count'] == 1
    assert audit['independence_verified'] is False
    assert all(row['design_id'] == 'task-one' for row in audit['bindings'])
    assert len(audit['assigned_searches']) == 2
    assert saved_catalog == assignment['catalog'] and origins
    inputs = tmp_path / 'searches.json'
    inputs.write_text(json.dumps([str(path) for path in paths]))
    output = tmp_path / 'collection'
    collect_main(['--assigned-searches', str(inputs), '--output', str(output)])
    assert read_collection(output)[0] == data
    with pytest.raises(SystemExit):
        collect_main(['--assigned-searches', str(inputs), '--output', str(tmp_path / 'other'),
                      '--catalog', str(tmp_path / 'posthoc.json')])


def test_unassigned_historical_run_is_not_promoted_to_pretrial_collection(tmp_path):
    from research.flow_forecast.task_catalog import collect_assigned_searches
    from hook_monitor.evaluation.flow_forecast.prefix import ForecastDataError
    from test_flow_forecast_import import create_search
    path = tmp_path / 'old'
    create_search(path)
    with pytest.raises(ForecastDataError, match='no_pretrial_assignment'):
        collect_assigned_searches((path,))


def test_task_context_changes_recorded_prompt_identity(tmp_path):
    from hook_monitor.evaluation.flow_lab.codex_agent import CodexProvider
    from test_flow_lab_codex_agent import events, executable
    response = {'status': 'complete', 'actions': []}
    provider = CodexProvider('synthetic-model', executable=executable(tmp_path, f'print({events(response).decode()!r})'))
    provider.propose([], task_mode='benign_task', timeout=2, max_bytes=4096)
    ordinary = provider.last_execution['prompt_sha']
    provider.propose([], task_mode='benign_task', timeout=2, max_bytes=4096, task_context=validate(binding()))
    assert provider.last_execution['prompt_sha'] != ordinary
