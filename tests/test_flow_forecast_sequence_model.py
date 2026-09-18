from dataclasses import asdict, replace

import pytest

from hook_monitor.evaluation.flow_forecast.dataset import assemble
from hook_monitor.evaluation.flow_forecast.metrics import score_routes
from hook_monitor.evaluation.flow_forecast.prefix import ForecastDataError
from research.flow_forecast.model import fit
from research.flow_forecast.tokens import Action, UNKNOWN, advance, context
from test_flow_forecast_baselines import dataset
from test_flow_forecast_evaluate import partition_copy


def find(data, *, task='plain_http', branch='send', cut=1, mode='observe', root='protected-http-family'):
    return next(b for b in data.branches if b.prefix.task_kind == task and b.branch_id == branch
                and b.prefix.max_sequence_no == cut and b.policy_mode == mode and b.prefix.root_case_id == root)


def test_learns_joint_multistep_continuations_and_updates_after_visible_output():
    data = dataset()
    model = fit(data)
    before = find(data)
    original = asdict(before.prefix)
    result = model.generate(before.prefix, policy_mode='observe', horizon=4)
    assert asdict(before.prefix) == original
    assert result.forecast.protected_probability == pytest.approx(2/3)
    assert sorted(c.probability for c in result.candidates) == pytest.approx([1/3] * 3)
    assert {tuple(a.operation for a in c.actions) for c in result.candidates} == {
        ('branch',), ('branch', 'send'), ('branch', 'save', 'send')}
    for branch, probability in [('send', 1), ('save_then_send', 1), ('local', 0)]:
        visible = find(data, branch=branch, cut=2)
        forecast = model.predict(visible.prefix, policy_mode='observe', horizon=4)
        assert forecast.protected_probability == probability
        assert score_routes(forecast, visible)['joint_top_k_hit']


def test_generated_intermediate_objects_and_relations_preserve_protected_path():
    data = dataset()
    model = fit(data)
    item = find(data, task='base64_http', branch='save_then_send', cut=2)
    prediction = model.generate(item.prefix, policy_mode='observe', horizon=4)
    candidate, = prediction.candidates
    assert [a.operation for a in candidate.actions] == ['encode', 'save', 'send']
    assert candidate.routes[0].steps == ((1, 'base64', 'bytes'), (2, 'save', 'file'), (3, 'send', 'sink'))
    assert score_routes(prediction.forecast, item)['edge_f1'] == 1
    partial = model.predict(item.prefix, policy_mode='observe', horizon=1)
    assert partial.protected_probability == 0
    assert partial.outcomes[0].routes[0].steps == ((1, 'base64', 'bytes'),)
    assert score_routes(partial, item)['edge_f1'] == 1


def test_public_objects_do_not_gain_protection_from_a_registered_unused_source():
    data = dataset()
    item = find(data, cut=2, root='public-http-family')
    prediction = fit(data).generate(item.prefix, policy_mode='observe', horizon=4)
    assert prediction.forecast.protected_probability == 0
    assert all(not c.routes for c in prediction.candidates)


def test_unknown_and_censored_continuations_are_not_learned_as_safe_endings():
    data = dataset()
    model = fit(data)
    blocked = find(data, cut=2, mode='enforce')
    result = model.predict(blocked.prefix, policy_mode='enforce', horizon=4)
    assert result.protected_probability is None and result.unknown_probability == 1
    unseen = replace(blocked.prefix, task_kind='unknown')
    assert model.predict(unseen, policy_mode='observe', horizon=4).unknown_probability == 1
    altered = []
    for b in data.branches:
        edges = tuple(replace(e, relation='unknown', evidence='unknown', evidence_digest=None)
                      if e.relation == 'send' else e for e in b.transfers)
        altered.append(replace(b, transfers=edges))
    uncertain_model = fit(assemble(tuple(altered)))
    prefix = find(data, cut=2).prefix
    assert uncertain_model.predict(prefix, policy_mode='observe', horizon=4).protected_probability is None


def test_beam_pruning_preserves_unenumerated_mass_and_does_not_renormalize():
    data = dataset()
    result = fit(data).generate(find(data).prefix, policy_mode='observe', horizon=4, beam_width=1)
    assert result.forecast.other_probability == pytest.approx(2/3)
    assert sum(c.probability for c in result.candidates) == pytest.approx(1/3)
    assert result.forecast.protected_probability is None


def test_test_truth_is_not_used_for_training_or_model_version():
    train = dataset()
    combined = assemble(train.branches + partition_copy(train, 'test'))
    first, second = fit(train), fit(combined)
    assert first == second
    assert first.training_roots == ('protected-http-family', 'public-http-family')
    with pytest.raises(TypeError):
        first.transitions['new'] = ((UNKNOWN, 1.0),)


def test_object_renaming_does_not_change_the_learned_distribution():
    data = dataset()
    model = fit(data)
    old = find(data, task='base64_http', cut=2).prefix
    mapping = {o.object_id: f'renamed-{i}' for i, o in enumerate(old.objects)}
    renamed = replace(old, objects=tuple(replace(o, object_id=mapping[o.object_id]) for o in old.objects),
                      observations=tuple(replace(s, inputs=tuple(mapping[k] for k in s.inputs),
                                                 outputs=tuple(mapping[k] for k in s.outputs))
                                         for s in old.observations),
                      protected_sources=tuple(mapping[k] for k in old.protected_sources))
    assert context(old, 'observe') == context(renamed, 'observe')
    forecast = model.predict(renamed, policy_mode='observe', horizon=4)
    assert forecast.protected_probability == 1
    assert forecast.outcomes[0].routes[0].source == mapping['private-source']


def test_tokens_reject_unavailable_parents_and_invalid_sink_relations():
    prefix = find(dataset()).prefix
    action = Action('file', 'copy', 'ok', (('file', 0),), ('bytes',), ((0, 0, 'copy'),))
    with pytest.raises(ForecastDataError, match='predicted_parent_unavailable'):
        advance(prefix, action)
    with pytest.raises(ForecastDataError, match='invalid_action_sink'):
        Action('http', 'send', 'ok', (('bytes', 0),), ('sink',), ((0, 0, 'copy'),))


def test_save_reload_preserves_every_prediction_and_rejects_tampering(tmp_path):
    import json
    from research.flow_forecast.artifacts import load_model, save_model
    data = dataset()
    model = fit(data)
    path = tmp_path / 'model.json'
    save_model(model, path)
    restored = load_model(path)
    assert model.model_digest == restored.model_digest
    assert model.version == restored.version
    for branch in data.branches:
        for horizon in (1, 2, 4, 8):
            assert model.generate(branch.prefix, policy_mode=branch.policy_mode, horizon=horizon) == restored.generate(
                branch.prefix, policy_mode=branch.policy_mode, horizon=horizon)
    with pytest.raises(FileExistsError):
        save_model(model, path)
    artifact = json.loads(path.read_text())
    artifact['model']['training_digest'] = 'f' * 64
    path.write_text(json.dumps(artifact))
    with pytest.raises(ForecastDataError, match='model_digest_mismatch'):
        load_model(path)


def test_model_version_covers_parameters_not_just_training_data():
    from research.flow_forecast.model import SequenceModel
    model = fit(dataset())
    transitions = dict(model.transitions)
    key = next(iter(transitions))
    transitions[key] = ((UNKNOWN, 1.0),)
    altered = SequenceModel(transitions, model.training_digest, model.training_roots)
    assert altered.version != model.version


def test_resource_limits_stop_training_and_never_create_artifacts(tmp_path):
    from research.flow_forecast.budget import Budget
    def exhausted():
        raise ForecastDataError('research_time_budget_exceeded')
    with pytest.raises(ForecastDataError, match='research_time_budget_exceeded'):
        fit(dataset(), check_budget=exhausted)
    with pytest.raises(ForecastDataError, match='research_memory_budget_exceeded'):
        fit(dataset(), check_budget=Budget(memory_bytes=1024).check)
    assert not list(tmp_path.iterdir())


def test_research_command_measures_cpu_and_keeps_holdout_absence_visible(tmp_path):
    from hook_monitor.evaluation.flow_forecast.dataset import write_dataset
    from research.flow_forecast.train import run
    data = dataset()
    source = tmp_path / 'source'
    write_dataset(data, source)
    heldout = run(source, tmp_path / 'heldout')
    assert heldout['reload_predictions_match']
    assert heldout['prediction_rows'] == 0
    assert heldout['conditions']['observe/4']['status'] == 'insufficient_evaluation_roots'
    assert heldout['resources']['device'] == 'cpu'
    assert heldout['training_cpu_seconds'] > 0
    smoke = run(source, tmp_path / 'smoke', partition='train')
    assert smoke['prediction_rows'] == len(data.branches) * 4
    assert smoke['scope'] == 'training_smoke_only'
    assert smoke['adoption'] == 'not_assessed_do_not_adopt'
    # Hidden branch outcomes cannot all match the single MAP continuation.
    assert 0 < smoke['conditions']['observe/4']['edge_f1'] < 1
    with pytest.raises(FileExistsError):
        run(source, tmp_path / 'smoke', partition='train')
