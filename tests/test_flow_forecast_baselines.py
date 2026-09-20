from dataclasses import replace

import pytest

from hook_monitor.evaluation.flow_forecast.baselines import KINDS, fit_baseline
from hook_monitor.evaluation.flow_forecast.dataset import assemble
from hook_monitor.evaluation.flow_forecast.executor import SendResult, reference_suite
from hook_monitor.evaluation.flow_forecast.metrics import score_routes
from hook_monitor.evaluation.flow_forecast.prefix import ForecastDataError, digest
from hook_monitor.evaluation.flow_forecast.runner import expected_body


class Sender:
    def send(self, *, source, encoding, body, mode):
        assert body == expected_body(source, encoding)
        denied = source == 'protected'
        executed = mode == 'observe' or not denied
        return SendResult('deny' if denied else 'allow', executed, 'yes' if executed else 'no',
                          'yes' if executed and denied else 'no', True, executed,
                          digest([source, encoding, mode]))


def dataset():
    return assemble(tuple(row for variant in ('initial', 'alternate')
                          for row in reference_suite(Sender(), environment_version='v1', task_variant=variant)))


@pytest.mark.parametrize('kind', KINDS)
def test_all_baselines_predict_from_visible_prefix_only(kind):
    data = dataset()
    model = fit_baseline(data, kind)
    for branch in data.branches:
        for horizon in (1, 2, 4, 8):
            prediction = model.predict(branch.prefix, policy_mode=branch.policy_mode, horizon=horizon)
            prediction.validate_for(branch.prefix, policy_mode=branch.policy_mode, horizon=horizon)
            score_routes(prediction, branch)
    if kind != 'static_reachability':
        assert model.training_roots == ('protected-http-family', 'public-http-family')
        with pytest.raises(TypeError):
            model.cohorts['future'] = {}


def test_frequency_uses_joint_future_counts_and_keeps_unknown_mass():
    data = dataset()
    model = fit_baseline(data, 'frequency')
    before = next(b for b in data.branches if b.prefix.max_sequence_no == 1 and b.prefix.task_kind == 'plain_http')
    observe = model.predict(before.prefix, policy_mode='observe', horizon=4)
    # Equally weighted protected/public roots: 2/3 arrival for one, 0 for the other.
    assert observe.protected_probability == pytest.approx(1/3)
    assert sum(o.probability for o in observe.outcomes if o.routes) == pytest.approx(1/3)
    enforce = model.predict(before.prefix, policy_mode='enforce', horizon=4)
    assert enforce.protected_probability is None
    assert enforce.unknown_probability == pytest.approx(1/3)


def test_risk_only_has_no_paths_and_one_step_does_not_roll_out_hidden_steps():
    data = dataset()
    before = next(b for b in data.branches if b.prefix.max_sequence_no == 1)
    risk = fit_baseline(data, 'risk_only').predict(before.prefix, policy_mode='observe', horizon=4)
    assert risk.protected_probability is not None and risk.outcomes == () and risk.other_probability == 1
    single = fit_baseline(data, 'one_step').predict(before.prefix, policy_mode='observe', horizon=4)
    assert single.protected_probability == 0
    static = fit_baseline(data, 'static_reachability')
    assert static.predict(before.prefix, policy_mode='enforce', horizon=1).protected_probability == 1
    no_network = replace(before.prefix, capabilities=('file', 'tool_output'))
    assert static.predict(no_network, policy_mode='observe', horizon=1).protected_probability == 0


def test_unseen_context_is_abstention_not_a_safe_prediction():
    data = dataset()
    prefix = replace(data.branches[0].prefix, task_kind='unknown')
    result = fit_baseline(data, 'frequency').predict(prefix, policy_mode='observe', horizon=4)
    assert result.protected_probability is None and result.unknown_probability == 1


def test_holdout_truth_is_never_fitted():
    original = dataset()
    roots = []
    for index in range(100):
        candidate = f'heldout-{index}'
        bucket = int(digest(['split-v1', candidate])[:16], 16) % 100
        if bucket >= 80:
            roots.append(candidate)
        if len(roots) == 2:
            break
    root_map = dict(zip(('protected-http-family', 'public-http-family'), roots))
    heldout = tuple(replace(b, prefix=replace(b.prefix, root_case_id=root_map[b.prefix.root_case_id],
                                             environment_version='holdout-environment'),
                           control_group=root_map[b.prefix.root_case_id]) for b in original.branches)
    combined = assemble(original.branches + heldout)
    for kind in KINDS:
        first, second = fit_baseline(original, kind), fit_baseline(combined, kind)
        assert first.training_digest == second.training_digest
        assert first.training_roots == second.training_roots
    with pytest.raises(ForecastDataError, match='no_fixed_distribution_training_roots'):
        fit_baseline(assemble(heldout), 'frequency')
