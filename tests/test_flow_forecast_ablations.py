from dataclasses import replace

import pytest

from research.flow_forecast.ablations import Ablation, VARIANTS
from research.flow_forecast.model import fit
from hook_monitor.evaluation.flow_forecast.prefix import InformationObject
from test_flow_forecast_baselines import dataset
from test_flow_forecast_sequence_model import find


def test_removing_parent_attribution_does_not_invent_safe_arrivals():
    data = dataset()
    model = fit(data)
    prefix = find(data, cut=2).prefix
    assert model.predict(prefix, policy_mode='observe', horizon=4).protected_probability == 1
    forecast = Ablation(model, 'without_parent_relations').predict(prefix, policy_mode='observe', horizon=4)
    assert forecast.protected_probability is None
    assert forecast.unknown_probability == 1


def test_one_operation_ablation_does_not_look_beyond_its_only_step():
    data = dataset()
    prefix = find(data, task='base64_http', branch='save_then_send', cut=2).prefix
    forecast = Ablation(fit(data), 'without_multistep').predict(prefix, policy_mode='observe', horizon=4)
    assert forecast.protected_probability == 0
    assert forecast.horizon == 4
    assert all(len(r.steps) == 1 for item in forecast.outcomes for r in item.routes)


def test_identity_ablation_exposes_ambiguous_same_kind_objects():
    data = dataset()
    model = fit(data)
    prefix = find(data, cut=2).prefix
    # An additional visible byte object changes no recent operation, but removing
    # object identity makes the intended future input unresolvable.
    ambiguous = replace(prefix, objects=prefix.objects + (InformationObject('other-bytes', 'bytes', 0),))
    forecast = Ablation(model, 'without_object_identity').predict(ambiguous, policy_mode='observe', horizon=4)
    assert forecast.unknown_probability == 1
    original = Ablation(model, 'without_object_identity').predict(prefix, policy_mode='observe', horizon=4)
    assert original.protected_probability == 1


@pytest.mark.parametrize('variant', VARIANTS)
def test_all_ablation_outputs_remain_bound_to_visible_prefix_and_condition(variant):
    data = dataset()
    model = Ablation(fit(data), variant)
    for branch in data.branches:
        for horizon in (1, 2, 4, 8):
            output = model.predict(branch.prefix, policy_mode=branch.policy_mode, horizon=horizon)
            output.validate_for(branch.prefix, policy_mode=branch.policy_mode, horizon=horizon)
