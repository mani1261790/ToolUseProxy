from copy import deepcopy
from pathlib import Path

import pytest

from hook_monitor.evaluation.flow_forecast.labels import label_future
from hook_monitor.evaluation.flow_forecast.prefix import ForecastDataError, digest
from research.flow_forecast import mbpp_import, checked_mbpp, task_catalog
from research.flow_forecast.mbpp_projection import TRANSPORT_SHA
from research.flow_forecast import mbpp_contract
from test_flow_forecast_mbpp_import import capture, reference as mbpp_reference

reference = mbpp_reference


@pytest.fixture(autouse=True)
def fixture_source(monkeypatch, reference):
    monkeypatch.setattr(mbpp_contract, 'selected', lambda path: [reference])


def fake_binding(audit):
    return {'capture_root':audit['intent']['root'], 'capture_report_sha':digest(audit['report']),
            'transport_source_sha':TRANSPORT_SHA, 'record_sha':audit['intent']['origin']['candidate']['record_sha'], 'semantic_truth_promoted':False}


@pytest.mark.parametrize('variant', ['public','include_private'])
def test_checked_projection_preserves_visible_prefix_and_censors_blocked_future(monkeypatch, tmp_path, variant, reference):
    directory = tmp_path / 'capture'
    capture(directory, reference, variant)
    original, audit = mbpp_import.read_capture(directory, Path("source"))
    monkeypatch.setattr(checked_mbpp, 'bind_capture', lambda *a: fake_binding(audit))
    checked, evidence = checked_mbpp.read_checked_capture(directory, Path('fixture-interventions'), Path('source'))
    assert checked.prefixes == original.prefixes
    for branch in checked.branches:
        label = label_future(branch, 4)
        expected = 'no' if variant == 'public' else 'yes' if branch.policy_mode == 'observe' else 'unknown'
        assert label.protected_arrival == expected
        assert label.censored == (variant == 'include_private' and branch.policy_mode == 'enforce')
        assert all(edge.relation != 'selection' for edge in branch.transfers)
    assert evidence['closed_mbpp_projection_evidence']['general_semantic_truth'] is False
    assert evidence['closed_mbpp_projection_evidence']['independence_verified'] is False


def test_changed_pinned_transport_refuses_truth_promotion(monkeypatch, tmp_path, reference):
    directory = tmp_path / 'capture'
    capture(directory, reference)
    _, audit = mbpp_import.read_capture(directory, Path("source"))
    monkeypatch.setattr(checked_mbpp, 'TRANSPORT_SHA', '0'*64)
    with pytest.raises(ForecastDataError, match='binding_changed'):
        checked_mbpp.contract(audit, fake_binding(audit), mbpp_contract.bind_capture(directory, Path("source")))


def test_changed_private_state_refuses_contract(monkeypatch, tmp_path, reference):
    directory = tmp_path / 'capture'
    capture(directory, reference)
    _, original = mbpp_import.read_capture(directory, Path("source"))
    audit = deepcopy(original)
    audit['report']['conditions'][0]['steps'][0]['observation']['dispatch']['after']['private'] = 'different'
    computation = mbpp_contract.bind_capture(directory, Path('source'))
    computation['capture_report_sha'] = digest(audit['report'])
    with pytest.raises(ForecastDataError, match='compute_domain'):
        checked_mbpp.contract(audit, fake_binding(audit), computation)


def test_missing_source_edge_cannot_turn_private_into_safe(monkeypatch, tmp_path, reference):
    from dataclasses import replace
    from hook_monitor.evaluation.flow_forecast.dataset import assemble
    directory = tmp_path / 'capture'
    capture(directory, reference, 'include_private')
    original, audit = mbpp_import.read_capture(directory, Path("source"))
    branches = tuple(replace(b, transfers=tuple(e for e in b.transfers if e.source != 'protected-source')) for b in original.branches)
    changed = assemble(branches, provenance=original.provenance)
    monkeypatch.setattr(checked_mbpp, 'read_capture', lambda *a: (changed, audit))
    monkeypatch.setattr(checked_mbpp, 'bind_capture', lambda *a: fake_binding(audit))
    with pytest.raises(ForecastDataError, match='coverage_mismatch'):
        checked_mbpp.read_checked_capture(directory, Path('fixture-interventions'), Path('source'))


def test_related_checked_variants_remain_one_group(monkeypatch, tmp_path, reference):
    pairs = []
    audits = {}
    for index, variant in enumerate(('public','include_private'),1):
        directory = tmp_path / variant
        capture(directory, reference, variant, str(index)*32)
        _, audits[directory] = mbpp_import.read_capture(directory, Path("source"))
        pairs.append({'capture':str(directory), 'interventions':'fixture'})
    monkeypatch.setattr(checked_mbpp, 'bind_capture', lambda p, *a: fake_binding(audits[p]))
    data, audit, _, _ = task_catalog.collect_mbpp_captures(tuple(pairs), Path("source"), checked=True)
    assert len(data.branches) == 12
    assert audit['grouped_root_count'] == 1
    assert audit['independence_verified'] is False
    assert audit['prior_nonuse_verified'] is False
