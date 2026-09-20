from copy import deepcopy
from pathlib import Path

import pytest

from hook_monitor.evaluation.flow_forecast.labels import label_future
from hook_monitor.evaluation.flow_forecast.prefix import ForecastDataError, digest
from research.flow_forecast import agenda_import, checked_agenda, task_catalog
from research.flow_forecast.agenda_projection import API_SHA
from test_flow_forecast_agenda_import import capture


def fake_binding(audit):
    return {'capture_root':audit['intent']['root'], 'capture_report_sha':digest(audit['report']),
            'api_source_sha':API_SHA, 'semantic_truth_promoted':False}


@pytest.mark.parametrize('variant', ['public','include_private'])
def test_checked_projection_preserves_visible_prefix_and_censors_blocked_future(monkeypatch, tmp_path, variant):
    directory = tmp_path / 'capture'
    capture(directory, variant)
    original, audit = agenda_import.read_capture(directory)
    monkeypatch.setattr(checked_agenda, 'bind_capture', lambda *a: fake_binding(audit))
    checked, evidence = checked_agenda.read_checked_capture(directory, Path('fixture-interventions'))
    assert checked.prefixes == original.prefixes
    for branch in checked.branches:
        label = label_future(branch, 4)
        expected = 'no' if variant == 'public' else 'yes' if branch.policy_mode == 'observe' else 'unknown'
        assert label.protected_arrival == expected
        assert label.censored == (variant == 'include_private' and branch.policy_mode == 'enforce')
        assert all(edge.relation != 'selection' for edge in branch.transfers)
    assert evidence['closed_agenda_projection_evidence']['general_semantic_truth'] is False
    assert evidence['closed_agenda_projection_evidence']['independence_verified'] is False


def test_changed_pinned_transport_refuses_truth_promotion(monkeypatch, tmp_path):
    directory = tmp_path / 'capture'
    capture(directory)
    _, audit = agenda_import.read_capture(directory)
    monkeypatch.setattr(checked_agenda, 'TRANSPORT_SHA', '0'*64)
    with pytest.raises(ForecastDataError, match='source_changed'):
        checked_agenda.contract(audit, fake_binding(audit))


def test_changed_private_state_refuses_contract(tmp_path):
    directory = tmp_path / 'capture'
    capture(directory)
    _, original = agenda_import.read_capture(directory)
    audit = deepcopy(original)
    audit['report']['conditions'][0]['steps'][0]['observation']['dispatch']['after']['A']['new']['private'] = 'different'
    with pytest.raises(ForecastDataError, match='add_domain'):
        checked_agenda.contract(audit, fake_binding(audit))


def test_missing_source_edge_cannot_turn_private_into_safe(monkeypatch, tmp_path):
    from dataclasses import replace
    from hook_monitor.evaluation.flow_forecast.dataset import assemble
    directory = tmp_path / 'capture'
    capture(directory, 'include_private')
    original, audit = agenda_import.read_capture(directory)
    branches = tuple(replace(b, transfers=tuple(e for e in b.transfers if e.source != 'protected-source')) for b in original.branches)
    changed = assemble(branches, provenance=original.provenance)
    monkeypatch.setattr(checked_agenda, 'read_capture', lambda *a: (changed, audit))
    monkeypatch.setattr(checked_agenda, 'bind_capture', lambda *a: fake_binding(audit))
    with pytest.raises(ForecastDataError, match='coverage_mismatch'):
        checked_agenda.read_checked_capture(directory, Path('fixture-interventions'))


def test_related_checked_variants_remain_one_group(monkeypatch, tmp_path):
    pairs = []
    audits = {}
    for index, variant in enumerate(('public','include_private'),1):
        directory = tmp_path / variant
        capture(directory, variant, str(index)*32)
        _, audits[directory] = agenda_import.read_capture(directory)
        pairs.append({'capture':str(directory), 'interventions':'fixture'})
    monkeypatch.setattr(checked_agenda, 'bind_capture', lambda p, _: fake_binding(audits[p]))
    data, audit, _, _ = task_catalog.collect_agenda_captures(tuple(pairs), checked=True)
    assert len(data.branches) == 12
    assert audit['grouped_root_count'] == 1
    assert audit['independence_verified'] is False
    assert audit['prior_nonuse_verified'] is False
