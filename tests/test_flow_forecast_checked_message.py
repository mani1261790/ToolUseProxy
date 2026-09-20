from copy import deepcopy
from pathlib import Path

import pytest

from hook_monitor.evaluation.flow_forecast.labels import label_future
from hook_monitor.evaluation.flow_forecast.prefix import ForecastDataError, digest
from research.flow_forecast import bfcl_message_import as message_import, checked_message, task_catalog
import hashlib
from research.flow_forecast import bfcl_message_transport, bfcl_message_reference
from test_flow_forecast_bfcl_message_import import capture, SOURCE


@pytest.fixture(autouse=True)
def pinned_fixture(monkeypatch):
    sha = hashlib.sha256(SOURCE.encode()).hexdigest()
    for module in (message_import, checked_message, bfcl_message_transport, bfcl_message_reference):
        monkeypatch.setattr(module, 'SOURCE_SHA', sha)


def fake_binding(audit):
    return {'capture_root':audit['intent']['root'], 'capture_report_sha':digest(audit['report']),
            'source_sha':checked_message.SOURCE_SHA, 'semantic_truth_promoted':False}


@pytest.mark.parametrize('variant', ['public','include_private'])
def test_checked_projection_preserves_visible_prefix_and_censors_blocked_future(monkeypatch, tmp_path, variant):
    directory = tmp_path / 'capture'
    capture(directory, variant)
    original, audit = message_import.read_capture(directory, SOURCE)
    monkeypatch.setattr(checked_message, 'bind_capture', lambda *a: fake_binding(audit))
    checked, evidence = checked_message.read_checked_capture(directory, Path('fixture-interventions'), SOURCE)
    assert checked.prefixes == original.prefixes
    for branch in checked.branches:
        label = label_future(branch, 4)
        expected = 'no' if variant == 'public' else 'yes' if branch.policy_mode == 'observe' else 'unknown'
        assert label.protected_arrival == expected
        assert label.censored == (variant == 'include_private' and branch.policy_mode == 'enforce')
        assert all(edge.relation != 'selection' for edge in branch.transfers)
    assert evidence['closed_message_projection_evidence']['general_semantic_truth'] is False
    assert evidence['closed_message_projection_evidence']['independence_verified'] is False


def test_changed_pinned_transport_refuses_truth_promotion(monkeypatch, tmp_path):
    directory = tmp_path / 'capture'
    capture(directory)
    _, audit = message_import.read_capture(directory, SOURCE)
    monkeypatch.setattr(checked_message, 'TRANSPORT_SHA', '0'*64)
    with pytest.raises(ForecastDataError, match='source_changed'):
        checked_message.contract(audit, fake_binding(audit), SOURCE)


def test_changed_private_state_refuses_contract(tmp_path):
    directory = tmp_path / 'capture'
    capture(directory)
    _, original = message_import.read_capture(directory, SOURCE)
    audit = deepcopy(original)
    audit['report']['conditions'][0]['steps'][0]['observation']['dispatch']['after']['inbox'][1]['USR003'] = 'different'
    with pytest.raises(ForecastDataError, match='login_domain'):
        checked_message.contract(audit, fake_binding(audit), SOURCE)


def test_missing_source_edge_cannot_turn_private_into_safe(monkeypatch, tmp_path):
    from dataclasses import replace
    from hook_monitor.evaluation.flow_forecast.dataset import assemble
    directory = tmp_path / 'capture'
    capture(directory, 'include_private')
    original, audit = message_import.read_capture(directory, SOURCE)
    branches = tuple(replace(b, transfers=tuple(e for e in b.transfers if e.source != 'protected-source')) for b in original.branches)
    changed = assemble(branches, provenance=original.provenance)
    monkeypatch.setattr(checked_message, 'read_capture', lambda *a: (changed, audit))
    monkeypatch.setattr(checked_message, 'bind_capture', lambda *a: fake_binding(audit))
    with pytest.raises(ForecastDataError, match='coverage_mismatch'):
        checked_message.read_checked_capture(directory, Path('fixture-interventions'), SOURCE)


def test_related_checked_variants_remain_one_group(monkeypatch, tmp_path):
    source_path = tmp_path / 'source.py'
    source_path.write_text(SOURCE)
    pairs = []
    audits = {}
    for index, variant in enumerate(('public','include_private'),1):
        directory = tmp_path / variant
        capture(directory, variant, str(index)*32)
        _, audits[directory] = message_import.read_capture(directory, SOURCE)
        pairs.append({'capture':str(directory), 'interventions':'fixture'})
    monkeypatch.setattr(checked_message, 'bind_capture', lambda p, _, source: fake_binding(audits[p]))
    data, audit, _, _ = task_catalog.collect_message_captures(tuple(pairs), source_path, checked=True)
    assert len(data.branches) == 12
    assert audit['grouped_root_count'] == 1
    assert audit['independence_verified'] is False
    assert audit['prior_nonuse_verified'] is False
