from dataclasses import FrozenInstanceError, replace

import pytest

from hook_monitor.evaluation.flow_forecast.prefix import (
    ForecastDataError, InformationObject as Obj, ObservedStep as Step, freeze_prefix,
)


def snapshot(*, branch='send', cutoff=1, root='root-1'):
    return freeze_prefix(
        root_case_id=root,
        observations=(Step(1, 'file', 'read', ('source',), ('memory',), 'ok'),
                      Step(2, 'tool_output', 'branch', result=branch),
                      Step(3, 'file', 'save', ('memory',), ('future-file',), 'ok')),
        objects=(Obj('source', 'source', 0), Obj('memory', 'bytes', 1),
                 Obj('future-file', 'file', 3)),
        max_sequence_no=cutoff, capabilities=('file', 'http', 'tool_output'),
        environment_version='synthetic-v1', source_version='source-v1',
    )


def test_future_branch_and_object_cannot_change_prefix_input():
    before_send = snapshot(branch='send')
    before_local = snapshot(branch='local')
    assert before_send.model_input() == before_local.model_input()
    assert before_send.snapshot_digest == before_local.snapshot_digest
    assert 'future-file' not in str(before_send.model_input())
    assert snapshot(branch='send', cutoff=2).snapshot_digest != snapshot(branch='local', cutoff=2).snapshot_digest


def test_group_identity_is_not_a_model_feature():
    first, second = snapshot(root='case-1'), snapshot(root='case-2')
    assert first.snapshot_digest == second.snapshot_digest
    assert first.prefix_id != second.prefix_id
    assert 'root_case_id' not in first.model_input()


def test_input_copy_and_records_are_immutable():
    prefix = snapshot()
    before = prefix.snapshot_digest
    value = prefix.model_input()
    value['observations'][0]['result'] = 'send'
    value['objects'].clear()
    assert prefix.snapshot_digest == before
    with pytest.raises(FrozenInstanceError):
        prefix.objects[0].kind = 'sink'


@pytest.mark.parametrize('change', [
    {'max_sequence_no': 2},
    {'objects': (Obj('source', 'source', 0), Obj('memory', 'bytes', 2))},
    {'objects': (Obj('source', 'source', 0), Obj('memory', 'bytes', 1), Obj('hidden', 'file', 0), Obj('hidden', 'file', 0))},
    {'observations': (Step(1, 'file', 'read', ('missing',), ('memory',)),)},
    {'observations': (Step(1, 'file', 'read', ('memory',), ('memory',)),)},
    {'capabilities': ('http',)},
    {'schema': True},
])
def test_invalid_or_future_snapshot_is_rejected(change):
    with pytest.raises(ForecastDataError):
        replace(snapshot(), **change)


def test_prefix_cannot_gain_truth_or_detector_fields():
    with pytest.raises(TypeError):
        replace(snapshot(), receiver_arrival='yes')
    with pytest.raises(TypeError):
        Step(1, 'file', 'read', truth_parent='source')
