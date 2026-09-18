from dataclasses import replace
import json

import pytest

from hook_monitor.evaluation.flow_forecast.branches import Continuation, Transfer
from hook_monitor.evaluation.flow_forecast.dataset import assemble, read_dataset, write_dataset
from hook_monitor.evaluation.flow_forecast.prefix import (
    ForecastDataError, InformationObject as Obj, ObservedStep as Step, freeze_prefix,
)


def branches():
    prefix = freeze_prefix(
        root_case_id='family-1', max_sequence_no=1,
        observations=(Step(1, 'file', 'read', ('source',), ('memory',), 'ok'),),
        objects=(Obj('source', 'source', 0), Obj('memory', 'bytes', 1)),
        capabilities=('file', 'http', 'tool_output'), environment_version='synthetic-v1',
        source_version='v1', protected_sources=('source',),
    )
    results = []
    for kind in ('local', 'send'):
        for mode in ('observe', 'enforce'):
            steps = (Step(2, 'tool_output', 'branch', result=kind),)
            objects, arrivals = (), ()
            edges = (Transfer('source', 'memory', 1, 'copy', 'checked_bytes', 'a' * 64),)
            blocked = kind == 'send' and mode == 'enforce'
            if kind == 'send' and not blocked:
                steps += (Step(3, 'http', 'send', ('memory',), ('receiver',), 'ok'),)
                objects = (Obj('receiver', 'sink', 3),)
                arrivals = (('receiver', 3),)
                edges += (Transfer('memory', 'receiver', 3, 'send', 'receiver', 'b' * 64),)
            results.append(Continuation(prefix, kind, mode, 'fixed_replay', 'fixed_distribution', .5,
                                        steps, objects, edges, ('source',), arrivals, True,
                                        'blocked' if blocked else 'completed', 'control-1'))
    return tuple(results)


def test_sealed_artifact_roundtrip_keeps_inputs_and_targets_separate(tmp_path):
    dataset = assemble(branches())
    directory = tmp_path / 'dataset'
    identity = write_dataset(dataset, directory)
    restored = read_dataset(directory)
    assert restored == dataset
    assert len(identity) == 64
    inputs = json.loads((directory / 'inputs.json').read_text())
    assert len(inputs) == 1
    assert all(key not in str(inputs) for key in ('receiver_arrivals', 'probability', 'transfers', 'termination'))
    summary = restored.summary()
    assert summary['termination_counts'] == {'completed': 3, 'blocked': 1}
    assert summary['label_counts']['enforce/4/unknown'] == 1
    assert summary['label_counts']['observe/4/yes'] == 1
    assert summary['unknown_relation_counts']['semantic'] == 0
    with pytest.raises(FileExistsError):
        write_dataset(dataset, directory)


def test_repeat_generation_has_identical_seals(tmp_path):
    dataset = assemble(branches())
    assert write_dataset(dataset, tmp_path / 'a') == write_dataset(dataset, tmp_path / 'b')
    for path in (tmp_path / 'a').iterdir():
        assert path.read_bytes() == (tmp_path / 'b' / path.name).read_bytes()


@pytest.mark.parametrize('name', ['inputs.json', 'targets.json', 'summary.json', 'splits.json', 'manifest.json'])
def test_modified_or_missing_artifact_is_rejected(tmp_path, name):
    directory = tmp_path / 'dataset'
    write_dataset(assemble(branches()), directory)
    (directory / name).write_text('{}')
    with pytest.raises(ForecastDataError):
        read_dataset(directory)
    (directory / name).unlink()
    with pytest.raises(ForecastDataError):
        read_dataset(directory)


def test_symlink_cannot_redirect_dataset_read(tmp_path):
    directory = tmp_path / 'dataset'
    write_dataset(assemble(branches()), directory)
    payload = directory / 'inputs.json'
    payload.rename(tmp_path / 'moved')
    payload.symlink_to(tmp_path / 'moved')
    with pytest.raises(ForecastDataError):
        read_dataset(directory)


def test_missing_control_duplicate_branch_and_incomplete_probability_are_rejected():
    values = branches()
    for changed in (values[:-1], values + (values[0],),
                    tuple(replace(b, probability=.2) for b in values)):
        with pytest.raises(ForecastDataError):
            assemble(changed)


def test_adaptive_search_samples_do_not_claim_natural_frequencies():
    values = tuple(replace(b, sampling='adaptive_search', probability=None) for b in branches())
    assert assemble(values).summary()['sampling_counts'] == {'adaptive_search': 4}
    with pytest.raises(ForecastDataError):
        replace(values[0], probability=.5)


def test_protection_registration_must_be_visible_before_prediction():
    branch = branches()[0]
    assert branch.prefix.model_input()['protected_sources'] == ['source']
    with pytest.raises(ForecastDataError):
        replace(branch, prefix=replace(branch.prefix, protected_sources=()))


def reseal(directory, name, value):
    import hashlib
    from hook_monitor.evaluation.flow_forecast.prefix import canonical, digest
    raw = (canonical(value) + '\n').encode()
    (directory / name).write_bytes(raw)
    manifest_path = directory / 'manifest.json'
    manifest = json.loads(manifest_path.read_text())
    manifest['files'][name] = hashlib.sha256(raw).hexdigest()
    manifest['dataset_digest'] = digest(manifest['files'])
    manifest_path.write_text(canonical(manifest))


def test_rehashed_input_still_cannot_smuggle_future_fields(tmp_path):
    directory = tmp_path / 'dataset'
    write_dataset(assemble(branches()), directory)
    inputs = json.loads((directory / 'inputs.json').read_text())
    inputs[0]['input']['receiver_arrivals'] = [['receiver', 3]]
    reseal(directory, 'inputs.json', inputs)
    with pytest.raises(ForecastDataError, match='unknown_model_input_field'):
        read_dataset(directory)


def test_rehashed_split_cannot_move_a_prefix_without_validation(tmp_path):
    directory = tmp_path / 'dataset'
    write_dataset(assemble(branches()), directory)
    value = json.loads((directory / 'splits.json').read_text())
    old = value['assignments'][0][2]
    value['assignments'][0][2] = 'test' if old != 'test' else 'train'
    reseal(directory, 'splits.json', value)
    with pytest.raises(ForecastDataError, match='split_manifest_mismatch'):
        read_dataset(directory)
