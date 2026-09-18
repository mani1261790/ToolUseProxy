from copy import deepcopy
from dataclasses import replace
import json
import hashlib

import pytest

from hook_monitor.evaluation.flow_forecast.dataset import assemble, read_dataset, write_dataset
from hook_monitor.evaluation.flow_forecast.prefix import ForecastDataError
from research.flow_forecast.task_catalog import collect, design_groups, main, read_origins, read_collection
from test_flow_forecast_dataset import branches


def design(key, *, parent=None, tool='http', origin='a'):
    return {'id': key, 'objective': '人工データだけで依頼を完了する',
            'origin': {'kind': 'derived' if parent else 'new_design',
                       'artifact_sha': origin * 64, 'rationale': 'テスト用の設計由来'},
            'parents': [parent] if parent else [], 'tools': [tool],
            'flow': [['synthetic-source', 'copy', 'working-memory'],
                     ['working-memory', tool, 'synthetic-receiver']],
            'success': '公開の人工データが受信された',
            'receiver_check': '独立受信側で人工値の到達を観測する'}


def dataset(root, snapshot=None):
    base = branches()
    prefix = replace(base[0].prefix, root_case_id=root, source_version=snapshot or root)
    return assemble(tuple(replace(b, prefix=prefix) for b in base))


def catalog(*values):
    return {'schema': 1, 'designs': list(values)}


def test_renaming_prose_and_order_do_not_create_independent_groups():
    first, second = design('original'), design('renamed', origin='b')
    second['objective'] = '違う表現、違うseedだと主張しても同じ処理'
    second['flow'].reverse()
    groups = design_groups(catalog(first, second))
    assert len(set(groups.values())) == 1
    data, evidence = collect(catalog(first, second), (
        (dataset('root-1'), {'root-1': 'original'}),
        (dataset('root-2'), {'root-2': 'renamed'})))
    assert len({row[1] for row in data.split.assignments}) == 1
    assert evidence['declared_design_count'] == 2
    assert evidence['grouped_root_count'] == 1
    assert evidence['independence_verified'] is False


def test_parent_origin_and_equivalent_snapshot_all_join_groups():
    values = catalog(design('a'), design('b', parent='a', tool='file', origin='b'),
                     design('c', tool='mail'), design('d', tool='pipe', origin='d'))
    assert design_groups(values) == {'a': 'a', 'b': 'a', 'c': 'a', 'd': 'd'}
    data, report = collect(values, (
        (dataset('one', 'shared'), {'one': 'a'}),
        (dataset('two', 'shared'), {'two': 'd'})))
    assert len({row[1] for row in data.split.assignments}) == 1
    assert report['origin_artifacts_verified'] is False


def test_missing_unknown_duplicate_binding_rejected():
    values = catalog(design('a'))
    for mapping in ({}, {'one': 'unknown'}, {'one': 'a', 'invented': 'a'}):
        with pytest.raises(ForecastDataError, match='binding_mismatch'):
            collect(values, ((dataset('one'), mapping),))
    with pytest.raises(ForecastDataError, match='duplicate_collection_root'):
        collect(values, ((dataset('one'), {'one': 'a'}),) * 2)


def test_invalid_and_cyclic_origins_are_not_accepted():
    cases = [catalog(design('a', parent='missing')), catalog(design('a'), design('a')),
             catalog(design('a', parent='b'), design('b', parent='a'))]
    bad = design('a')
    bad['origin']['independence_verified'] = True
    cases.append(catalog(bad))
    for value in cases:
        with pytest.raises(ForecastDataError):
            design_groups(value)


def test_cli_keeps_catalog_and_binding_evidence_with_new_dataset(tmp_path):
    source = tmp_path / 'source'
    write_dataset(dataset('one'), source)
    cat = tmp_path / 'catalog.json'
    origins = tmp_path / 'origins'
    origins.mkdir()
    content = b'Synthetic design for the CLI roundtrip fixture.'
    identity = hashlib.sha256(content).hexdigest()
    (origins / (identity + '.md')).write_bytes(content)
    row = design('a')
    row['origin']['artifact_sha'] = identity
    cat.write_text(json.dumps(catalog(row)))
    inputs = tmp_path / 'inputs.json'
    inputs.write_text(json.dumps([{'directory': str(source), 'roots': {'one': 'a'}}]))
    output = tmp_path / 'output'
    args = ['--catalog', str(cat), '--inputs', str(inputs), '--output', str(output),
            '--origins', str(origins)]
    main(args)
    restored = read_dataset(output / 'dataset')
    evidence = json.loads((output / 'collection-evidence.json').read_text())
    assert evidence['origin_artifacts_verified'] is True
    assert evidence['independence_verified'] is False
    assert (output / 'origins' / (identity + '.md')).read_bytes() == content
    assert evidence['split_sha'] == restored.split.digest
    assert evidence['bindings'][0]['root_case_id'] == 'one'
    assert json.loads((output / 'task-catalog.json').read_text()) == json.loads(cat.read_text())
    assert read_collection(output)[0] == restored
    assert 'origin' not in restored.prefixes[0].model_input()
    with pytest.raises(FileExistsError):
        main(args)
    (output / 'collection-evidence.json').write_text('{}')
    with pytest.raises(ForecastDataError, match='document_mismatch'):
        read_collection(output)
    (output / 'collection.json').unlink()
    with pytest.raises(ForecastDataError, match='incomplete_collection'):
        read_collection(output)


def test_unknown_fields_and_unhashable_input_fail_closed():
    value = catalog(design('a'))
    unknown, malformed = deepcopy(value), deepcopy(value)
    unknown['unexpected'] = True
    malformed['designs'][0]['tools'] = [{}]
    for changed in (unknown, malformed):
        with pytest.raises(ForecastDataError):
            design_groups(changed)


def test_origin_documents_are_verified_without_trusting_the_claim(tmp_path):
    content = b'Synthetic origin document'
    identity = hashlib.sha256(content).hexdigest()
    row = design('a')
    row['origin']['artifact_sha'] = identity
    path = tmp_path / (identity + '.md')
    path.write_bytes(content + b' altered')
    with pytest.raises(ForecastDataError, match='digest_mismatch'):
        read_origins(catalog(row), tmp_path)
    path.unlink()
    elsewhere = tmp_path / 'other.md'
    elsewhere.write_bytes(content)
    path.symlink_to(elsewhere)
    with pytest.raises(OSError):
        read_origins(catalog(row), tmp_path)


def test_aggregate_limits_apply_before_building_the_collection(monkeypatch):
    from research.flow_forecast import task_catalog
    samples = ((dataset('one'), {'one': 'a'}), (dataset('two'), {'two': 'a'}))
    monkeypatch.setattr(task_catalog, 'MAX_BRANCHES', 4)
    with pytest.raises(ForecastDataError, match='collection_size_limit'):
        collect(catalog(design('a')), samples)
    monkeypatch.setattr(task_catalog, 'MAX_BRANCHES', 2000)
    monkeypatch.setattr(task_catalog, 'MAX_ARTIFACT_BYTES', 1)
    with pytest.raises(ForecastDataError, match='collection_size_limit'):
        collect(catalog(design('a')), samples)
