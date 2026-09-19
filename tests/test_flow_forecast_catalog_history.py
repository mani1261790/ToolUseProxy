import hashlib
from copy import deepcopy

import pytest

from hook_monitor.evaluation.flow_forecast.prefix import ForecastDataError, canonical
from research.flow_forecast import catalog_history as module, compare_holdout
from test_flow_forecast_task_catalog import design, catalog


def metadata(path, rows):
    path.mkdir()
    raw = canonical(catalog(*rows)).encode()
    (path / 'task-catalog.json').write_bytes(raw)
    seal = {'schema': 1, 'dataset_digest': 'd'*64, 'catalog_sha': hashlib.sha256(raw).hexdigest(),
            'evidence_sha': 'e'*64, 'origin_shas': sorted({r['origin']['artifact_sha'] for r in rows})}
    (path / 'collection.json').write_text(canonical(seal))
    # Deliberately no targets or datasets: preflight must need metadata only.
    return path


def test_renamed_mechanics_cross_collections_are_not_unseen(tmp_path):
    old = metadata(tmp_path/'old', [design('one')])
    new = metadata(tmp_path/'new', [design('renamed', origin='b')])
    result = module.audit(new, (old,))
    assert result['status'] == 'known_related_origins'
    assert result['overlap'][0]['design'] == 'renamed'
    assert result['targets_read'] is False
    assert result['prior_nonuse_verified'] is False
    with pytest.raises(ForecastDataError, match='known_related'):
        module.require_no_known_overlap(new, (old,))


def test_no_match_never_certifies_independence_or_complete_history(tmp_path):
    old = metadata(tmp_path/'old', [design('one')])
    new = metadata(tmp_path/'new', [design('one', tool='different', origin='b')])
    result = module.require_no_known_overlap(new, (old,))
    assert result['status'] == 'no_match_in_supplied_history'
    assert result['independence_verified'] is False
    assert result['history_complete'] is False


def test_parent_bridges_and_shared_origins_join_across_catalogs(tmp_path):
    old = metadata(tmp_path/'old', [design('one')])
    first = design('root', tool='different')
    child = design('child', parent='root', tool='third', origin='b')
    new = metadata(tmp_path/'new', [first, child])
    assert {r['design'] for r in module.audit(new,(old,))['overlap']} == {'root','child'}


def test_duplicates_and_changed_catalog_refused(tmp_path):
    old = metadata(tmp_path/'old', [design('one')])
    new = metadata(tmp_path/'new', [design('two')])
    with pytest.raises(ForecastDataError, match='duplicate_prior'):
        module.audit(new,(old,old))
    (old/'task-catalog.json').write_text('{}')
    with pytest.raises(ForecastDataError, match='catalog_changed'):
        module.audit(new,(old,))


def test_history_checked_before_any_bundle_or_target_read(tmp_path,monkeypatch):
    old = metadata(tmp_path/'old', [design('one')])
    new = metadata(tmp_path/'new', [design('two')])
    def forbidden(*a):
        pytest.fail('bundle read before known-origin preflight')
    monkeypatch.setattr(compare_holdout,'read_manifest',forbidden)
    with pytest.raises(ForecastDataError, match='known_related'):
        compare_holdout.prepare(tmp_path/'absent',collection=new,prior_collections=(old,))
    with pytest.raises(ForecastDataError, match='history_requires_collection'):
        compare_holdout.prepare(tmp_path/'absent',prior_collections=(old,))


def test_metadata_mutation_during_audit_refused(tmp_path,monkeypatch):
    old = metadata(tmp_path/'old', [design('one')])
    new = metadata(tmp_path/'new', [design('two',tool='different',origin='b')])
    original = module.catalog_metadata
    count = 0
    def changing(path):
        nonlocal count
        row, identity = original(path)
        count += 1
        return deepcopy(row), ('f'*64 if count > 2 else identity)
    monkeypatch.setattr(module,'catalog_metadata',changing)
    with pytest.raises(ForecastDataError, match='collection_changed'):
        module.audit(new,(old,))
