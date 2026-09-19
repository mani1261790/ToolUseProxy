"""Snapshot supplied catalog history and reject known origins in holdout roles."""
from copy import deepcopy
import hashlib
import re

from hook_monitor.evaluation.flow_forecast.dataset import MAX_ARTIFACT_BYTES, _read, _json
from hook_monitor.evaluation.flow_forecast.prefix import ForecastDataError, canonical, digest
from .catalog_history import catalog_metadata
from .task_catalog import MAX_INPUTS, MAX_DESIGNS, design_groups


def freeze(prior):
    if type(prior) is not tuple or not 1 <= len(prior) <= MAX_INPUTS:
        raise ForecastDataError('invalid_cohort_history')
    result=[]
    for path in prior:
        catalog, identity = catalog_metadata(path)
        seal = _json(_read(path/'collection.json'))
        raw = _read(path/'task-catalog.json')
        if (digest(seal) != identity or hashlib.sha256(raw).hexdigest() != seal['catalog_sha']
                or canonical(_json(raw)) != canonical(catalog) or catalog_metadata(path)[1] != identity):
            raise ForecastDataError('cohort_history_changed')
        result.append({'collection_identity':identity, 'seal':seal, 'catalog_text':raw.decode('utf-8')})
        if len(canonical(result).encode()) > MAX_ARTIFACT_BYTES:
            raise ForecastDataError('cohort_history_size_limit')
    return result


def known_designs(catalog, history):
    if type(history) is not list or not 1 <= len(history) <= MAX_INPUTS:
        raise ForecastDataError('invalid_cohort_history')
    if len(canonical(history).encode()) > MAX_ARTIFACT_BYTES:
        raise ForecastDataError('cohort_history_size_limit')
    sources, identities = [catalog], set()
    try:
        for item in history:
            if type(item) is not dict or set(item) != {'collection_identity','seal','catalog_text'}:
                raise ValueError
            seal = item['seal']
            if (type(seal) is not dict or set(seal) != {'schema','dataset_digest','catalog_sha','evidence_sha','origin_shas'}
                    or type(seal['schema']) is not int or seal['schema'] != 1
                    or type(seal['origin_shas']) is not list or len(seal['origin_shas']) > MAX_DESIGNS
                    or type(item['catalog_text']) is not str or digest(seal) != item['collection_identity']
                    or item['collection_identity'] in identities):
                raise ValueError
            for value in [seal[k] for k in ('dataset_digest','catalog_sha','evidence_sha')] + seal['origin_shas']:
                if type(value) is not str or re.fullmatch('[a-f0-9]{64}',value) is None:
                    raise ValueError
            identities.add(item['collection_identity'])
            raw = item['catalog_text'].encode()
            if hashlib.sha256(raw).hexdigest() != seal['catalog_sha']:
                raise ValueError
            parsed = _json(raw)
            design_groups(parsed)
            if sorted({r['origin']['artifact_sha'] for r in parsed['designs']}) != seal['origin_shas']:
                raise ValueError
            sources.append(parsed)
        rows, owner = [], {}
        for index, source in enumerate(sources):
            design_groups(source)
            renamed = {r['id']:f'c{index}-d{n}' for n,r in enumerate(source['designs'])}
            for row in source['designs']:
                copy=deepcopy(row)
                copy['id']=renamed[row['id']]
                copy['parents']=[renamed[key] for key in row['parents']]
                rows.append(copy)
                owner[copy['id']]=(index,row['id'])
            if len(rows) > MAX_DESIGNS:
                raise ForecastDataError('cohort_history_design_limit')
        groups=design_groups({'schema':1,'designs':rows})
        previous={group for key,group in groups.items() if owner[key][0] != 0}
        return sorted(owner[key][1] for key,group in groups.items() if owner[key][0] == 0 and group in previous)
    except (KeyError,TypeError,ValueError,UnicodeError) as error:
        if isinstance(error,ForecastDataError):
            raise
        raise ForecastDataError('invalid_cohort_history') from error
