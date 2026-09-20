import hashlib
import json

import pytest

from hook_monitor.evaluation.flow_forecast.prefix import ForecastDataError
from research.flow_forecast import audit_taskbench as module


def source(tmp_path, monkeypatch, rows):
    files = {'data.json': '\n'.join(json.dumps(row) for row in rows).encode(),
             'tool_desc.json': b'{"nodes":[{"id":"read"},{"id":"send"}]}',
             'LICENSE': b'Synthetic license fixture'}
    blobs = {}
    for name, raw in files.items():
        (tmp_path / name).write_bytes(raw)
        blobs[name] = hashlib.sha1(f'blob {len(raw)}\0'.encode() + raw).hexdigest()
    monkeypatch.setattr(module, 'BLOBS', blobs)
    return tmp_path


def row(names=('read', 'send')):
    return {'tool_nodes': repr([{'task': name, 'arguments': {}} for name in names]),
            'tool_links': repr([{'source': names[0], 'target': names[-1]}]), 'type': 'chain'}


def test_pinned_graph_audit_deduplicates_without_certifying_research(tmp_path, monkeypatch):
    data = source(tmp_path, monkeypatch, [row(), row(), row(('unknown', 'send'))])
    report = module.audit(data)
    assert report['records'] == 3 and report['accepted_structure_records'] == 2
    assert report['structural_profile_count'] == 1
    assert report['excluded_records'] == {'tool_not_in_pinned_library': 1}
    assert report['accepted_f02_roots'] == report['trials_executed'] == report['model_calls'] == 0
    assert report['independence_verified'] is report['prior_nonuse_verified'] is False


def test_untrusted_expression_is_rejected_without_execution(tmp_path, monkeypatch):
    marker = tmp_path / 'unexpected'
    bad = row()
    bad['tool_nodes'] = f"__import__('pathlib').Path({str(marker)!r}).touch()"
    report = module.audit(source(tmp_path, monkeypatch, [bad]))
    assert report['excluded_records'] == {'invalid_graph': 1}
    assert not marker.exists()


def test_modified_or_linked_sources_do_not_pass_pinned_digest(tmp_path, monkeypatch):
    data = source(tmp_path, monkeypatch, [row()])
    (data / 'data.json').write_text('{}')
    with pytest.raises(ForecastDataError, match='revision_mismatch'):
        module.audit(data)
    (data / 'data.json').unlink()
    (data / 'data.json').symlink_to(data / 'tool_desc.json')
    with pytest.raises(ForecastDataError, match='invalid_design_source_file'):
        module.audit(data)
