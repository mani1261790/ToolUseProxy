import pytest

from hook_monitor.evaluation.flow_forecast.prefix import ForecastDataError
from research.flow_forecast.provenance import CODE_TREES, source_provenance


def source_tree(tmp_path):
    for tree in CODE_TREES:
        directory = tmp_path / tree
        directory.mkdir(parents=True)
        (directory / '__init__.py').write_text('# synthetic source\n')
    return tmp_path


def test_loader_predictor_and_runtime_changes_are_covered(tmp_path):
    root = source_tree(tmp_path)
    previous = source_provenance(root)
    for path in ('research/flow_forecast/artifacts.py', 'research/flow_forecast/model.py',
                 'research/flow_forecast/tokens.py', 'hook_monitor/runtime.py', 'tooluseproxy/authority.py'):
        (root / path).write_text('# changed synthetic implementation\n')
        current = source_provenance(root)
        assert current['sha256'] != previous['sha256']
        assert path in {row['path'] for row in current['files']}
        previous = current
    (root / 'events.db').write_bytes(b'not source')
    assert source_provenance(root) == previous


def test_linked_python_sources_are_rejected_without_reading_target(tmp_path):
    root = source_tree(tmp_path)
    (root / 'research/flow_forecast/linked.py').symlink_to(root / 'missing-target')
    with pytest.raises(ForecastDataError, match='invalid_source_file'):
        source_provenance(root)


def test_source_budget_does_not_return_partial_identity(tmp_path, monkeypatch):
    root = source_tree(tmp_path)
    monkeypatch.setattr('research.flow_forecast.provenance.MAX_BYTES', 1)
    with pytest.raises(ForecastDataError, match='source_size_limit'):
        source_provenance(root)
