"""Bounded provenance for the complete local application-code trees.

Python sources are hashed, never project configuration, event DBs, or protected
files. The model and Docker context retain their separate recorded identities.
"""
from pathlib import Path
import hashlib
import platform

from hook_monitor.evaluation.flow_forecast.prefix import ForecastDataError, digest


CODE_TREES = ('research/flow_forecast', 'hook_monitor', 'tooluseproxy', 'scripts')
MAX_FILES = 2000
MAX_BYTES = 32 * 1024 * 1024


def source_provenance(root: Path):
    files = []
    remaining = MAX_BYTES
    for tree in CODE_TREES:
        directory = root / tree
        if directory.is_symlink() or not directory.is_dir():
            raise ForecastDataError('source_tree_unavailable')
        for path in sorted(directory.rglob('*.py')):
            if path.is_symlink() or not path.is_file():
                raise ForecastDataError('invalid_source_file')
            if len(files) >= MAX_FILES:
                raise ForecastDataError('source_file_count_limit')
            with path.open('rb') as stream:
                content = stream.read(remaining + 1)
            remaining -= len(content)
            if remaining < 0:
                raise ForecastDataError('source_size_limit')
            files.append({'path': path.relative_to(root).as_posix(),
                          'sha256': hashlib.sha256(content).hexdigest()})
    if not files:
        raise ForecastDataError('source_tree_empty')
    return {'schema': 1, 'files': files, 'sha256': digest(files),
            'python_version': platform.python_version(), 'python_implementation': platform.python_implementation()}
