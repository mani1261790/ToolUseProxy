from collections import Counter
import importlib.util
from pathlib import Path

import pytest


spec = importlib.util.spec_from_file_location('public_source_audit', Path(__file__).parents[1] / 'scripts/audit_public_source.py')
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


@pytest.mark.parametrize('text', [
    '/private/tmp/tooluseproxy-task-world-comparison-train-v3.json',
    'task-world-comparison-plan-v3', 'risk-description-with-long-suffix',
])
def test_word_suffix_is_not_an_api_key(text):
    findings = Counter()
    audit._scan_content(text.encode(), findings, Counter(), binary_allowed=False)
    assert findings['openai_key'] == 0


@pytest.mark.parametrize('prefix', ['', '"', "'", '=', 'Bearer ', '/', '\n', 'KEY_', 'key-'])
@pytest.mark.parametrize('project', [False, True])
def test_actual_key_tokens_remain_detected(prefix, project):
    key = 'sk-' + ('proj-' if project else '') + 'a' * 32
    findings = Counter()
    audit._scan_content((prefix + key).encode(), findings, Counter(), binary_allowed=False)
    assert findings['openai_key'] == 1
