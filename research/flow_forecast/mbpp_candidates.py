"""Inspect pinned MBPP training tasks without executing reference code or tests.

Candidate tests are JSON input/output examples, not verified task or flow labels.
This module never grants execution permission or claims task independence.
"""
import argparse
import ast
from collections import Counter
import hashlib
from pathlib import Path

from hook_monitor.evaluation.flow_forecast.dataset import _json, _read
from hook_monitor.evaluation.flow_forecast.prefix import ForecastDataError, canonical, digest

COMMIT = '4700efb9afa54286b0e04473ba80a13e8461e25f'
SOURCE_SHA = 'ccf64ceae9c5403bf50a044cb6d505bfd2a2963ee58338ba268fd65beab92a9f'


def _plain(value):
    if type(value) in (str, int, bool, type(None)):
        return True
    if type(value) is list:
        return all(_plain(child) for child in value)
    if type(value) is dict:
        return all(type(key) is str and _plain(child) for key, child in value.items())
    return False


def inspect_task(row):
    """Recognize a single function and literal equality examples, without eval."""
    if (type(row) is not dict or set(row) != {'task_id', 'text', 'code', 'test_setup_code',
                                            'test_list', 'challenge_test_list'}
            or type(row['task_id']) is not int or not 601 <= row['task_id'] <= 974
            or any(type(row[key]) is not str for key in ('text', 'code', 'test_setup_code'))
            or type(row['test_list']) is not list or not 1 <= len(row['test_list']) <= 20
            or any(type(test) is not str for test in row['test_list'])
            or type(row['challenge_test_list']) is not list):
        raise ForecastDataError('invalid_mbpp_training_task')
    result = {'task_id': row['task_id'], 'record_sha': digest(row),
              'reference_sha': hashlib.sha256(row['code'].encode()).hexdigest(),
              'status': 'unsupported', 'reason': None}
    try:
        if row['test_setup_code'].strip():
            raise ValueError('setup_code_required')
        tree = ast.parse(row['code'])
        if len(tree.body) != 1 or not isinstance(tree.body[0], ast.FunctionDef):
            raise ValueError('not_single_function')
        function = tree.body[0]
        arguments = function.args
        if (function.decorator_list or function.returns is not None or arguments.posonlyargs
                or arguments.kwonlyargs or arguments.vararg or arguments.kwarg or arguments.defaults
                or any(arg.annotation is not None for arg in arguments.args)):
            raise ValueError('unsupported_function_signature')
        cases = []
        for source in row['test_list']:
            test = ast.parse(source)
            if len(test.body) != 1 or not isinstance(test.body[0], ast.Assert) or test.body[0].msg is not None:
                raise ValueError('not_literal_equality_test')
            comparison = test.body[0].test
            if (not isinstance(comparison, ast.Compare) or len(comparison.ops) != 1
                    or not isinstance(comparison.ops[0], ast.Eq) or not isinstance(comparison.left, ast.Call)):
                raise ValueError('not_literal_equality_test')
            call = comparison.left
            if (not isinstance(call.func, ast.Name) or call.func.id != function.name
                    or call.keywords or len(call.args) != len(arguments.args)):
                raise ValueError('unsupported_test_call')
            try:
                inputs = [ast.literal_eval(arg) for arg in call.args]
                expected = ast.literal_eval(comparison.comparators[0])
            except (ValueError, TypeError):
                raise ValueError('nonliteral_test_values') from None
            if not _plain(inputs) or not _plain(expected):
                raise ValueError('non_json_test_values')
            cases.append({'arguments': inputs, 'expected': expected})
        # Retain source names/structure: this hash finds exact AST copies only.
        # Different hashes MUST NOT be used as independent-group evidence.
        result.update(status='candidate', function=function.name, cases=cases,
                      reference_ast_sha=digest(ast.dump(tree, include_attributes=False)),
                      challenge_tests_checked=False, execution_verified=False)
    except SyntaxError:
        result['reason'] = 'invalid_python_syntax'
    except ValueError as error:
        result['reason'] = str(error)
    return result


def inventory(path):
    raw = _read(path)
    if len(raw) > 1024 * 1024 or hashlib.sha256(raw).hexdigest() != SOURCE_SHA:
        raise ForecastDataError('mbpp_source_digest_mismatch')
    rows = [_json(line) for line in raw.splitlines()]
    if (len(rows) != 974 or any(type(row) is not dict or type(row.get('task_id')) is not int for row in rows)
            or sorted(row['task_id'] for row in rows) != list(range(1, 975))):
        raise ForecastDataError('invalid_mbpp_source_records')
    # Only the upstream training partition is inspected as development material.
    tasks = [inspect_task(row) for row in rows if 601 <= row['task_id'] <= 974]
    return {'schema': 1, 'source_commit': COMMIT, 'source_sha': SOURCE_SHA,
            'scope': 'upstream_training_static_candidate_inventory',
            'source_records': len(rows), 'inspected_training_records': len(tasks),
            'candidate_count': sum(task['status'] == 'candidate' for task in tasks),
            'rejections': dict(sorted(Counter(task['reason'] for task in tasks if task['reason']).items())),
            'tasks': tasks, 'code_executed': False, 'model_calls': 0, 'trials': 0,
            'accepted_independent_groups': 0, 'independence_verified': False,
            'prior_nonuse_verified': False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    args = parser.parse_args(argv)
    print(canonical(inventory(args.source)))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
