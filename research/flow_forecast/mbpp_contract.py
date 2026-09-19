"""Inspect the input capabilities of the three pinned MBPP reference functions.

This is not an execution sandbox, termination proof, or field-causality oracle.
The successful plain-JSON paths assume unmodified Python primitives. Captures
remain raw/unknown until a separately bound projection contract is applied.
"""
import argparse
import ast
import hashlib
from pathlib import Path

from hook_monitor.evaluation.flow_forecast.prefix import ForecastDataError, canonical, digest
from .mbpp_batch import checked, selected

BUILTINS = {'enumerate': (1, 2), 'range': (1, 2, 3), 'len': (1,), 'reversed': (1,)}
METHODS = {'count': (1,), 'append': (1,), 'remove': (1,), 'split': (0,), 'join': (1,)}
NODES = (ast.Module, ast.FunctionDef, ast.arguments, ast.arg, ast.Assign, ast.AugAssign,
         ast.For, ast.While, ast.If, ast.Return, ast.Expr, ast.Name, ast.Load, ast.Store,
         ast.Constant, ast.Tuple, ast.List, ast.Subscript, ast.Slice, ast.BinOp, ast.Add,
         ast.Sub, ast.Compare, ast.Gt, ast.Lt, ast.NotEq, ast.Call, ast.Attribute)


def inspect_program(source):
    """Conservatively reject syntax/capabilities outside the reviewed references."""
    def fail():
        raise ForecastDataError('unsupported_mbpp_computation')
    if type(source) is not str or not 1 <= len(source.encode()) <= 16384:
        fail()
    try:
        tree = ast.parse(source)
        if len(tree.body) != 1 or type(tree.body[0]) is not ast.FunctionDef:
            fail()
        function = tree.body[0]
        args = function.args
        if (function.name in BUILTINS or function.decorator_list or function.returns is not None or args.posonlyargs or args.kwonlyargs
                or args.vararg or args.kwarg or args.defaults or args.kw_defaults
                or any(arg.annotation is not None for arg in args.args)):
            fail()
        pending, nodes, parents = [(tree, 0)], [], {}
        while pending:
            node, depth = pending.pop()
            if type(node) not in NODES or depth > 32 or len(nodes) >= 2048:
                fail()
            if isinstance(node, ast.FunctionDef) and node is not function:
                fail()
            nodes.append(node)
            for child in ast.iter_child_nodes(node):
                parents[id(child)] = node
                pending.append((child, depth + 1))
        bound = {arg.arg for arg in args.args} | {
            node.id for node in nodes if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store)}
        if (not args.args or any(name in BUILTINS or name.startswith('_') for name in bound)
                or len({arg.arg for arg in args.args}) != len(args.args)):
            fail()
        used_builtins, used_methods = set(), set()
        for node in nodes:
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
                if node.id not in bound and node.id not in BUILTINS:
                    fail()
                if node.id in BUILTINS:
                    parent = parents[id(node)]
                    if not isinstance(parent, ast.Call) or parent.func is not node:
                        fail()
            if isinstance(node, ast.Constant) and type(node.value) not in (str, int, bool, type(None)):
                fail()
            if isinstance(node, ast.Attribute):
                parent = parents[id(node)]
                if (node.attr not in METHODS or not isinstance(parent, ast.Call) or parent.func is not node):
                    fail()
            if isinstance(node, ast.Call):
                if node.keywords:
                    fail()
                if isinstance(node.func, ast.Name) and node.func.id in BUILTINS:
                    allowed = BUILTINS[node.func.id]
                    used_builtins.add(node.func.id)
                elif isinstance(node.func, ast.Attribute) and node.func.attr in METHODS:
                    allowed = METHODS[node.func.attr]
                    used_methods.add(node.func.attr)
                else:
                    fail()
                if len(node.args) not in allowed:
                    fail()
        return {'schema': 1, 'contract': 'pinned-mbpp-input-capabilities-v1',
                'program_sha': hashlib.sha256(source.encode()).hexdigest(),
                'external_values': ['plain_json_arguments'], 'builtins': sorted(used_builtins),
                'methods': sorted(used_methods), 'scope': 'input_capabilities_not_field_causality',
                'assumptions': ['unmodified Python primitives', 'plain JSON arguments', 'successful execution'],
                'termination_proven': False, 'timing_and_exception_flows_evaluated': False,
                'execution_authorized': False, 'semantic_truth_promoted': False}
    except (SyntaxError, RecursionError) as error:
        raise ForecastDataError('unsupported_mbpp_computation') from error


def inspect_reference(row):
    candidate = checked(row)
    contract = inspect_program(row['code'])
    return {'task_id': row['task_id'], 'record_sha': candidate['record_sha'],
            'candidate_sha': digest(candidate), 'contract': contract,
            'independence_verified': False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True, type=Path)
    args = parser.parse_args(argv)
    result = {'schema': 1, 'references': [inspect_reference(row) for row in selected(args.source)],
              'new_model_calls': 0, 'new_trials': 0, 'semantic_truth_promoted': False}
    print(canonical(result))
    return 0


if __name__ == '__main__':
    main()
