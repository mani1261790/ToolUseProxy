"""Check a small computation language whose only external value is plain JSON.

This is a syntactic capability check, not a Python sandbox or a proof of field-
level causality, termination, task independence, or provider identity. Never run
untrusted Python merely because this check accepts it.
"""
import ast
import hashlib

from hook_monitor.evaluation.flow_forecast.prefix import ForecastDataError


BUILTINS = {'dict', 'range', 'all', 'any', 'sum'}
METHODS = {'get': (1, 2), 'append': (1,), 'values': (0,)}
FORBIDDEN_BINDINGS = BUILTINS | {'source', 'Path', 'json', 'sys'}


class Checker:
    def fail(self):
        raise ForecastDataError('unsupported_closed_computation')

    def target(self, node, bound):
        if isinstance(node, ast.Name):
            if node.id in FORBIDDEN_BINDINGS or node.id.startswith('_'):
                self.fail()
            return {node.id}
        if isinstance(node, (ast.Tuple, ast.List)):
            return set().union(*(self.target(child, bound) for child in node.elts))
        if isinstance(node, ast.Subscript):
            self.expr(node.value, bound)
            self.expr(node.slice, bound)
            return set()
        self.fail()

    def expr(self, node, bound):
        if isinstance(node, ast.Name):
            if node.id not in bound:
                self.fail()
        elif isinstance(node, ast.Constant):
            if type(node.value) not in (str, int, bool, type(None)):
                self.fail()
        elif isinstance(node, (ast.List, ast.Tuple)):
            for child in node.elts:
                self.expr(child, bound)
        elif isinstance(node, ast.Dict):
            if any(key is None for key in node.keys):
                self.fail()
            for child in node.keys + node.values:
                self.expr(child, bound)
        elif isinstance(node, ast.Subscript):
            self.expr(node.value, bound)
            self.expr(node.slice, bound)
        elif isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Sub)):
            self.expr(node.left, bound)
            self.expr(node.right, bound)
        elif isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.Not, ast.UAdd, ast.USub)):
            self.expr(node.operand, bound)
        elif isinstance(node, ast.BoolOp):
            for child in node.values:
                self.expr(child, bound)
        elif isinstance(node, ast.Compare):
            if any(not isinstance(op, (ast.Eq, ast.NotEq, ast.Lt, ast.LtE, ast.Gt, ast.GtE, ast.Is, ast.IsNot)) for op in node.ops):
                self.fail()
            for child in [node.left, *node.comparators]:
                self.expr(child, bound)
        elif isinstance(node, ast.IfExp):
            for child in (node.test, node.body, node.orelse):
                self.expr(child, bound)
        elif isinstance(node, ast.Call):
            if node.keywords or any(isinstance(arg, ast.Starred) for arg in node.args):
                self.fail()
            if isinstance(node.func, ast.Name):
                if node.func.id not in BUILTINS or len(node.args) != 1:
                    self.fail()
            elif isinstance(node.func, ast.Attribute):
                if node.func.attr not in METHODS or len(node.args) not in METHODS[node.func.attr]:
                    self.fail()
                self.expr(node.func.value, bound)
            else:
                self.fail()
            for child in node.args:
                self.expr(child, bound)
        elif isinstance(node, ast.GeneratorExp):
            local = set(bound)
            for generator in node.generators:
                if generator.is_async:
                    self.fail()
                self.expr(generator.iter, local)
                local.update(self.target(generator.target, local))
                for condition in generator.ifs:
                    self.expr(condition, local)
            self.expr(node.elt, local)
        else:
            self.fail()

    def statements(self, nodes, bound, *, in_loop=False):
        bound = set(bound)
        for node in nodes:
            if isinstance(node, ast.Assign):
                self.expr(node.value, bound)
                for target in node.targets:
                    bound.update(self.target(target, bound))
            elif isinstance(node, ast.AugAssign) and isinstance(node.op, (ast.Add, ast.Sub)):
                self.expr(node.target, bound)
                self.expr(node.value, bound)
                bound.update(self.target(node.target, bound))
            elif isinstance(node, ast.For):
                if node.orelse:
                    self.fail()
                self.expr(node.iter, bound)
                local = bound | self.target(node.target, bound)
                self.statements(node.body, local, in_loop=True)
                # A loop may execute zero times. Its new names are not definite.
            elif isinstance(node, ast.If):
                self.expr(node.test, bound)
                left = self.statements(node.body, bound, in_loop=in_loop)
                right = self.statements(node.orelse, bound, in_loop=in_loop)
                bound |= left & right
            elif isinstance(node, ast.Expr):
                self.expr(node.value, bound)
            elif isinstance(node, ast.Assert):
                if node.msg is not None:
                    self.fail()
                self.expr(node.test, bound)
            elif isinstance(node, (ast.Break, ast.Continue)) and in_loop:
                pass
            else:
                self.fail()
        return bound


def validate_program(program):
    if type(program) is not str or not 1 <= len(program.encode()) <= 16384:
        raise ForecastDataError('invalid_computation_program')
    try:
        tree = ast.parse(program)
        pending, count = [(tree, 0)], 0
        while pending:
            node, depth = pending.pop()
            count += 1
            if count > 2048 or depth > 32:
                raise ForecastDataError('computation_syntax_limit')
            pending.extend((child, depth + 1) for child in ast.iter_child_nodes(node))
        if 'result' not in Checker().statements(tree.body, {'source'}):
            raise ForecastDataError('computation_result_not_definite')
    except (SyntaxError, RecursionError) as error:
        raise ForecastDataError('invalid_computation_syntax') from error
    return {'schema': 1, 'contract': 'json-input-only-computation-v1',
            'program_sha': hashlib.sha256(program.encode()).hexdigest(),
            'external_values': ['source'], 'builtins': sorted(BUILTINS),
            'assumptions': ['source_is_plain_json', 'unmodified_python_builtins', 'trusted_execution_wrapper'],
            'scope': 'syntactic_input_capabilities_not_field_level_causality',
            'semantic_truth_promoted': False}
