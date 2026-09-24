"""Evaluate Git includes on controller-owned snapshots, never arbitrary live includes.

Only configuration queries are run. Native Git evaluates include conditions and
ordering on copied relevant entries; original include paths are never delegated
to Git's recursive loader. This also preserves the original origin of each value.
"""
from pathlib import Path
from tempfile import TemporaryDirectory
import os
import time

from tooluseproxy.engine.repository_evidence import bounded_read


def rows(raw):
    fields = raw.split(b'\0')
    if fields[-1] != b'' or (len(fields) - 1) % 2:
        raise ValueError('context_config_output_invalid')
    result = []
    for index in range(0, len(fields) - 1, 2):
        origin, row = (field.decode('utf-8') for field in fields[index:index + 2])
        key, separator, value = row.partition('\n')
        result.append((origin, key, value if separator else None))
    return result


def quote(value):
    return '"' + value.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n').replace('\t', '\\t').replace('\b', '\\b') + '"'


def entry(key, value):
    parent, name = key.rsplit('.', 1)
    section, dot, subsection = parent.partition('.')
    header = section + (' ' + quote(subsection) if dot else '')
    return '[' + header + ']\n' + name + ('' if value is None else ' = ' + quote(value)) + '\n'


def expand(initial, root, argv, env, pattern):
    if not any(key.lower().startswith(('include.', 'includeif.')) for _, key, _ in initial):
        return initial
    deadline = time.monotonic() + 10
    budget = 256_000
    clean_env = {k: v for k, v in env.items() if not k.startswith('GIT_CONFIG')}
    clean_env.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull)
    with TemporaryDirectory(prefix='tooluseproxy-config-') as temp:
        base = Path(temp)
        originals = {}
        staged = {}

        def allocate(origin):
            if len(originals) >= 64 or time.monotonic() >= deadline:
                raise ValueError('context_include_budget')
            target = base / str(len(originals))
            originals[str(target)] = origin
            return target

        def load(path):
            nonlocal budget
            # Reject before any read, including symlink aliases to control data.
            if path.name == 'protected_sources.json' or path.resolve().name == 'protected_sources.json':
                target = allocate('forbidden-control-state')
                target.write_text(entry('tooluseproxy.snapshotblocked', 'context_control_state_forbidden'))
                return target
            path = path.resolve()
            if str(path) in staged:
                return staged[str(path)]
            target = allocate('file:' + str(path))
            staged[str(path)] = target  # cycles are evaluated by native Git
            if not path.exists():
                target.write_text('')  # Git ignores missing include files
                return target
            if not path.is_file():
                raise ValueError('context_include_not_file')
            raw = bounded_read([*argv, 'config', '--file', str(path), '--no-includes',
                                '--show-origin', '--null', '--get-regexp', pattern],
                               clean_env, limit=min(64_000, budget), accepted_codes=(0, 1))
            budget -= len(raw)
            if budget <= 0:
                raise ValueError('context_include_budget')
            render(rows(raw), target)
            return target

        def render(values, target):
            lines = []
            for origin, key, value in values:
                if key.lower().startswith(('include.', 'includeif.')):
                    if not key.lower().endswith('.path') or not value or '%(' in value:
                        raise ValueError('context_include_path_unsupported')
                    path = Path(value).expanduser()
                    parent = Path(origin[5:]).parent if origin.startswith('file:') else root
                    if not parent.is_absolute():
                        parent = root / parent
                    if not path.is_absolute():
                        if not origin.startswith('file:'):
                            raise ValueError('context_relative_include_without_file')
                        path = parent / path
                    value = str(load(path))
                    # ./ in gitdir conditions is relative to the ORIGINAL file.
                    for prefix in ('includeif.gitdir:./', 'includeif.gitdir/i:./'):
                        if key.lower().startswith(prefix):
                            key = key[:len(prefix) - 2] + str(parent) + '/' + key[len(prefix):]
                            break
                lines.append(entry(key, value))
            target.write_text(''.join(lines))

        # Preserve source ordering and origin even when one source appears again.
        chunks = []
        for row in initial:
            if not chunks or chunks[-1][0][0] != row[0]:
                chunks.append([])
            chunks[-1].append(row)
        wrapper = base / 'root'
        parts = []
        for chunk in chunks:
            target = allocate(chunk[0][0])
            render(chunk, target)
            parts.append(entry('include.path', str(target)))
        wrapper.write_text(''.join(parts))
        raw = bounded_read([*argv, 'config', '--file', str(wrapper), '--includes',
                            '--show-origin', '--null', '--get-regexp',
                            '(' + pattern + '|^tooluseproxy\\.snapshotblocked$)'],
                           clean_env, limit=64_000, accepted_codes=(0, 1))
        observed = rows(raw)
        for _, key, value in observed:
            if key == 'tooluseproxy.snapshotblocked':
                raise ValueError(value)
        return [(originals.get(origin[5:], origin) if origin.startswith('file:') else origin, key, value)
                for origin, key, value in observed
                if not key.lower().startswith(('include.', 'includeif.'))]
