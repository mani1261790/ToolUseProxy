"""Acquire explicitly requested, bounded definition evidence; never execute it."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from tooluseproxy.engine.payload import open_resource, fingerprint
import os
import stat


def acquire(records, requests, *, budget=128_000):
    node = records['current_call']
    root = Path(node['workspace_root'])
    runtime = Path(__file__).resolve().parents[2]
    # Runtime code is available only when the recorded operation references it.
    # This is an evidence-read capability, not an execution/allow exception.
    owners = [node, *records.get('previous_calls', [])]
    runtime_owners = [n for n in owners if str(runtime) + '/' in json.dumps(n.get('input'), ensure_ascii=False)]
    roots = [root]
    if runtime_owners:
        roots.append(runtime)
    results = []
    for request in requests:
        path = request['path']
        outcome = dict(path=path, reason=request['reason'], status='unavailable')
        try:
            candidate = Path(path)
            if not candidate.is_absolute():
                candidate = root / candidate
            selected = next((r for r in roots if candidate.is_relative_to(r)), None)
            if selected is None:
                raise ValueError('outside_evidence_roots')
            relative = str(candidate.relative_to(selected))
            if selected == runtime and selected != root:
                allowed = (relative in ('tooluseproxy_plugin.py', 'hooks/run_cli.sh', 'hooks/run_cli.cmd')
                           or (relative.startswith('tooluseproxy/') and candidate.suffix in ('.py', '.js', '.css', '.html')))
                if not allowed:
                    raise ValueError('not_a_runtime_definition')
            with open_resource(str(selected), relative) as (fd, _, _):
                before = os.fstat(fd)
                if not stat.S_ISREG(before.st_mode) or before.st_size > budget:
                    raise ValueError('definition_budget_or_type')
                data = os.read(fd, budget + 1)
                if len(data) > budget or fingerprint(before) != fingerprint(os.fstat(fd)):
                    raise ValueError('definition_changed_or_large')
            budget -= len(data)
            observed_hashes = {n.get('definition_observations', {}).get(str(candidate)) for n in owners}
            observed_hashes.discard(None)
            if len(observed_hashes) > 1:
                raise ValueError('ambiguous_definition_observation')
            observed_hash = next(iter(observed_hashes), None)
            current_hash = hashlib.sha256(data).hexdigest()
            if observed_hash is not None and current_hash != observed_hash:
                raise ValueError('definition_changed_since_observation')
            outcome.update(status='observed', content=data.decode('utf-8'),
                           sha256=hashlib.sha256(data).hexdigest(),
                           temporal_scope='matches_hook_observation' if observed_hash else 'current_definition_not_historical_execution')
        except (ValueError, OSError, UnicodeError) as exc:
            outcome['failure'] = type(exc).__name__
        results.append(outcome)
    return results


def inspect(records, judge, validate, candidates, *, evidence_context=None):
    """Retry only after adding evidence, and retain acquisition outcomes for audit."""
    context = dict(records)
    shared = {} if evidence_context is None else evidence_context
    seen = set()
    receipts = []
    for item in shared.values():
        # Recheck permissions and content identity for the focused producer.
        current = acquire(context, [{'path':item['path'], 'reason':item['reason']}])
        if current and current[0].get('sha256') == item.get('sha256') and current[0]['status'] == 'observed':
            receipts.extend(current)
            seen.add(item['path'])
    if receipts:
        context['execution_definitions'] = list(receipts)
    validation_failure = None
    for _ in range(8):
        raw = judge(context)
        try:
            value = validate(raw, candidates)
        except ValueError as exc:
            if _ == 7 or validation_failure == str(exc):
                raise
            validation_failure = str(exc)
            context['validation_feedback'] = dict(error=str(exc),
                instruction='Return a corrected schema-valid assessment; do not change evidence or invent paths. Accesses must be canonical filesystem paths, never URLs.')
            continue
        requests = value.get('evidence_requests', [])
        if value['complete'] or not requests:
            break
        pending = [r for r in requests if r['path'] not in seen]
        if not pending:
            break
        seen.update(r['path'] for r in pending)
        acquired = acquire(context, pending)
        receipts.extend(acquired)
        for item in acquired:
            shared[item['path']] = item
        context['execution_definitions'] = list(receipts)
    # Contents belong in request evidence, not the displayed verdict.
    if receipts:
        value = dict(value, evidence_receipts=[{k:v for k,v in r.items() if k != 'content'} for r in receipts])
    return value


def reusable(value, node):
    receipts = value.get('evidence_receipts', [])
    if not receipts:
        return True
    refreshed = acquire({'current_call': node}, [{'path':r['path'], 'reason':r['reason']} for r in receipts])
    return [{k:v for k,v in r.items() if k != 'content'} for r in refreshed] == receipts


def observe_runtime_definitions(tool_input):
    """Record the available runtime's code identity at the Hook observation.

    This observes files, not execution. Models must still establish which definitions
    were invoked. Only product code under the current runtime is eligible, never
    workspace files, configuration, credentials, or arbitrary absolute paths.
    """
    runtime = Path(__file__).resolve().parents[2]
    if str(runtime) + '/' not in json.dumps(tool_input, ensure_ascii=False):
        return {}
    paths = list((runtime/'tooluseproxy').rglob('*.py'))
    paths += [p for p in (runtime/'tooluseproxy/viewer').glob('*') if p.suffix in ('.js', '.css', '.html')]
    paths += [runtime/'tooluseproxy_plugin.py', runtime/'hooks/run_cli.sh', runtime/'hooks/run_cli.cmd']
    result = {}
    for path in paths:
        try:
            with open_resource(str(runtime), str(path.relative_to(runtime))) as (fd, _, _):
                before = os.fstat(fd)
                if not stat.S_ISREG(before.st_mode) or before.st_size > 256_000:
                    continue
                data = os.read(fd, 256_001)
                if fingerprint(before) != fingerprint(os.fstat(fd)) or len(data) > 256_000:
                    continue
            result[str(path)] = hashlib.sha256(data).hexdigest()
        except (OSError, ValueError):
            continue
    return result


def resource_identity(path, workspace):
    """Canonical resource name; external identities do not authorize reading bytes."""
    if not isinstance(path, str) or not path or '\x00' in path:
        raise ValueError('invalid_resource_identity')
    candidate = Path(path)
    if candidate.name == 'protected_sources.json':
        raise ValueError('control_state_not_resource_evidence')
    root = Path(workspace).resolve()
    if not candidate.is_absolute():
        from tooluseproxy.engine.payload import safe_parts
        safe_parts(path)
        candidate = root / candidate
    candidate = candidate.resolve()
    if candidate.name == 'protected_sources.json':
        raise ValueError('control_state_not_resource_evidence')
    return str(candidate.relative_to(root)) if candidate.is_relative_to(root) else str(candidate)


def external_generation(path):
    """Metadata-only generation witness; never open/read an external data file."""
    value = Path(path).stat()
    if not stat.S_ISREG(value.st_mode):
        raise ValueError('external_resource_not_regular')
    return fingerprint(value)


def observe_managed_resources(directory, limit=256):
    """Observe names and generations in controller-owned storage, without contents."""
    directory = Path(directory).resolve()
    entries = []
    with os.scandir(directory) as listing:
        for entry in listing:
            if len(entries) >= limit:
                return dict(directory=str(directory), entries=entries, complete=False)
            if entry.name == 'protected_sources.json' or entry.is_symlink():
                continue
            if entry.is_file(follow_symlinks=False):
                entries.append(dict(path=str(directory/entry.name), generation=fingerprint(entry.stat(follow_symlinks=False))))
    return dict(directory=str(directory), entries=entries, complete=True)
