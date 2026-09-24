"""Fresh, bounded invocation facts. Receipts never contain an allow decision.

Adapters expose named facts, not arbitrary commands requested by a model. Cache
keys include the receipt; the same adapter re-observes it before execution.
"""
from pathlib import Path
import os

from tooluseproxy.engine.contracts import literal_words
from tooluseproxy.engine.graph import digest
from tooluseproxy.engine.repository_evidence import bounded_read

CONTRACT = 'invocation-context-v3'
GIT_KEYS = (r'^(push\..*|remote\..*|branch\..*|url\..*|submodule\..*|'
            r'include\..*|includeif\..*|extensions\.worktreeconfig)$')


def observe(records):
    words = literal_words(records.get('tool_name'), records.get('tool_input'))
    if not words or words[:2] != ['git', 'push']:
        return None
    binding = {key: records.get(key) for key in
               ('tool_name', 'tool_input', 'resolved_cwd', 'workspace_root')}
    receipt = dict(contract=CONTRACT, adapter='git-push-config-v1',
                   binding=digest(binding), status='unavailable', facts={},
                   boundary='Hook environment; hidden shell startup changes are not observed')
    try:
        receipt['facts'] = git_facts(records['resolved_cwd'])
        receipt['status'] = 'observed'
    except (OSError, ValueError) as error:
        # Never leak subprocess output or settings in diagnostics.
        receipt['reason'] = str(error) if isinstance(error, ValueError) else type(error).__name__
    return receipt


def git_facts(cwd):
    root = Path(cwd)
    if not root.is_absolute() or root.resolve() != root:
        raise ValueError('context_cwd_not_canonical')
    env = {k: v for k, v in os.environ.items() if k in (
        'PATH', 'HOME', 'LANG', 'TMPDIR', 'SYSTEMROOT', 'XDG_CONFIG_HOME',
        'GIT_CONFIG_GLOBAL', 'GIT_CONFIG_SYSTEM', 'GIT_CONFIG_NOSYSTEM',
        'GIT_CONFIG_COUNT', 'GIT_CONFIG_PARAMETERS') or
        k.startswith(('GIT_CONFIG_KEY_', 'GIT_CONFIG_VALUE_'))}
    if any(os.environ.get(k) for k in ('GIT_DIR', 'GIT_WORK_TREE', 'GIT_COMMON_DIR', 'GIT_CONFIG')):
        raise ValueError('context_repository_environment_unsupported')
    # Keep configuration scopes intact. Unlike object reads, suppressing global
    # configuration here would conceal the very settings being observed.
    home = Path(env.get('HOME', str(Path.home())))
    paths = [root / '.git/config', root / '.git/config.worktree', home / '.gitconfig',
             Path(env.get('XDG_CONFIG_HOME', str(home / '.config'))) / 'git/config',
             Path(env.get('GIT_CONFIG_GLOBAL', '/dev/null')),
             Path(env.get('GIT_CONFIG_SYSTEM', '/etc/gitconfig'))]
    if any(p.name == 'protected_sources.json' or p.resolve().name == 'protected_sources.json' for p in paths):
        raise ValueError('context_control_state_forbidden')
    if not (root / '.git').is_dir() or (root / '.git').is_symlink():
        raise ValueError('context_repository_metadata_unsupported')
    argv = ['git', '--no-pager', '--no-optional-locks', '-C', str(root)]
    # Recursive loading is evaluated only on controller-owned snapshots.
    raw = bounded_read([*argv, 'config', '--no-includes', '--show-origin', '--null', '--get-regexp', GIT_KEYS],
                       env, limit=64_000, accepted_codes=(0, 1))
    settings = []
    from tooluseproxy.engine.config_snapshot import rows, expand
    values = expand(rows(raw), root, argv, env, GIT_KEYS)
    origins = {}
    for origin, key, value in values:
        if origin.startswith('file:'):
            path = Path(origin[5:])
            path = (path if path.is_absolute() else root / path).resolve()
            if path.name == 'protected_sources.json':
                raise ValueError('context_control_state_forbidden')
            origins[f'/invocation_context/facts/settings/{len(settings)}/value'] = dict(
                path=str(path), projection=dict(kind='git_config_value', key=key, value=value))
        settings.append(dict(key=key, value=value))
    # Reading HEAD directly cannot invoke Git's live include loader.
    from tooluseproxy.engine.payload import open_resource
    with open_resource(root, '.git/HEAD') as (descriptor, _, __):
        head = os.read(descriptor, 4097).decode('utf-8').strip()
    if len(head) > 4096:
        raise ValueError('context_head_budget')
    branch = head[5:] if head.startswith('ref: refs/heads/') else None
    if branch is None and not (len(head) in (40, 64) and all(c in '0123456789abcdef' for c in head)):
        raise ValueError('context_head_unsupported')
    origins['/invocation_context/facts/head_ref'] = dict(path=str(root / '.git/HEAD'),
                                                       projection=dict(kind='git_head_ref', value=branch))
    return dict(settings=settings, head_ref=branch or None, origins=origins,
                settings_scope='system, global, local, worktree and inherited command configuration; ordered, duplicates retained',
                absent_settings='not configured in the observed scopes; standard Git defaults apply')


def unchanged(records):
    prior = records.get('invocation_context')
    return prior is None or (prior['status'] == 'observed' and observe(records) == prior)
