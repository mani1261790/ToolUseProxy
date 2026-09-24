"""Fresh, bounded invocation facts. Receipts never contain an allow decision.

Adapters expose named facts, not arbitrary commands requested by a model. Cache
keys include the receipt; the same adapter re-observes it before execution.
"""
from pathlib import Path
import os

from tooluseproxy.engine.contracts import literal_words
from tooluseproxy.engine.graph import digest
from tooluseproxy.engine.repository_evidence import bounded_read

CONTRACT = 'invocation-context-v1'
GIT_KEYS = (r'^(push\..*|remote\..*|branch\..*|url\..*|'
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
    argv = ['git', '--no-optional-locks', '-C', str(root)]
    # No includes are opened by Git. An unresolved include is explicitly NOT a
    # complete effective-config observation (including conditional includes).
    raw = bounded_read([*argv, 'config', '--no-includes', '--null', '--get-regexp', GIT_KEYS],
                       env, limit=64_000, accepted_codes=(0, 1))
    settings = []
    for row in raw.split(b'\0'):
        if not row:
            continue
        key, value = row.decode('utf-8').split('\n', 1)
        if key.lower().startswith(('include.', 'includeif.')):
            raise ValueError('context_config_includes_unresolved')
        settings.append(dict(key=key, value=value))
    branch = bounded_read([*argv, 'symbolic-ref', '--quiet', 'HEAD'], env,
                          limit=4096, accepted_codes=(0, 1)).decode('utf-8').strip()
    return dict(settings=settings, head_ref=branch or None,
                settings_scope='system, global, local, worktree and inherited command configuration; ordered, duplicates retained',
                absent_settings='not configured in the observed scopes; standard Git defaults apply')


def unchanged(records):
    prior = records.get('invocation_context')
    return prior is None or (prior['status'] == 'observed' and observe(records) == prior)
