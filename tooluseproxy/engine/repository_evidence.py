"""Bounded local Git object observation, without checkout, fetch, or tool dispatch.

The snapshot is the reachable object closure, an upper bound on network payload:
objects already held by the receiver may not be retransmitted. It is never called
by parsing a command; a model supplies the explicit revision to inspect.
"""
from __future__ import annotations

import os
from pathlib import Path
import re
import selectors
import subprocess
import time


class SnapshotUnavailable(ValueError):
    pass


def git_read(root, *args, limit=1_048_576):
    env = {k:v for k,v in os.environ.items() if k in ('PATH','HOME','LANG','TMPDIR','SYSTEMROOT')}
    env.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull,
               GIT_NO_REPLACE_OBJECTS='1', GIT_NO_LAZY_FETCH='1', GIT_TERMINAL_PROMPT='0')
    argv = ['git','--no-optional-locks','-c','core.fsmonitor=false',
            '-c','core.hooksPath='+os.devnull,'-C',str(root),*args]
    return bounded_read(argv, env, limit=limit)


def bounded_read(argv, env, *, limit, accepted_codes=(0,)):
    """Run only controller-owned read queries, with bounded output and lifetime."""
    with subprocess.Popen(argv, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                          stderr=subprocess.DEVNULL) as child:
        result = bytearray()
        deadline = time.monotonic()+10
        with selectors.DefaultSelector() as selector:
            selector.register(child.stdout, selectors.EVENT_READ)
            try:
                while True:
                    if not selector.select(max(0,deadline-time.monotonic())):
                        raise SnapshotUnavailable('repository_read_timeout')
                    chunk = os.read(child.stdout.fileno(), min(65536,limit+1-len(result)))
                    if not chunk:
                        break
                    result.extend(chunk)
                    if len(result)>limit:
                        raise SnapshotUnavailable('repository_evidence_budget')
                try:
                    code = child.wait(timeout=max(0.01,deadline-time.monotonic()))
                except subprocess.TimeoutExpired:
                    raise SnapshotUnavailable('repository_read_timeout') from None
                if code not in accepted_codes:
                    raise SnapshotUnavailable('repository_read_failed')
            finally:
                if child.poll() is None:
                    child.kill()
                    child.wait()
    return bytes(result)


def snapshot(root, revision, *, max_bytes, max_objects=128):
    root = Path(root)
    if (not isinstance(revision,str) or len(revision)>200
            or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_./~^{}-]*',revision)):
        raise SnapshotUnavailable('invalid_repository_revision')
    # Worktree gitfiles and alternates need an explicit administrative boundary;
    # do not follow them as ordinary workspace file references.
    metadata=root/'.git'
    if metadata.is_symlink() or not metadata.is_dir():
        raise SnapshotUnavailable('repository_metadata_not_local_directory')
    if (metadata/'objects/info/alternates').exists() or (metadata/'shallow').exists():
        raise SnapshotUnavailable('repository_object_closure_incomplete')
    if git_read(root,'rev-parse','--show-toplevel').decode().strip()!=str(root.resolve()):
        raise SnapshotUnavailable('repository_root_mismatch')
    oid=git_read(root,'rev-parse','--verify',revision+'^{commit}').decode().strip()
    commits=git_read(root,'rev-list','--max-count='+str(max_objects+1),oid).decode().splitlines()
    if len(commits)>max_objects:
        raise SnapshotUnavailable('repository_object_budget')
    config=git_read(root,'config','--local','--no-includes','--list').lower()
    if b'.promisor=' in config or b'extensions.partialclone=' in config or list((metadata/'objects/pack').glob('*.promisor')):
        raise SnapshotUnavailable('repository_requires_remote_objects')
    blobs={}
    trees=set()
    for commit in commits:
        trees.add(git_read(root,'rev-parse',commit+'^{tree}').decode().strip())
        tree=git_read(root,'ls-tree','-rtz','--full-tree',commit)
        for row in tree.split(b'\0'):
            if not row:
                continue
            meta,path=row.split(b'\t',1)
            mode,kind,identity=meta.decode().split()
            if kind=='commit':
                continue  # Gitlinks transmit only the recorded object ID, not submodule contents.
            if kind=='tree':
                trees.add(identity)
                continue
            if kind!='blob':
                raise SnapshotUnavailable('repository_object_kind')
            name=path.decode('utf-8',errors='strict')
            if Path(name).name=='protected_sources.json':
                raise SnapshotUnavailable('control_state_not_payload')
            blobs.setdefault(identity,set()).add(name)
    if len(commits)+len(blobs)+len(trees)>max_objects:
        raise SnapshotUnavailable('repository_object_budget')
    parts=[]
    for kind,identities in [('commit',commits),('tree',sorted(trees)),('blob',blobs)]:
        for identity in identities:
            size=int(git_read(root,'cat-file','-s',identity))
            if size>max_bytes:
                raise SnapshotUnavailable('repository_evidence_budget')
            content=git_read(root,'cat-file',kind,identity,limit=max_bytes)
            max_bytes-=len(content)
            parts.append(dict(kind=kind,oid=identity,content=content,
                              paths=sorted(blobs[identity]) if kind=='blob' else []))
    if git_read(root,'rev-parse','--verify',revision+'^{commit}').decode().strip()!=oid:
        raise SnapshotUnavailable('repository_revision_changed')
    return oid,parts
