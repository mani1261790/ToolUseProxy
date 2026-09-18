"""Group-level split manifest; shared prefixes and declared variants stay together."""
from __future__ import annotations

from dataclasses import dataclass

from .prefix import ForecastDataError, Prefix, digest, identifier


PARTITIONS = ('train', 'calibration', 'test')


@dataclass(frozen=True)
class SplitManifest:
    assignments: tuple[tuple[str, str, str], ...]  # prefix id, component id, partition
    seed: str
    dataset_digest: str

    @property
    def digest(self):
        return digest([self.seed, self.dataset_digest, self.assignments])

    def partition(self, prefix: Prefix) -> str:
        for prefix_id, _, partition in self.assignments:
            if prefix_id == prefix.prefix_id:
                return partition
        raise ForecastDataError('prefix_not_in_frozen_split')


def split_prefixes(prefixes: tuple[Prefix, ...], *, seed: str,
                   related_roots: tuple[tuple[str, str], ...] = ()) -> SplitManifest:
    """Union roots, equivalent snapshots and explicit shortened/paraphrased relatives.

    This function makes a complete manifest, not incremental row assignments.
    Changing the collection changes its digest and requires a new frozen dataset.
    """
    identifier(seed)
    if (type(prefixes) is not tuple or not 1 <= len(prefixes) <= 10000
            or any(type(p) is not Prefix for p in prefixes)):
        raise ForecastDataError('invalid_split_input')
    unique = {p.prefix_id: p for p in prefixes}
    roots = {p.root_case_id for p in prefixes}
    parent = {root: root for root in roots}

    def find(root):
        while parent[root] != root:
            parent[root] = parent[parent[root]]
            root = parent[root]
        return root

    def union(a, b):
        a, b = find(a), find(b)
        parent[max(a, b)] = min(a, b)

    if type(related_roots) is not tuple or len(related_roots) > 10000:
        raise ForecastDataError('invalid_related_roots')
    for pair in related_roots:
        if type(pair) is not tuple or len(pair) != 2 or any(x not in roots for x in pair):
            raise ForecastDataError('unknown_related_root')
        union(*pair)
    by_snapshot = {}
    for prefix in prefixes:
        previous = by_snapshot.setdefault(prefix.snapshot_digest, prefix.root_case_id)
        union(previous, prefix.root_case_id)
    rows = []
    for prefix in sorted(unique.values(), key=lambda p: p.prefix_id):
        component = find(prefix.root_case_id)
        bucket = int(digest([seed, component])[:16], 16) % 100
        partition = 'train' if bucket < 80 else 'calibration' if bucket < 90 else 'test'
        rows.append((prefix.prefix_id, component, partition))
    identity = digest([sorted(unique), sorted(related_roots)])
    return SplitManifest(tuple(rows), seed, identity)


def verify_split(manifest: SplitManifest, prefixes: tuple[Prefix, ...], *,
                 related_roots: tuple[tuple[str, str], ...] = ()) -> None:
    expected = split_prefixes(prefixes, seed=manifest.seed, related_roots=related_roots)
    if manifest != expected:
        raise ForecastDataError('split_manifest_mismatch')
