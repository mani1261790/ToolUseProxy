"""Bounded, sealed synthetic datasets with separate input and truth files."""
from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
import hashlib
import json
import math
import os
from pathlib import Path
import stat

from .branches import Continuation, Transfer, UNKNOWN_RELATIONS
from .labels import label_future
from .prefix import ForecastDataError, InformationObject, ObservedStep, Prefix, canonical, digest
from .splits import SplitManifest, PlannedSplitManifest, split_prefixes, split_planned, verify_split


FILES = ('inputs.json', 'targets.json', 'splits.json', 'summary.json')
MAX_ARTIFACT_BYTES = 32 * 1024 * 1024
# Aggregate research artifact capacity; execution batches retain their own F02 limits.
MAX_BRANCHES = 20000


@dataclass(frozen=True)
class Dataset:
    branches: tuple[Continuation, ...]
    split: SplitManifest
    related_roots: tuple[tuple[str, str], ...] = ()
    provenance: str = 'synthetic-reference-v1'

    def __post_init__(self):
        if (type(self.branches) is not tuple or not 1 <= len(self.branches) <= MAX_BRANCHES
                or any(type(b) is not Continuation for b in self.branches)
                or self.provenance not in {'synthetic-reference-v1', 'synthetic-flow-lab-v1'}):
            raise ForecastDataError('invalid_dataset')
        verify_split(self.split, self.prefixes, related_roots=self.related_roots)
        identities, controls, distributions = set(), defaultdict(dict), defaultdict(list)
        for branch in self.branches:
            key = (branch.prefix.prefix_id, branch.branch_id, branch.policy_mode)
            if key in identities:
                raise ForecastDataError('duplicate_continuation')
            identities.add(key)
            control_key = (branch.prefix.prefix_id, branch.control_group, branch.branch_id)
            controls[control_key][branch.policy_mode] = branch
            if branch.sampling == 'fixed_distribution':
                distributions[(branch.prefix.prefix_id, branch.policy_mode)].append(branch.probability)
        for pair in controls.values():
            if set(pair) != {'observe', 'enforce'}:
                if all(b.sampling == 'adaptive_search' for b in pair.values()):
                    continue  # Historical searches have no invented counterfactual branch.
                raise ForecastDataError('missing_paired_control')
            left, right = pair['observe'], pair['enforce']
            if ((left.sampling, left.probability, left.replay_kind) !=
                    (right.sampling, right.probability, right.replay_kind)):
                raise ForecastDataError('control_conditions_mismatch')
            if left.replay_kind == 'fixed_replay':
                shared = min(len(left.observations), len(right.observations))
                if left.observations[:shared] != right.observations[:shared]:
                    raise ForecastDataError('fixed_control_prefix_mismatch')
        if any(not math.isclose(sum(values), 1.0, rel_tol=0, abs_tol=1e-9)
               for values in distributions.values()):
            raise ForecastDataError('incomplete_branch_distribution')

    @property
    def prefixes(self):
        return tuple(sorted({b.prefix.prefix_id: b.prefix for b in self.branches}.values(),
                            key=lambda p: p.prefix_id))

    def summary(self):
        labels = Counter()
        conditions = {(b.prefix.prefix_id, b.branch_id, b.policy_mode) for b in self.branches}
        unknown = Counter({kind: 0 for kind in UNKNOWN_RELATIONS})
        for branch in self.branches:
            for horizon in (1, 2, 4, 8):
                label = label_future(branch, horizon)
                labels[f'{branch.policy_mode}/{horizon}/{label.protected_arrival}'] += 1
            unknown.update(edge.relation for edge in branch.transfers if edge.evidence == 'unknown')
        return {
            'schema': 1, 'synthetic_only': True, 'provenance': self.provenance,
            'prefix_count': len(self.prefixes), 'continuation_count': len(self.branches),
            'root_count': len({p.root_case_id for p in self.prefixes}),
            'group_count': len({row[1] for row in self.split.assignments}),
            'split_prefix_counts': dict(Counter(row[2] for row in self.split.assignments)),
            'termination_counts': dict(Counter(b.termination for b in self.branches)),
            'label_counts': dict(sorted(labels.items())),
            'unknown_relation_counts': dict(sorted(unknown.items())),
            'deferred_scope': ['semantic_origin', 'selection_influence', 'cross_task_state'],
            'sampling_counts': dict(Counter(b.sampling for b in self.branches)),
            'unpaired_adaptive_count': sum(
                b.sampling == 'adaptive_search' and
                (b.prefix.prefix_id, b.branch_id, 'observe' if b.policy_mode == 'enforce' else 'enforce')
                not in conditions
                for b in self.branches),
        }


def assemble(branches: tuple[Continuation, ...], *, seed='split-v1', related_roots=(),
             provenance='synthetic-reference-v1', planned=None) -> Dataset:
    if (type(branches) is not tuple or not 1 <= len(branches) <= MAX_BRANCHES
            or any(type(branch) is not Continuation for branch in branches)):
        raise ForecastDataError('invalid_dataset')
    prefixes = tuple({b.prefix.prefix_id: b.prefix for b in branches}.values())
    if planned is not None:
        return Dataset(branches, split_planned(prefixes, seed=seed, related_roots=related_roots,
                       plan_sha=planned[0], root_assignments=planned[1]), related_roots, provenance)
    return Dataset(branches, split_prefixes(prefixes, seed=seed,
                                           related_roots=related_roots), related_roots, provenance)


def _documents(dataset):
    inputs = [{'prefix_id': p.prefix_id, 'root_case_id': p.root_case_id,
               'snapshot_digest': p.snapshot_digest, 'input': p.model_input()} for p in dataset.prefixes]
    targets = []
    for branch in dataset.branches:
        value = asdict(branch)
        del value['prefix']
        value['prefix_id'] = branch.prefix.prefix_id
        targets.append(value)
    splits = {**asdict(dataset.split), 'related_roots': dataset.related_roots}
    return dict(zip(FILES, (inputs, targets, splits, dataset.summary())))


def write_dataset(dataset: Dataset, directory: Path) -> str:
    """Create a new directory; manifest is written last as the completion seal."""
    if type(dataset) is not Dataset:
        raise ForecastDataError('invalid_dataset')
    payloads = {name: (canonical(value) + '\n').encode()
                for name, value in _documents(dataset).items()}
    if sum(map(len, payloads.values())) > MAX_ARTIFACT_BYTES:
        raise ForecastDataError('dataset_size_exceeded')
    file_hashes = {name: hashlib.sha256(raw).hexdigest() for name, raw in payloads.items()}
    manifest = {'schema': 1, 'synthetic_only': True, 'files': file_hashes,
                'dataset_digest': digest(file_hashes), 'split_digest': dataset.split.digest,
                'provenance': dataset.provenance}
    payloads['manifest.json'] = (canonical(manifest) + '\n').encode()
    directory.mkdir(mode=0o700)  # Existing or partially written outputs are never overwritten.
    for name, raw in payloads.items():
        fd = os.open(directory / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    return manifest['dataset_digest']


def _read(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_ARTIFACT_BYTES:
            raise ForecastDataError('invalid_artifact_file')
        raw = stream.read(MAX_ARTIFACT_BYTES + 1)
        if len(raw) > MAX_ARTIFACT_BYTES:
            raise ForecastDataError('dataset_size_exceeded')
        return raw


def _json(raw):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ForecastDataError('duplicate_json_key')
            value[key] = item
        return value
    def invalid(_):
        raise ForecastDataError('nonfinite_json_number')
    return json.loads(raw, object_pairs_hook=unique, parse_constant=invalid)


def _step(value):
    return ObservedStep(**{**value, 'inputs': tuple(value['inputs']), 'outputs': tuple(value['outputs'])})


def read_dataset(directory: Path) -> Dataset:
    """Validate all files, identities, labels and group splits before returning data."""
    try:
        if directory.is_symlink() or not directory.is_dir():
            raise ForecastDataError('invalid_dataset_directory')
        if {p.name for p in directory.iterdir()} != {*FILES, 'manifest.json'}:
            raise ForecastDataError('incomplete_or_unknown_artifact')
        manifest = _json(_read(directory / 'manifest.json'))
        if (set(manifest) != {'schema', 'synthetic_only', 'files', 'dataset_digest', 'split_digest', 'provenance'}
                or type(manifest['schema']) is not int or manifest['schema'] != 1
                or manifest['synthetic_only'] is not True or set(manifest['files']) != set(FILES)
                or digest(manifest['files']) != manifest['dataset_digest']):
            raise ForecastDataError('invalid_dataset_manifest')
        documents, total = {}, 0
        for name in FILES:
            raw = _read(directory / name)
            total += len(raw)
            if total > MAX_ARTIFACT_BYTES:
                raise ForecastDataError('dataset_size_exceeded')
            if hashlib.sha256(raw).hexdigest() != manifest['files'][name]:
                raise ForecastDataError('artifact_digest_mismatch')
            documents[name] = _json(raw)
        if (not isinstance(documents['inputs.json'], list)
                or not 1 <= len(documents['inputs.json']) <= MAX_BRANCHES
                or not isinstance(documents['targets.json'], list)
                or not 1 <= len(documents['targets.json']) <= MAX_BRANCHES):
            raise ForecastDataError('invalid_dataset_record_count')
        prefixes = {}
        for row in documents['inputs.json']:
            if set(row) != {'prefix_id', 'root_case_id', 'snapshot_digest', 'input'}:
                raise ForecastDataError('invalid_input_envelope')
            fields = row['input']
            if set(fields) != {'schema', 'max_sequence_no', 'observations', 'objects',
                               'capabilities', 'environment_version', 'source_version',
                               'protected_sources', 'task_kind'}:
                raise ForecastDataError('unknown_model_input_field')
            prefix = Prefix(**{**fields, 'root_case_id': row['root_case_id'],
                               'observations': tuple(_step(s) for s in fields['observations']),
                               'objects': tuple(InformationObject(**o) for o in fields['objects']),
                               'capabilities': tuple(fields['capabilities']),
                               'protected_sources': tuple(fields['protected_sources'])})
            if (prefix.prefix_id != row['prefix_id'] or prefix.snapshot_digest != row['snapshot_digest']
                    or prefix.prefix_id in prefixes):
                raise ForecastDataError('input_identity_mismatch')
            prefixes[prefix.prefix_id] = prefix
        branches = []
        for row in documents['targets.json']:
            values = dict(row)
            prefix = prefixes[values.pop('prefix_id')]
            for key in ('observations', 'objects', 'transfers'):
                parser = {'observations': _step, 'objects': lambda x: InformationObject(**x),
                          'transfers': lambda x: Transfer(**x)}[key]
                values[key] = tuple(parser(x) for x in values[key])
            values['receiver_arrivals'] = tuple(tuple(x) for x in values['receiver_arrivals'])
            values['protected_sources'] = tuple(values['protected_sources'])
            branches.append(Continuation(prefix=prefix, **values))
        split_data = dict(documents['splits.json'])
        related = tuple(tuple(x) for x in split_data.pop('related_roots'))
        split_data['assignments'] = tuple(tuple(x) for x in split_data['assignments'])
        manifest_type = SplitManifest
        if 'plan_sha' in split_data:
            manifest_type = PlannedSplitManifest
            split_data['root_assignments'] = tuple(tuple(x) for x in split_data['root_assignments'])
        dataset = Dataset(tuple(branches), manifest_type(**split_data), related, manifest['provenance'])
        if ({p.prefix_id for p in dataset.prefixes} != set(prefixes)
                or dataset.split.digest != manifest['split_digest']
                or dataset.summary() != documents['summary.json']):
            raise ForecastDataError('dataset_summary_mismatch')
        return dataset
    except ForecastDataError:
        raise
    except (OSError, TypeError, ValueError, KeyError, AttributeError, RecursionError) as exc:
        raise ForecastDataError('invalid_dataset_artifact') from exc
