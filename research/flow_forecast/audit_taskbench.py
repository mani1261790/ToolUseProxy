"""Read-only audit of a pinned public synthetic design pool; never execute tasks."""
from __future__ import annotations

import argparse
import ast
from collections import Counter
import hashlib
import json
from pathlib import Path

from hook_monitor.evaluation.flow_forecast.prefix import ForecastDataError
from research.flow_forecast.task_catalog import GROUPING_METHOD, _flow_signature

COMMIT = '7624cf388b47334ff8a0868e7d862dde18cfda86'
BLOBS = {'data.json': 'ea5e70584a144d1ff7a9a246805bab7c7fe0f511',
         'tool_desc.json': 'c79202fcf0ade9b1f64f8d96ef7f18f180b8a15d',
         'LICENSE': '9e841e7a26e4eb057b24511e7b92d42b257a80e5'}
MAX_BYTES = 16 * 1024 * 1024


def audit(directory):
    documents, files = {}, []
    for name, expected in BLOBS.items():
        path = directory / name
        if path.is_symlink() or not path.is_file():
            raise ForecastDataError('invalid_design_source_file')
        with path.open('rb') as stream:
            raw = stream.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise ForecastDataError('design_source_size_limit')
        blob = hashlib.sha1(f'blob {len(raw)}\0'.encode() + raw).hexdigest()
        if blob != expected:
            raise ForecastDataError('design_source_revision_mismatch')
        documents[name] = raw
        files.append({'name': name, 'bytes': len(raw), 'git_blob_sha': blob,
                      'sha256': hashlib.sha256(raw).hexdigest()})
    library = {row['id'] for row in json.loads(documents['tool_desc.json'])['nodes']}
    counts, signatures, excluded = Counter(), Counter(), Counter()
    lines = documents['data.json'].splitlines()
    if len(lines) > 10000:
        raise ForecastDataError('design_source_record_limit')
    for raw in lines:
        try:
            row = json.loads(raw)
            if any(type(row[key]) is not str or len(row[key]) > 131072 for key in ('tool_nodes', 'tool_links')):
                raise ValueError
            nodes, links = (ast.literal_eval(row[key]) for key in ('tool_nodes', 'tool_links'))
            if type(nodes) is not list or type(links) is not list or not 1 <= len(nodes) <= 100 or len(links) > 100:
                raise ValueError
            names = [node['task'] for node in nodes]
            if any(type(name) is not str for name in names):
                raise ValueError
            if len(set(names)) != len(names):
                excluded['duplicate_tool_node'] += 1
                continue
            if any(link['source'] not in names or link['target'] not in names for link in links):
                excluded['unknown_link_endpoint'] += 1
                continue
            if not set(names) <= library:
                excluded['tool_not_in_pinned_library'] += 1
                continue
            if row['type'] not in ('single', 'chain', 'dag'):
                raise ValueError
            mapping = {name: str(index) for index, name in enumerate(names)}
            # Preserve callable labels, discard arbitrary object identifiers and parameters.
            flow = [[f'in-{mapping[name]}', name, f'out-{mapping[name]}'] for name in names]
            flow += [[f"out-{mapping[link['source']]}", 'declared_dependency',
                      f"in-{mapping[link['target']]}" ] for link in links]
            signatures[_flow_signature({'tools': names, 'flow': flow})] += 1
            counts[row['type']] += 1
        except (KeyError, ValueError, TypeError, SyntaxError, RecursionError):
            excluded['invalid_graph'] += 1
    return {'schema': 1, 'scope': 'public_design_source_structure_audit_not_trials',
            'grouping_method': GROUPING_METHOD,
            'audit_implementation_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'grouping_implementation_sha256': hashlib.sha256(Path(__file__).with_name('task_catalog.py').read_bytes()).hexdigest(),
            'repository': 'microsoft/JARVIS', 'commit': COMMIT,
            'source_subdirectory': 'taskbench/data_dailylifeapis', 'files': files,
            'records': len(lines), 'library_tools': len(library),
            'accepted_structure_records': sum(counts.values()), 'structural_profile_count': len(signatures),
            'profile_size_histogram': {str(k): v for k, v in sorted(Counter(signatures.values()).items())},
            'graph_types': dict(counts), 'excluded_records': dict(excluded),
            'independence_verified': False, 'prior_nonuse_verified': False,
            'trials_executed': 0, 'model_calls': 0, 'accepted_f02_roots': 0,
            'limitations': ['declared_graphs_not_observed_execution', 'dependency_edges_not_verified_information_flow',
                            'structural_profiles_not_semantic_independence', 'public_data_not_asserted_unused_holdout',
                            'no_compatible_runtime_adapter']}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', required=True, type=Path)
    args = parser.parse_args(argv)
    print(json.dumps(audit(args.directory), indent=2))


if __name__ == '__main__':
    main()
