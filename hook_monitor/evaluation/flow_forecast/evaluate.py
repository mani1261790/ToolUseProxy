"""Two-stage, synthetic-only evaluation. Freeze calibration before scoring holdout."""
from __future__ import annotations

import argparse
from collections import defaultdict
from dataclasses import asdict
import json
import math
from pathlib import Path
import resource
import sys
import time

from .baselines import KINDS, fit_baseline
from .calibration import ProbabilitySample, probability_scores, reliability_bins
from .confidence import select_threshold
from .dataset import read_dataset
from .labels import label_future
from .metrics import WarningPoint, score_early_warning, score_routes
from .prefix import ForecastDataError, digest
from .protocol import PROTOCOL_SHA256, load_protocol


def _identity(dataset):
    return digest(asdict(dataset))


def _rows(dataset, model, partition, mode, horizon):
    assignments = {p: (root, part) for p, root, part in dataset.split.assignments}
    rows = []
    for branch in dataset.branches:
        root, part = assignments[branch.prefix.prefix_id]
        if part != partition or branch.policy_mode != mode or branch.sampling != 'fixed_distribution':
            continue
        start = time.perf_counter()
        prediction = model.predict(branch.prefix, policy_mode=mode, horizon=horizon)
        elapsed = (time.perf_counter() - start) * 1000
        label = label_future(branch, horizon)
        actual = None if label.protected_arrival == 'unknown' else label.protected_arrival == 'yes'
        rows.append((branch, root, prediction, actual, elapsed))
    return rows


def _samples(rows):
    return tuple(ProbabilitySample(root, prediction.protected_probability, actual, branch.probability)
                 for branch, root, prediction, actual, _ in rows)


def prepare(dataset):
    """Only training and calibration truth influence model/threshold selection."""
    protocol = load_protocol()
    models, scores = {}, {}
    for kind in KINDS:
        model = fit_baseline(dataset, kind)
        conditions = {}
        for mode in ('observe', 'enforce'):
            for horizon in protocol['horizons']:
                rows = _rows(dataset, model, 'calibration', mode, horizon)
                roots = defaultdict(list)
                for row in rows:
                    roots[row[1]].append(row)
                # A normal root must have fully observed negative continuations,
                # not merely no arrival within this particular short horizon.
                normal = {root: tuple(r[2].protected_probability for r in group)
                          for root, group in roots.items()
                          if all(label_future(r[0], 8).protected_arrival == 'no'
                                 and not label_future(r[0], 8).censored
                                 and not label_future(r[0], 8).unknown_edges for r in group)}
                summary = probability_scores(_samples(rows))
                conditions[f'{mode}/{horizon}'] = {
                    'threshold': select_threshold(normal, maximum_fpr=protocol['primary_maximum_fpr_upper']),
                    'probability': summary,
                }
                if mode == 'observe' and horizon == protocol['primary_horizon']:
                    if summary['coverage'] is not None and summary['coverage'] >= protocol['minimum_prediction_coverage']:
                        if summary['brier'] is not None:
                            scores[kind] = summary['brier']
        models[kind] = {'training_digest': model.training_digest,
                        'training_roots': list(model.training_roots), 'conditions': conditions}
    result = {'schema': 1, 'protocol_sha256': PROTOCOL_SHA256, 'dataset_digest': _identity(dataset),
              'split_digest': dataset.split.digest, 'models': models,
              'selected_probability_baseline': min(scores, key=lambda k: (scores[k], k)) if scores else None,
              'status': 'frozen' if scores else 'insufficient_calibration'}
    return {**result, 'plan_digest': digest(result)}


def _root_means(rows, field):
    groups = defaultdict(list)
    for root, weight, result in rows:
        if result[field] is not None:
            groups[root].append((weight, float(result[field])))
    means = {root: sum(w * value for w, value in points) / sum(w for w, _ in points)
             for root, points in groups.items()}
    return {'mean': sum(means.values()) / len(means) if means else None, 'roots': means}


def evaluate(dataset, plan, *, partition='test'):
    if partition not in {'test', 'train'}:
        raise ForecastDataError('unsupported_evaluation_partition')
    # Recompute from train/calibration, never accept edited operating points.
    if plan != prepare(dataset):
        raise ForecastDataError('frozen_evaluation_plan_mismatch')
    results = {}
    for kind in KINDS:
        started = time.perf_counter()
        model = fit_baseline(dataset, kind)
        training_seconds = time.perf_counter() - started
        conditions = {}
        for mode in ('observe', 'enforce'):
            for horizon in load_protocol()['horizons']:
                key = f'{mode}/{horizon}'
                rows = _rows(dataset, model, partition, mode, horizon)
                samples = _samples(rows)
                routes = [(root, branch.probability, score_routes(prediction, branch))
                          for branch, root, prediction, _, _ in rows]
                timings = sorted(r[4] for r in rows)
                threshold = plan['models'][kind]['conditions'][key]['threshold']['threshold']
                series = defaultdict(list)
                for row in rows:
                    b = row[0]
                    trajectory = digest([b.prefix.environment_version, b.prefix.source_version, b.prefix.task_kind,
                                         [asdict(step) for step in b.prefix.observations + b.observations]])
                    series[(b.prefix.root_case_id, b.branch_id, b.policy_mode, trajectory)].append(row)
                warnings = []
                for group in series.values():
                    group.sort(key=lambda r: r[0].prefix.max_sequence_no)
                    first = group[0][0]
                    if threshold is None:
                        result = {'status': 'no_calibration_threshold'}
                    else:
                        points = tuple(WarningPoint(r[0].prefix.root_case_id, r[0].branch_id, mode,
                                                    r[0].prefix.max_sequence_no, r[2].protected_probability,
                                                    horizon) for r in group)
                        result = score_early_warning(first, points, threshold=threshold)
                    warnings.append({'root': group[0][1], 'branch_id': first.branch_id, **result})
                conditions[key] = {
                    'status': 'scored' if rows else 'insufficient_evaluation_roots',
                    'probability': probability_scores(samples), 'reliability': reliability_bins(samples),
                    'routes': {field: _root_means(routes, field) for field in
                               ('edge_f1', 'route_coverage', 'joint_top_k_hit', 'candidate_missing')},
                    'unknown_route_rows': sum(r[2]['status'] == 'unknown_truth' for r in routes),
                    'early_warnings': warnings,
                    'prediction_p95_ms': timings[math.ceil(.95 * len(timings)) - 1] if timings else None,
                }
        results[kind] = {'training_seconds': training_seconds, 'conditions': conditions}
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return {'schema': 1, 'synthetic_only': True, 'partition': partition,
            'plan_digest': plan['plan_digest'], 'protocol_sha256': PROTOCOL_SHA256,
            'dataset_digest': plan['dataset_digest'], 'models': results,
            'peak_process_memory_bytes': peak if sys.platform == 'darwin' else peak * 1024,
            'adoption': 'not_assessed_do_not_adopt',
            'scope': 'training_smoke_only' if partition == 'train' else 'heldout_baseline_scoring'}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('stage', choices=('prepare', 'evaluate'))
    parser.add_argument('--dataset', required=True, type=Path)
    parser.add_argument('--plan', type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--partition', choices=('test', 'train'), default='test')
    args = parser.parse_args(argv)
    if args.output.exists():
        parser.error('output already exists')
    dataset = read_dataset(args.dataset)
    if args.stage == 'prepare':
        if args.plan or args.partition != 'test':
            parser.error('prepare does not accept plan or training smoke')
        result = prepare(dataset)
    else:
        if args.plan is None:
            parser.error('evaluate requires a frozen --plan')
        if args.plan.stat().st_size > 1024 * 1024:
            parser.error('plan exceeds size limit')
        result = evaluate(dataset, json.loads(args.plan.read_text()), partition=args.partition)
    with args.output.open('x', encoding='utf-8') as stream:
        json.dump(result, stream, ensure_ascii=False, indent=2, allow_nan=False)
        stream.write('\n')
    print(json.dumps({'output': str(args.output), 'stage': args.stage}))


if __name__ == '__main__':
    main()
