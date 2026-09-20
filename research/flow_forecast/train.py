"""Train/save/reload/evaluate a bounded CPU model on a sealed synthetic dataset."""
from __future__ import annotations

import argparse
from collections import defaultdict
from dataclasses import asdict
import json
import math
from pathlib import Path
import platform
import time

from hook_monitor.evaluation.flow_forecast.calibration import ProbabilitySample, probability_scores
from hook_monitor.evaluation.flow_forecast.dataset import read_dataset
from hook_monitor.evaluation.flow_forecast.labels import label_future
from hook_monitor.evaluation.flow_forecast.metrics import score_routes
from hook_monitor.evaluation.flow_forecast.predictions import HORIZONS
from hook_monitor.evaluation.flow_forecast.prefix import ForecastDataError, canonical, digest
from hook_monitor.evaluation.flow_forecast.protocol import PROTOCOL_SHA256, load_protocol
from .artifacts import load_model, save_model
from .budget import Budget
from .model import fit


MAX_PREDICTION_BYTES = 64 * 1024 * 1024


def score(model, dataset, *, partition='test', check_budget=None):
    if partition not in {'train', 'calibration', 'test'}:
        raise ForecastDataError('invalid_model_evaluation_partition')
    assignments = {p: (root, part) for p, root, part in dataset.split.assignments}
    records, conditions = [], {}
    artifact_bytes = 0
    for mode in ('observe', 'enforce'):
        for horizon in HORIZONS:
            samples, paths, times = [], defaultdict(list), []
            unknown_paths = 0
            for branch in dataset.branches:
                root, part = assignments[branch.prefix.prefix_id]
                if part != partition or branch.policy_mode != mode or branch.sampling != 'fixed_distribution':
                    continue
                if check_budget:
                    check_budget()
                started = time.perf_counter()
                prediction = model.generate(branch.prefix, policy_mode=mode, horizon=horizon)
                times.append((time.perf_counter() - started) * 1000)
                truth = label_future(branch, horizon)
                actual = None if truth.protected_arrival == 'unknown' else truth.protected_arrival == 'yes'
                samples.append(ProbabilitySample(root, prediction.forecast.protected_probability,
                                                 actual, branch.probability))
                route_score = score_routes(prediction.forecast, branch)
                if route_score['edge_f1'] is not None:
                    paths[root].append((branch.probability, route_score['edge_f1']))
                else:
                    unknown_paths += route_score['status'] == 'unknown_truth'
                row = {'prefix_id': branch.prefix.prefix_id, 'branch_id': branch.branch_id,
                       'component': root, 'prediction': asdict(prediction),
                       'truth': truth.protected_arrival, 'routes': route_score}
                artifact_bytes += len(canonical(row).encode()) + 1
                if artifact_bytes > MAX_PREDICTION_BYTES:
                    raise ForecastDataError('prediction_artifact_limit')
                records.append(row)
            root_f1 = {root: sum(w * value for w, value in values) / sum(w for w, _ in values)
                       for root, values in paths.items()}
            times.sort()
            conditions[f'{mode}/{horizon}'] = {
                'status': 'scored' if samples else 'insufficient_evaluation_roots',
                'probability': probability_scores(tuple(samples)),
                'edge_f1_by_root': root_f1,
                'edge_f1': sum(root_f1.values()) / len(root_f1) if root_f1 else None,
                'unknown_route_rows': unknown_paths,
                'prediction_p95_ms': times[math.ceil(.95 * len(times)) - 1] if times else None,
            }
    return {'partition': partition, 'conditions': conditions, 'predictions_digest': digest(records),
            'prediction_rows': len(records), 'model_sha256': model.model_digest,
            'scope': 'training_smoke_only' if partition == 'train' else f'{partition}_scoring',
            'adoption': 'not_assessed_do_not_adopt'}, records


def _write(path, value):
    with path.open('x', encoding='utf-8') as stream:
        stream.write(canonical(value) + '\n')


def run(dataset_path: Path, output: Path, *, partition='test', seconds=300, memory_bytes=1024**3):
    load_protocol()
    budget = Budget(seconds=seconds, memory_bytes=memory_bytes)
    output.mkdir(parents=False, exist_ok=False)
    _write(output / 'intent.json', {'status': 'pending', 'synthetic_only': True,
                                  'partition': partition, 'protocol_sha256': PROTOCOL_SHA256})
    try:
        dataset = read_dataset(dataset_path)
        budget.check()
        start = budget.snapshot()
        model = fit(dataset, check_budget=budget.check)
        trained = budget.snapshot()
        saved = save_model(model, output / 'model.json')
        restored = load_model(output / 'model.json')
        report, records = score(restored, dataset, partition=partition, check_budget=budget.check)
        # Recompute with the pre-save model. Compare only deterministic predictions,
        # not process time or RSS. No additional training or holdout tuning occurs.
        original, _ = score(model, dataset, partition=partition, check_budget=budget.check)
        if report['predictions_digest'] != original['predictions_digest']:
            raise ForecastDataError('model_reload_prediction_mismatch')
        with (output / 'predictions.jsonl').open('x', encoding='utf-8') as stream:
            for row in records:
                stream.write(canonical(row) + '\n')
        budget.check()
        report.update({'status': 'completed', 'synthetic_only': True, 'model': saved,
                       'dataset_digest': digest(asdict(dataset)), 'split_digest': dataset.split.digest,
                       'protocol_sha256': PROTOCOL_SHA256, 'training_roots': list(model.training_roots),
                       'training_wall_seconds': trained['wall_seconds'] - start['wall_seconds'],
                       'training_cpu_seconds': trained['cpu_seconds'] - start['cpu_seconds'],
                       'resources': budget.snapshot(), 'reload_predictions_match': True,
                       'runtime': {'python': platform.python_version(), 'architecture': platform.machine()},
                       'license': 'Apache-2.0', 'external_training_dependencies': []})
        _write(output / 'report.json', report)
        return report
    except (ForecastDataError, OSError, ValueError):
        _write(output / 'failure.json', {'status': 'failed', 'resources': budget.snapshot(),
                                       'resume': 'new_output_directory_required'})
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dataset', required=True, type=Path)
    parser.add_argument('--output-directory', required=True, type=Path)
    parser.add_argument('--partition', choices=('train', 'calibration', 'test'), default='test')
    parser.add_argument('--seconds', type=float, default=300)
    parser.add_argument('--memory-bytes', type=int, default=1024**3)
    args = parser.parse_args(argv)
    result = run(args.dataset, args.output_directory, partition=args.partition,
                 seconds=args.seconds, memory_bytes=args.memory_bytes)
    print(json.dumps({'status': result['status'], 'output_directory': str(args.output_directory),
                      'model_sha256': result['model_sha256'], 'scope': result['scope']}))


if __name__ == '__main__':
    main()
