"""Frozen calibration followed by matched, root-level forecast comparisons."""
from __future__ import annotations

from collections import defaultdict
from dataclasses import asdict
import math
import statistics
import time

from hook_monitor.evaluation.flow_forecast.baselines import KINDS, fit_baseline
from hook_monitor.evaluation.flow_forecast.calibration import ProbabilitySample, probability_scores
from hook_monitor.evaluation.flow_forecast.confidence import select_threshold
from hook_monitor.evaluation.flow_forecast.labels import label_future
from hook_monitor.evaluation.flow_forecast.metrics import WarningPoint, score_early_warning, score_routes
from hook_monitor.evaluation.flow_forecast.prefix import ForecastDataError, digest
from hook_monitor.evaluation.flow_forecast.protocol import PROTOCOL_SHA256, load_protocol
from .ablations import Ablation, VARIANTS
from .comparison import CaseScore, operating_point, paired_improvement
from .model import fit


MODEL_NAMES = (*KINDS, 'sequence', *VARIANTS)


def build_models(dataset, *, check_budget=lambda: None):
    models, costs = {}, {}
    for name in KINDS:
        check_budget()
        start = time.perf_counter()
        models[name] = fit_baseline(dataset, name, check_budget=check_budget)
        costs[name] = time.perf_counter() - start
    start = time.perf_counter()
    models['sequence'] = fit(dataset, check_budget=check_budget)
    costs['sequence'] = time.perf_counter() - start
    for name in VARIANTS:
        models[name] = Ablation(models['sequence'], name)
        costs[name] = costs['sequence']  # shared training; not a separately retrained architecture
    check_budget()
    return models, costs


def rows_for(dataset, model, partition, mode, horizon, *, check_budget=lambda: None):
    assignments = {prefix: (root, part) for prefix, root, part in dataset.split.assignments}
    result = []
    for branch in dataset.branches:
        root, part = assignments[branch.prefix.prefix_id]
        if part != partition or branch.policy_mode != mode or branch.sampling != 'fixed_distribution':
            continue
        check_budget()
        start = time.perf_counter()
        forecast = model.predict(branch.prefix, policy_mode=mode, horizon=horizon)
        elapsed = (time.perf_counter() - start) * 1000
        label = label_future(branch, horizon)
        actual = None if label.protected_arrival == 'unknown' else label.protected_arrival == 'yes'
        result.append((branch, root, forecast, actual, score_routes(forecast, branch), elapsed))
    return result


def probability_summary(rows):
    return probability_scores(tuple(ProbabilitySample(root, prediction.protected_probability, actual, branch.probability)
                                    for branch, root, prediction, actual, _, _ in rows))


def calibration_threshold(rows, target):
    roots = defaultdict(list)
    for row in rows:
        roots[row[1]].append(row)
    normals = {}
    for root, group in roots.items():
        truth = [label_future(row[0], 8) for row in group]
        if all(t.protected_arrival == 'no' and not t.censored and not t.unknown_edges for t in truth):
            normals[root] = tuple(row[2].protected_probability for row in group)
    return select_threshold(normals, maximum_fpr=target)


def freeze_plan(dataset, models, *, check_budget=lambda: None):
    if set(models) != set(MODEL_NAMES):
        raise ForecastDataError('incomplete_model_comparison')
    choices, scores = {}, {}
    for name in MODEL_NAMES:
        model = models[name]
        conditions = {}
        for mode in ('observe', 'enforce'):
            for horizon in (1, 2, 4, 8):
                rows = rows_for(dataset, model, 'calibration', mode, horizon, check_budget=check_budget)
                summary = probability_summary(rows)
                conditions[f'{mode}/{horizon}'] = {
                    'probability': summary,
                    'thresholds': {str(target): calibration_threshold(rows, target) for target in (.01, .05)}}
                if (name in KINDS and mode == 'observe' and horizon == 4 and summary['brier'] is not None
                        and summary['coverage'] >= load_protocol()['minimum_prediction_coverage']):
                    scores[name] = summary['brier']
        version = (model.kind + '-' + model.training_digest if name in KINDS else model.version)
        choices[name] = {'version': version, 'conditions': conditions}
    content = {'schema': 1, 'protocol_sha256': PROTOCOL_SHA256, 'dataset_digest': digest(asdict(dataset)),
               'split_digest': dataset.split.digest, 'models': choices,
               'selected_probability_baseline': min(scores, key=lambda n: (scores[n], n)) if scores else None}
    return {**content, 'plan_digest': digest(content)}


def case_scores(rows):
    return tuple(CaseScore(digest([b.prefix.prefix_id, b.branch_id, b.policy_mode, prediction.horizon]),
                           root, b.probability, actual, prediction.protected_probability, route['edge_f1'])
                 for b, root, prediction, actual, route, _ in rows)


def mean_by_root(rows, field):
    roots = defaultdict(list)
    for branch, root, _, _, route, _ in rows:
        if route[field] is not None:
            roots[root].append((branch.probability, route[field]))
    means = {root: math.fsum(w * value for w, value in points) / math.fsum(w for w, _ in points)
             for root, points in roots.items()}
    return {'mean': statistics.mean(means.values()) if means else None, 'roots': means}


def warnings(rows, threshold):
    series = defaultdict(list)
    for row in rows:
        branch = row[0]
        identity = digest([branch.prefix.environment_version, branch.prefix.source_version, branch.prefix.task_kind,
                           [asdict(step) for step in branch.prefix.observations + branch.observations]])
        series[(row[1], branch.prefix.root_case_id, branch.branch_id, identity)].append(row)
    outcomes = defaultdict(list)
    for group in series.values():
        group.sort(key=lambda row: row[0].prefix.max_sequence_no)
        first = group[0][0]
        truth = label_future(first, 8)
        if truth.protected_arrival == 'unknown' or truth.censored or truth.unknown_edges:
            outcomes[group[0][1]].append({'status': 'unknown_truth'})
            continue
        if threshold is None:
            outcomes[group[0][1]].append({'status': 'positive' if truth.protected_arrival == 'yes' else 'negative',
                                          'detected_early': None, 'false_alarm': None, 'lead_steps': None})
            continue
        points = tuple(WarningPoint(r[0].prefix.root_case_id, r[0].branch_id, r[0].policy_mode,
                                    r[0].prefix.max_sequence_no, r[2].protected_probability, r[2].horizon) for r in group)
        end = first.observations[-1].sequence_no if first.observations else first.prefix.max_sequence_no
        if end - first.prefix.max_sequence_no > 8:
            outcomes[group[0][1]].append({'status': 'unsupported_series_length'})
        else:
            outcomes[group[0][1]].append(score_early_warning(first, points, threshold=threshold))
    normal, positive, leads, unknown = {}, {}, [], []
    for root, values in outcomes.items():
        if any(v['status'] not in {'negative', 'positive'} for v in values):
            unknown.append(root)
            continue
        positives = [v for v in values if v['status'] == 'positive']
        if positives:
            flags = [v['detected_early'] for v in positives]
            positive[root] = None if any(f is None for f in flags) else all(flags)
            if positive[root]:
                leads.append(min(v['lead_steps'] for v in positives))
        else:
            flags = [v['false_alarm'] for v in values]
            normal[root] = True if any(f is True for f in flags) else None if any(f is None for f in flags) else False
    operating = operating_point(normal, positive)
    if threshold is None:
        operating.update({'fpr': None, 'fpr_upper_95': None, 'recall': None, 'recall_lower_95': None})
    return {**operating, 'status': 'scored' if threshold is not None else 'missing_calibration_threshold',
            'threshold': threshold,
            'normal_outcomes': normal, 'positive_outcomes': positive, 'unknown_truth_roots': unknown,
            'median_early_lead_steps': statistics.median(leads) if leads else None}


def strata_summary(rows):
    groups = defaultdict(list)
    for row in rows:
        branch = row[0]
        groups['task/' + branch.prefix.task_kind].append(row)
        groups['source-version/' + branch.prefix.source_version].append(row)
        # Future tools label an analysis stratum after prediction; they are never
        # added to the predictor's visible Prefix.
        for tool in {step.tool for step in branch.prefix.observations + branch.observations}:
            groups['tool/' + tool].append(row)
    return {key: {'probability': probability_summary(group),
                  'edge_f1': mean_by_root(group, 'edge_f1'),
                  'route_coverage': mean_by_root(group, 'route_coverage')}
            for key, group in sorted(groups.items())}


def evaluate(dataset, models, plan, *, partition='test', check_budget=lambda: None,
             calibration_dataset=None):
    if partition not in {'test', 'train'}:
        raise ForecastDataError('unsupported_comparison_partition')
    calibration_data = dataset if calibration_dataset is None else calibration_dataset
    if calibration_dataset is not None:
        development_rows = tuple(row for row in dataset.split.assignments if row[2] != 'test')
        development_branches = tuple(b for b in dataset.branches
                                     if dataset.split.partition(b.prefix) != 'test')
        if (calibration_data.split.assignments != development_rows
                or calibration_data.branches != development_branches
                or calibration_data.split.seed != dataset.split.seed
                or calibration_data.provenance != dataset.provenance):
            raise ForecastDataError('comparison_development_mismatch')
    if plan != freeze_plan(calibration_data, models, check_budget=check_budget):
        raise ForecastDataError('comparison_plan_mismatch')
    results, cases = {}, {}
    for name in MODEL_NAMES:
        conditions = {}
        for mode in ('observe', 'enforce'):
            for horizon in (1, 2, 4, 8):
                key = f'{mode}/{horizon}'
                rows = rows_for(dataset, models[name], partition, mode, horizon, check_budget=check_budget)
                cases[name, key] = case_scores(rows)
                times = sorted(row[5] for row in rows)
                conditions[key] = {
                    'probability': probability_summary(rows), 'strata': strata_summary(rows),
                    'routes': {field: mean_by_root(rows, field) for field in ('edge_f1', 'route_coverage', 'candidate_missing')},
                    'operating_points': {target: warnings(rows, value['threshold']) for target, value in
                                         plan['models'][name]['conditions'][key]['thresholds'].items()},
                    'prediction_p95_ms': times[math.ceil(.95 * len(times)) - 1] if times else None,
                }
        results[name] = conditions
    comparisons = {}
    for key in results['sequence']:
        comparisons[key] = {name: {metric: paired_improvement(cases['sequence', key], cases[name, key], metric=metric)
                                  for metric in ('brier', 'edge_f1')}
                            for name in MODEL_NAMES if name != 'sequence'}
    return {'schema': 1, 'partition': partition, 'plan_digest': plan['plan_digest'], 'models': results,
            'paired_comparisons': comparisons, 'scope': 'training_smoke_only' if partition == 'train' else 'heldout_comparison',
            'selected_probability_baseline': plan['selected_probability_baseline'],
            'product_activation_authorized': False}
