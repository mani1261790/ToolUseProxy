"""Research comparison CLI: explicit prepare/evaluate stages, never product activation."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from hook_monitor.evaluation.flow_forecast.confidence import paired_root_interval
from hook_monitor.evaluation.flow_forecast.dataset import read_dataset
from hook_monitor.evaluation.flow_forecast.prefix import ForecastDataError, canonical
from .acceptance import assess
from .ablations import VARIANTS
from .budget import Budget
from .experiment import build_models, evaluate, freeze_plan


MAX_REPORT_BYTES = 64 * 1024 * 1024


def _ablation_benefit(report, variant):
    full = report['models']['sequence']['observe/4']['operating_points']['0.01']
    ablated = report['models'][variant]['observe/4']['operating_points']['0.01']
    if full['threshold'] is None or ablated['threshold'] is None:
        return {'status': 'missing_calibration', 'benefit': None}
    left, right = full['positive_outcomes'], ablated['positive_outcomes']
    paired = {root: float(left[root]) - float(right[root]) for root in set(left) & set(right)
              if left[root] is not None and right[root] is not None}
    interval = paired_root_interval(paired)
    normal_left, normal_right = full['normal_outcomes'], ablated['normal_outcomes']
    common_normal = set(normal_left) & set(normal_right)
    all_known = bool(common_normal) and all(normal_left[k] is not None and normal_right[k] is not None for k in common_normal)
    no_more_false_alarms = (sum(normal_left[k] for k in common_normal) <= sum(normal_right[k] for k in common_normal)
                           if all_known else None)
    benefit = (interval['lower'] > 0 and no_more_false_alarms
               if interval['lower'] is not None and no_more_false_alarms is not None else None)
    return {**interval, 'benefit': benefit, 'no_more_false_alarms': no_more_false_alarms,
            'scope': 'inference_component_removal_not_architecture_retraining'}


def attach_assessment(report, dataset, models, costs, resources, plan, *, generator_evidence=None):
    primary = report['models']['sequence']['observe/4']
    probability = primary['probability']
    operating = primary['operating_points']['0.01']
    calibration = plan['models']['sequence']['conditions']['observe/4']['thresholds']['0.01']
    chosen = report['selected_probability_baseline']
    brier = report['paired_comparisons']['observe/4'][chosen]['brier'] if chosen else {}
    edges = report['paired_comparisons']['observe/4']['frequency']['edge_f1']
    model = models['sequence']
    model_bytes = len((canonical({'model': model.payload(), 'sha256': model.model_digest}) + '\n').encode())
    metrics = {
        'training_roots': len(model.training_roots), 'calibration_normal_roots': calibration['normal_roots'],
        'test_normal_roots': operating['normal_roots'], 'test_positive_roots': operating['positive_roots'],
        'truth_coverage': probability['labeled_rows'] / probability['row_count'] if probability['row_count'] else None,
        'prediction_coverage': probability['coverage'], 'fpr_upper': operating['fpr_upper_95'],
        'recall_lower': operating['recall_lower_95'], 'brier_improvement': brier.get('mean'),
        'paired_brier_lower': brier.get('lower'), 'edge_f1_improvement': edges['mean'],
        'paired_edge_f1_lower': edges['lower'], 'positive_top3_route_coverage': primary['routes']['route_coverage']['mean'],
        'median_early_lead_steps': operating['median_early_lead_steps'], 'training_seconds': costs['sequence'],
        'peak_memory_bytes': resources['peak_process_memory_bytes'],
        'prediction_p95_ms': primary['prediction_p95_ms'], 'model_bytes': model_bytes,
    }
    scored_metrics = {('normal_roots' if key == 'test_normal_roots' else
                       'positive_roots' if key == 'test_positive_roots' else key): value
                      for key, value in metrics.items()}
    test_scored = report['partition'] == 'test' and probability['row_count'] > 0
    if report['partition'] != 'test':
        # Training diagnostics cannot fill heldout sample or performance gates.
        development_costs = {'training_roots', 'calibration_normal_roots', 'training_seconds',
                             'peak_memory_bytes', 'model_bytes'}
        metrics = {key: value if key in development_costs else None for key, value in metrics.items()}
    ablations = {name: _ablation_benefit(report, name) for name in VARIANTS}
    test_prefixes = [p for p in dataset.prefixes if dataset.split.partition(p) == 'test']
    train_prefixes = [p for p in dataset.prefixes if dataset.split.partition(p) == 'train']
    train_tools = {s.tool for b in dataset.branches if dataset.split.partition(b.prefix) == 'train'
                   for s in b.prefix.observations + b.observations}
    test_tools = {s.tool for b in dataset.branches if dataset.split.partition(b.prefix) == 'test'
                  for s in b.prefix.observations + b.observations}
    train_tasks = {p.task_kind for p in train_prefixes}
    test_tasks = {p.task_kind for p in test_prefixes}
    unknown_tasks = {'training_prefixes': sum(p.task_kind == 'unknown' for p in train_prefixes),
                     'test_prefixes': sum(p.task_kind == 'unknown' for p in test_prefixes)}
    unseen_tasks = test_tasks - train_tasks - {'unknown'}
    generalization = {
        'training_tools': sorted(train_tools), 'test_tools': sorted(test_tools),
        'unseen_test_tools': sorted(test_tools - train_tools),
        'training_tasks': sorted(train_tasks), 'test_tasks': sorted(test_tasks),
        'unseen_test_tasks': sorted(unseen_tasks),
        'unknown_task_evidence': unknown_tasks, 'scored_partition': report['partition'],
        'agent_models': {'status': 'not_recorded_in_F01_schema', 'evaluated': False},
        'test_prior_use': 'not_proven_by_a_partition_label',
        'independence': 'component_grouping_verified_but_new_root_ids_are_not_independence_proof',
    }
    if generator_evidence is not None:
        from .generator_strata import PREFIX
        scored = sorted({key[len(PREFIX):] for conditions in report['models'].values()
                         for condition in conditions.values() for key, stratum in condition['strata'].items()
                         if key.startswith(PREFIX) and stratum['probability']['row_count'] > 0})
        generalization['agent_models'] = {**generator_evidence['summary'],
                                          'scored_requested_aliases': scored,
                                          'requested_alias_strata_scored': bool(scored),
                                          'scored_partition': report['partition']}
    conditions = {
        'unused_test_partition': False if report['partition'] == 'train' else None,
        'frozen_calibration_selection': True if chosen else None,
        'independent_root_groups': None,
        'different_tools_evaluated': bool(test_tools - train_tools) if test_scored else None,
        'different_tasks_evaluated': bool(unseen_tasks) if test_scored and not any(unknown_tasks.values()) else None,
        'different_agent_models_evaluated': None,
        'object_identity_ablation_benefit': ablations['without_object_identity']['benefit'] if test_scored else None,
        'parent_relation_ablation_benefit': ablations['without_parent_relations']['benefit'] if test_scored else None,
        'multistep_ablation_benefit': ablations['without_multistep']['benefit'] if test_scored else None,
    }
    report.update({'acceptance': assess(metrics, conditions), 'acceptance_metrics': metrics,
                   'ablation_benefits': ablations, 'generalization': generalization,
                   'costs': {'training_seconds': costs, 'resources': resources, 'sequence_model_bytes': model_bytes},
                   'scored_partition_metrics': {'partition': report['partition'], **scored_metrics},
                   'dataset_summary': dataset.summary()})
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('stage', choices=('prepare', 'evaluate'))
    parser.add_argument('--dataset', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--plan', type=Path)
    parser.add_argument('--collection', type=Path)
    parser.add_argument('--partition', choices=('test', 'train'), default='test')
    args = parser.parse_args(argv)
    if args.output.exists():
        parser.error('output already exists')
    if args.stage == 'prepare' and (args.plan or args.partition != 'test'):
        parser.error('prepare does not accept plan or training smoke')
    if args.stage == 'evaluate' and args.plan is None:
        parser.error('evaluate requires --plan')
    budget = Budget()
    dataset = read_dataset(args.dataset)
    models, costs = build_models(dataset, check_budget=budget.check)
    from . import generator_strata
    collection_sha = generator_strata.collection_identity(args.collection) if args.collection else None
    if args.stage == 'prepare':
        result = freeze_plan(dataset, models, check_budget=budget.check)
        if collection_sha is not None:
            result = {'schema': 1, 'calibration_plan': result, 'generator_collection_sha': collection_sha}
    else:
        with args.plan.open('rb') as stream:
            raw = stream.read(1024 * 1024 + 1)
        if len(raw) > 1024 * 1024:
            raise ForecastDataError('comparison_plan_size_limit')
        plan = json.loads(raw)
        generators = apis = None
        if collection_sha is not None:
            if (type(plan) is not dict or set(plan) != {
                    'schema', 'calibration_plan', 'generator_collection_sha'}
                    or type(plan['schema']) is not int or plan['schema'] != 1
                    or plan['generator_collection_sha'] != collection_sha):
                raise ForecastDataError('comparison_generator_plan_mismatch')
            generators = generator_strata.load(dataset, args.collection, collection_sha, check_budget=budget.check)
            from .api_task_strata import load as load_apis
            apis = load_apis(dataset, args.collection, collection_sha, check_budget=budget.check)
            plan = plan['calibration_plan']
        result = evaluate(dataset, models, plan, partition=args.partition, check_budget=budget.check,
                          generator_groups=generators['group_labels'] if generators else None,
                          api_labels=apis['branch_labels'] if apis else None)
        attach_assessment(result, dataset, models, costs, budget.snapshot(), plan, generator_evidence=generators)
        if apis is not None:
            result['generalization']['closed_api_tasks'] = apis['summary']
    budget.check()
    encoded = canonical(result) + '\n'
    if len(encoded.encode()) > MAX_REPORT_BYTES:
        raise ForecastDataError('comparison_report_size_limit')
    with args.output.open('x', encoding='utf-8') as stream:
        stream.write(encoded)
    print(json.dumps({'stage': args.stage, 'output': str(args.output),
                      'acceptance': result.get('acceptance', {}).get('status')}))


if __name__ == '__main__':
    main()
