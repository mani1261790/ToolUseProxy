"""Apply the frozen F02 criteria; missing evidence never becomes a passing gate."""
from __future__ import annotations

import math

from hook_monitor.evaluation.flow_forecast.prefix import ForecastDataError
from hook_monitor.evaluation.flow_forecast.protocol import PROTOCOL_SHA256, load_protocol


# metric, protocol key, comparison, evidence class
RULES = (
    ('training_roots', 'minimum_training_roots', 'ge', 'sample'),
    ('calibration_normal_roots', 'minimum_calibration_normal_roots', 'ge', 'sample'),
    ('test_normal_roots', 'minimum_test_normal_roots', 'ge', 'sample'),
    ('test_positive_roots', 'minimum_test_positive_roots', 'ge', 'sample'),
    ('truth_coverage', 'minimum_truth_coverage', 'ge', 'coverage'),
    ('prediction_coverage', 'minimum_prediction_coverage', 'ge', 'coverage'),
    ('fpr_upper', 'primary_maximum_fpr_upper', 'le', 'performance'),
    ('recall_lower', 'minimum_recall_lower', 'ge', 'performance'),
    ('brier_improvement', 'minimum_brier_improvement', 'ge', 'performance'),
    ('paired_brier_lower', 'minimum_paired_brier_lower', 'gt', 'performance'),
    ('edge_f1_improvement', 'minimum_edge_f1_improvement_over_frequency', 'ge', 'performance'),
    ('paired_edge_f1_lower', 'minimum_paired_edge_f1_lower', 'gt', 'performance'),
    ('positive_top3_route_coverage', 'minimum_positive_top3_route_coverage', 'ge', 'performance'),
    ('median_early_lead_steps', 'minimum_median_early_lead_steps', 'ge', 'performance'),
    ('training_seconds', 'maximum_training_seconds', 'le', 'cost'),
    ('peak_memory_bytes', 'maximum_peak_memory_bytes', 'le', 'cost'),
    ('prediction_p95_ms', 'maximum_prediction_p95_ms', 'le', 'cost'),
    ('model_bytes', 'maximum_model_bytes', 'le', 'cost'),
)
CONDITIONS = (
    'unused_test_partition', 'frozen_calibration_selection', 'independent_root_groups',
    'different_tools_evaluated', 'different_tasks_evaluated', 'different_agent_models_evaluated',
    'object_identity_ablation_benefit', 'parent_relation_ablation_benefit', 'multistep_ablation_benefit',
)


def assess(metrics: dict, conditions: dict) -> dict:
    """Assess computed evidence. This result is not an authorization artifact."""
    if (type(metrics) is not dict or type(conditions) is not dict
            or set(metrics) - {r[0] for r in RULES} or set(conditions) - set(CONDITIONS)):
        raise ForecastDataError('unknown_acceptance_evidence')
    protocol = load_protocol()
    gates = []
    for name, key, comparison, kind in RULES:
        value = metrics.get(name)
        if value is not None and (type(value) not in (float, int) or not math.isfinite(value)):
            raise ForecastDataError('invalid_acceptance_number')
        if value is not None:
            if kind == 'sample' or name in {'peak_memory_bytes', 'model_bytes'}:
                valid = type(value) is int and value >= 0
            elif name in {'brier_improvement', 'paired_brier_lower', 'edge_f1_improvement', 'paired_edge_f1_lower'}:
                valid = -1 <= value <= 1
            elif name == 'median_early_lead_steps':
                valid = 0 <= value <= 8
            elif kind == 'cost':
                valid = value >= 0
            else:
                valid = 0 <= value <= 1
            if not valid:
                raise ForecastDataError('acceptance_value_out_of_domain')
        if value is None:
            status = 'missing'
        else:
            target = protocol[key]
            passed = value >= target if comparison == 'ge' else value > target if comparison == 'gt' else value <= target
            status = 'pass' if passed else 'insufficient' if kind in {'sample', 'coverage'} else 'fail'
        gates.append({'metric': name, 'value': value, 'threshold': protocol[key],
                      'comparison': comparison, 'status': status, 'kind': kind})
    for name in CONDITIONS:
        value = conditions.get(name)
        if value is not None and type(value) is not bool:
            raise ForecastDataError('invalid_acceptance_condition')
        gates.append({'metric': name, 'value': value, 'status': 'missing' if value is None else 'pass' if value else 'fail',
                      'kind': 'experimental_design'})
    missing = any(g['status'] in {'missing', 'insufficient'} for g in gates)
    failed = any(g['status'] == 'fail' for g in gates)
    status = ('inconclusive_do_not_adopt' if missing else 'does_not_meet_criteria' if failed
              else 'criteria_met_research_only')
    return {'status': status, 'gates': gates, 'protocol_sha256': PROTOCOL_SHA256,
            'performance_failures': [g['metric'] for g in gates if g['status'] == 'fail'],
            'missing_or_insufficient': [g['metric'] for g in gates if g['status'] in {'missing', 'insufficient'}],
            'product_activation_authorized': False}
