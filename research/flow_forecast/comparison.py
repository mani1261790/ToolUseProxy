"""Matched-row, independent-root comparisons; no cherry-picked unmatched averages."""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
import math

from hook_monitor.evaluation.flow_forecast.calibration import probability
from hook_monitor.evaluation.flow_forecast.confidence import binomial_upper, paired_root_interval
from hook_monitor.evaluation.flow_forecast.prefix import ForecastDataError, identifier


@dataclass(frozen=True)
class CaseScore:
    row_id: str
    root: str
    weight: float
    actual: bool | None
    predicted: float | None
    edge_f1: float | None

    def __post_init__(self):
        identifier(self.row_id)
        identifier(self.root)
        if type(self.weight) not in (int, float) or not math.isfinite(self.weight) or not 0 < self.weight <= 1:
            raise ForecastDataError('invalid_comparison_weight')
        if self.actual is not None and type(self.actual) is not bool:
            raise ForecastDataError('invalid_comparison_truth')
        for value in (self.predicted, self.edge_f1):
            if value is not None:
                probability(value)


def paired_improvement(candidate: tuple[CaseScore, ...], baseline: tuple[CaseScore, ...], *, metric='brier'):
    if (metric not in {'brier', 'edge_f1'} or type(candidate) is not tuple or type(baseline) is not tuple
            or max(len(candidate), len(baseline)) > 100000
            or any(type(row) is not CaseScore for row in candidate + baseline)):
        raise ForecastDataError('invalid_paired_comparison')
    left, right = {r.row_id: r for r in candidate}, {r.row_id: r for r in baseline}
    if len(left) != len(candidate) or len(right) != len(baseline):
        raise ForecastDataError('duplicate_comparison_row')
    groups = defaultdict(list)
    omitted = len(set(left) ^ set(right))
    for key in sorted(set(left) & set(right)):
        a, b = left[key], right[key]
        if (a.root, a.weight, a.actual) != (b.root, b.weight, b.actual):
            raise ForecastDataError('comparison_population_mismatch')
        if metric == 'brier':
            if a.actual is None or a.predicted is None or b.predicted is None:
                omitted += 1
                continue
            improvement = (b.predicted - a.actual) ** 2 - (a.predicted - a.actual) ** 2
        else:
            if a.edge_f1 is None or b.edge_f1 is None:
                omitted += 1
                continue
            improvement = a.edge_f1 - b.edge_f1
        groups[a.root].append((a.weight, improvement))
    differences = {root: math.fsum(w * difference for w, difference in rows) / math.fsum(w for w, _ in rows)
                   for root, rows in groups.items()}
    interval = paired_root_interval(differences)
    count = sum(len(rows) for rows in groups.values())
    return {**interval, 'metric': metric, 'paired_rows': count, 'omitted_rows': omitted,
            'paired_row_coverage': count / (count + omitted) if count + omitted else None,
            'root_differences': differences}


def operating_point(normal_alarm: dict[str, bool | None], positive_detected: dict[str, bool | None]):
    """A positive root is recalled only if all its positive continuations are early.

    The caller computes that conservative per-root flag. Missing positive predictions
    count as misses, while unknown normal predictions never earn true-negative credit.
    """
    for groups in (normal_alarm, positive_detected):
        if type(groups) is not dict or len(groups) > 10000:
            raise ForecastDataError('invalid_operating_population')
        for root, flag in groups.items():
            identifier(root)
            if flag is not None and type(flag) is not bool:
                raise ForecastDataError('invalid_operating_outcome')
    if set(normal_alarm) & set(positive_detected):
        raise ForecastDataError('normal_positive_roots_overlap')
    negatives = [flag for flag in normal_alarm.values() if flag is not None]
    alarms = sum(negatives)
    positives = len(positive_detected)
    recalled = sum(flag is True for flag in positive_detected.values())
    missed_upper = binomial_upper(positives - recalled, positives)
    return {'normal_roots': len(negatives), 'unknown_normal_roots': len(normal_alarm) - len(negatives),
            'false_alarm_roots': alarms, 'fpr': alarms / len(negatives) if negatives else None,
            'fpr_upper_95': binomial_upper(alarms, len(negatives)),
            'positive_roots': positives, 'recalled_roots': recalled,
            'unknown_positive_roots': sum(flag is None for flag in positive_detected.values()),
            'recall': recalled / positives if positives else None,
            'recall_lower_95': 1 - missed_upper if missed_upper is not None else None}
