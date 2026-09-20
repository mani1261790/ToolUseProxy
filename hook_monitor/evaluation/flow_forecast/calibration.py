"""Probability checks and calibration summaries with explicit missingness.

Rows are not independent experiments. Losses first average within a root task
and then across root tasks, so duplicating a prefix's branches cannot increase
that task's influence. Confidence intervals and adoption gates live separately.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
import math

from .prefix import ForecastDataError, identifier


def probability(value):
    if type(value) not in (int, float) or not math.isfinite(value) or not 0 <= value <= 1:
        raise ForecastDataError('invalid_forecast_probability')
    return float(value)


@dataclass(frozen=True)
class ProbabilitySample:
    root_case_id: str
    predicted: float | None
    actual: bool | None
    weight: float = 1.0

    def __post_init__(self):
        identifier(self.root_case_id)
        if self.predicted is not None:
            probability(self.predicted)
        if self.actual is not None and type(self.actual) is not bool:
            raise ForecastDataError('invalid_probability_label')
        if type(self.weight) not in (int, float) or not math.isfinite(self.weight) or not 0 < self.weight <= 1:
            raise ForecastDataError('invalid_probability_weight')


def validate_samples(samples):
    if (type(samples) is not tuple or len(samples) > 100000
            or any(type(s) is not ProbabilitySample for s in samples)):
        raise ForecastDataError('invalid_probability_samples')


def probability_scores(samples: tuple[ProbabilitySample, ...]) -> dict:
    validate_samples(samples)
    groups = defaultdict(list)
    for sample in samples:
        if sample.actual is not None and sample.predicted is not None:
            groups[sample.root_case_id].append(sample)
    brier, log_loss = [], []
    infinite_log_loss = False
    for rows in groups.values():
        total = sum(row.weight for row in rows)
        brier.append(sum(row.weight * (row.predicted - int(row.actual)) ** 2 for row in rows) / total)
        group_log = 0.0
        for row in rows:
            assigned = row.predicted if row.actual else 1 - row.predicted
            if assigned == 0:
                infinite_log_loss = True
            else:
                group_log -= row.weight / total * math.log(assigned)
        log_loss.append(group_log)
    count = len(samples)
    labeled = sum(s.actual is not None for s in samples)
    scored = sum(len(rows) for rows in groups.values())
    return {
        'root_count': len({s.root_case_id for s in samples}), 'scored_roots': len(groups),
        'row_count': count, 'labeled_rows': labeled, 'scored_rows': scored,
        'unknown_label_rows': count - labeled,
        'abstained_labeled_rows': sum(s.actual is not None and s.predicted is None for s in samples),
        'coverage': scored / labeled if labeled else None,
        'brier': sum(brier) / len(brier) if brier else None,
        'log_loss': None if not log_loss or infinite_log_loss else sum(log_loss) / len(log_loss),
        'log_loss_status': 'infinite' if infinite_log_loss else 'scored' if log_loss else 'no_labels',
    }


def reliability_bins(samples: tuple[ProbabilitySample, ...], *, bins=10) -> tuple[dict, ...]:
    validate_samples(samples)
    if type(bins) is not int or not 1 <= bins <= 100:
        raise ForecastDataError('invalid_calibration_bins')
    # Normalize each root's known/predicted mass before binning. The bins do not
    # imply that repeated branches count as independent calibration samples.
    root_mass = defaultdict(float)
    for sample in samples:
        if sample.predicted is not None and sample.actual is not None:
            root_mass[sample.root_case_id] += sample.weight
    bucket_rows = [[] for _ in range(bins)]
    for sample in samples:
        if sample.predicted is not None and sample.actual is not None:
            bucket_rows[min(bins - 1, int(sample.predicted * bins))].append(sample)
    result = []
    for index, rows in enumerate(bucket_rows):
        weights = [row.weight / root_mass[row.root_case_id] for row in rows]
        total = sum(weights)
        result.append({
            'lower': index / bins, 'upper': (index + 1) / bins, 'rows': len(rows),
            'roots': len({row.root_case_id for row in rows}), 'root_weight': total,
            'mean_probability': sum(w * row.predicted for w, row in zip(weights, rows)) / total if total else None,
            'observed_rate': sum(w * row.actual for w, row in zip(weights, rows)) / total if total else None,
        })
    return tuple(result)
