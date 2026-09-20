"""Root-task uncertainty and operating points; repeated branches are not new trials."""
from __future__ import annotations

import math
import random

from .calibration import probability
from .prefix import ForecastDataError, identifier


def binomial_upper(failures: int, trials: int, *, confidence=.95) -> float | None:
    """One-sided exact binomial upper bound, by monotone CDF inversion."""
    if (type(failures) is not int or type(trials) is not int or not 0 <= failures <= trials <= 10000
            or type(confidence) not in (float, int) or not .5 < confidence < 1):
        raise ForecastDataError('invalid_binomial_counts')
    if trials == 0:
        return None
    if failures == trials:
        return 1.0
    alpha = 1 - confidence
    if failures == 0:
        return -math.expm1(math.log(alpha) / trials)
    coefficients = [math.lgamma(trials + 1) - math.lgamma(k + 1) - math.lgamma(trials - k + 1)
                    for k in range(failures + 1)]
    lower, upper = failures / trials, 1.0
    for _ in range(60):
        p = (lower + upper) / 2
        log_p, log_q = math.log(p), math.log1p(-p)
        logs = [coefficient + k * log_p + (trials - k) * log_q for k, coefficient in enumerate(coefficients)]
        largest = max(logs)
        log_cdf = largest + math.log(math.fsum(math.exp(value - largest) for value in logs))
        if log_cdf > math.log(alpha):
            lower = p
        else:
            upper = p
    return (lower + upper) / 2


def zero_failure_sample_size(rate=.01, *, confidence=.95) -> int:
    if type(rate) not in (int, float) or not 0 < rate < 1 or not .5 < confidence < 1:
        raise ForecastDataError('invalid_sample_size_target')
    return math.ceil(math.log1p(-confidence) / math.log1p(-rate))


def paired_root_interval(differences: dict[str, float], *, draws=2000, seed=134, confidence=.95) -> dict:
    if (type(differences) is not dict or len(differences) > 10000
            or type(draws) is not int or not 100 <= draws <= 5000
            or type(seed) is not int or type(confidence) not in (int, float) or not .5 < confidence < 1):
        raise ForecastDataError('invalid_root_bootstrap')
    for root, value in differences.items():
        identifier(root)
        if type(value) not in (int, float) or not math.isfinite(value) or not -1 <= value <= 1:
            raise ForecastDataError('invalid_paired_difference')
    values = [differences[key] for key in sorted(differences)]
    if len(values) < 2:
        return {'status': 'insufficient_roots', 'roots': len(values), 'mean': values[0] if values else None,
                'lower': None, 'upper': None}
    rng = random.Random(seed)
    means = sorted(math.fsum(rng.choice(values) for _ in values) / len(values) for _ in range(draws))
    tail = (1 - confidence) / 2
    return {'status': 'scored', 'roots': len(values), 'mean': math.fsum(values) / len(values),
            'lower': means[max(0, math.floor(tail * draws))],
            'upper': means[min(draws - 1, math.ceil((1 - tail) * draws) - 1)],
            'draws': draws, 'seed': seed, 'confidence': confidence}


def select_threshold(normal_roots: dict[str, tuple[float | None, ...]], *, maximum_fpr=.01) -> dict:
    """Choose only from calibration negatives. An alarm on any row flags its root."""
    probability(maximum_fpr)
    if type(normal_roots) is not dict or len(normal_roots) > 10000:
        raise ForecastDataError('invalid_calibration_roots')
    maxima, unknown = [], 0
    for root, values in normal_roots.items():
        identifier(root)
        if type(values) is not tuple or not 1 <= len(values) <= 1000:
            raise ForecastDataError('invalid_root_scores')
        for value in values:
            if value is not None:
                probability(value)
        if any(value is None for value in values):
            unknown += 1
        else:
            maxima.append(max(values))
    if not maxima:
        return {'status': 'insufficient_calibration', 'threshold': None,
                'normal_roots': 0, 'unknown_roots': unknown}
    candidates = sorted({0.0, 1.0, *maxima, *(math.nextafter(p, 1.0) for p in maxima if p < 1)})
    for threshold in candidates:
        failures = sum(value >= threshold for value in maxima)
        if failures / len(maxima) <= maximum_fpr:
            return {'status': 'selected' if not unknown else 'partial_calibration',
                    'threshold': threshold, 'normal_roots': len(maxima), 'unknown_roots': unknown,
                    'false_alarm_roots': failures, 'observed_fpr': failures / len(maxima),
                    'upper_95': binomial_upper(failures, len(maxima))}
    return {'status': 'no_finite_operating_point', 'threshold': None,
            'normal_roots': len(maxima), 'unknown_roots': unknown}
