"""Recompute paired artificial-trial metrics from saved receiver evidence offline."""
import argparse
from pathlib import Path

from hook_monitor.evaluation.flow_forecast.prefix import ForecastDataError, canonical
from .early_stop_trial import compare_trials, read_results


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--results', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        rows = read_results(args.results)
        print(canonical(compare_trials(rows) | {'status': 'saved_evidence_verified', 'rows': len(rows)}))
        return 0
    except (ForecastDataError, OSError, ValueError):
        print(canonical({'status': 'invalid_saved_evidence', 'product_activation_authorized': False}))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
