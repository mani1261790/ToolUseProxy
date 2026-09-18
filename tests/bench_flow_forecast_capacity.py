"""Explicit offline capacity probe; copied fixtures are not research samples.

Run with PYTHONPATH=.:tests. This is deliberately not an automatic pytest test.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import time

from hook_monitor.evaluation.flow_forecast.dataset import read_dataset, write_dataset
from research.flow_forecast.budget import Budget
from research.flow_forecast.experiment import build_models, evaluate, freeze_plan
from research.flow_forecast.provenance import source_provenance
from test_flow_forecast_capacity import capacity_dataset


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--roots', type=int, default=4000, choices=range(520, 5001))
    args = parser.parse_args(argv)
    args.output.mkdir(mode=0o700)
    budget = Budget()
    root = Path(__file__).resolve().parents[1]
    sources = source_provenance(root)
    probe_files = {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in
                   (Path(__file__), Path(__file__).with_name('test_flow_forecast_capacity.py'))}
    report = {'schema': 1, 'scope': 'mechanical_capacity_fixture_not_independent_research_data',
              'started_at': datetime.now(timezone.utc).isoformat(), 'roots': args.roots,
              'trials_executed': 0, 'phases': {}, 'source_provenance': sources,
              'probe_files': probe_files, 'research_acceptance': 'not_tested',
              'provider_cost': None, 'product_activation_authorized': False}
    started = time.monotonic()
    try:
        data = capacity_dataset(args.roots)
        budget.check()
        report['phases']['assemble_seconds'] = time.monotonic() - started
        print('assembled', len(data.branches), 'branches', flush=True)
        mark = time.monotonic()
        write_dataset(data, args.output / 'dataset')
        if data != read_dataset(args.output / 'dataset'):
            raise ValueError('capacity_roundtrip_mismatch')
        report['phases']['roundtrip_seconds'] = time.monotonic() - mark
        report['artifact_bytes'] = sum(p.stat().st_size for p in (args.output / 'dataset').iterdir())
        report['partitions'] = data.summary()['split_prefix_counts']
        budget.check()
        print('roundtrip', report['artifact_bytes'], 'bytes', flush=True)
        mark = time.monotonic()
        models, costs = build_models(data, check_budget=budget.check)
        report['phases']['training_seconds'] = time.monotonic() - mark
        report['model_training_seconds'] = costs
        print('trained', report['phases']['training_seconds'], flush=True)
        mark = time.monotonic()
        plan = freeze_plan(data, models, check_budget=budget.check)
        report['phases']['calibration_seconds'] = time.monotonic() - mark
        print('calibrated', report['phases']['calibration_seconds'], flush=True)
        mark = time.monotonic()
        result = evaluate(data, models, plan, check_budget=budget.check)
        report['phases']['evaluation_seconds'] = time.monotonic() - mark
        report['models_evaluated'] = len(result['models'])
        if source_provenance(root) != sources or any(
                hashlib.sha256((Path(__file__).parent / name).read_bytes()).hexdigest() != identity
                for name, identity in probe_files.items()):
            raise ValueError('capacity_source_changed')
        budget.check()
        report['status'] = 'capacity_passed_not_research_acceptance'
    except Exception as error:
        report['status'] = 'not_completed'
        report['error'] = type(error).__name__ + ':' + str(error)
    finally:
        report['resources'] = budget.snapshot()
        with (args.output / 'capacity-report.json').open('x') as stream:
            json.dump(report, stream, indent=2)
        print(json.dumps({key: value for key, value in report.items() if key != 'source_provenance'}))
    return 0 if report['status'] == 'capacity_passed_not_research_acceptance' else 1


if __name__ == '__main__':
    raise SystemExit(main())
