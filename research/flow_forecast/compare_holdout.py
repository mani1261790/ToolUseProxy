"""Explicit holdout lifecycle; test files are read only after durable reservation."""
from __future__ import annotations

import argparse
from pathlib import Path
import uuid

from hook_monitor.evaluation.flow_forecast.dataset import _json, _read, read_dataset
from hook_monitor.evaluation.flow_forecast.prefix import ForecastDataError, canonical, digest
from .budget import Budget
from .compare import MAX_REPORT_BYTES, attach_assessment
from .experiment import build_models, evaluate, freeze_plan
from .holdout import HoldoutLedger
from .partition_bundle import combine, read_development, read_manifest, read_partition, write_bundle
from .provenance import source_provenance


def _prepare(directory, budget):
    manifest = read_manifest(directory)
    development = read_development(directory, manifest)
    models, costs = build_models(development, check_budget=budget.check)
    plan = freeze_plan(development, models, check_budget=budget.check)
    content = {'schema': 1, 'bundle_sha': manifest['bundle_sha'], 'calibration_plan': plan,
               'model_sha': digest({'versions': {name: row['version'] for name, row in plan['models'].items()},
                                    'sequence': models['sequence'].model_digest}),
               'evaluator_sha': digest(source_provenance(Path(__file__).resolve().parents[2]))}
    return manifest, development, models, costs, {**content, 'plan_sha': digest(content)}


def prepare(directory, *, budget=None):
    return _prepare(directory, budget or Budget())[-1]


def evaluate_once(directory, plan, ledger, *, budget=None):
    budget = budget or Budget()
    manifest, development, models, costs, expected = _prepare(directory, budget)
    if plan != expected:
        raise ForecastDataError('holdout_plan_mismatch')
    seal = manifest['partitions']['test']
    run_id = uuid.uuid4().hex
    budget.check()
    reservation = ledger.reserve(**seal, run_id=run_id, plan_sha=plan['plan_sha'],
                                 model_sha=plan['model_sha'], evaluator_sha=plan['evaluator_sha'])
    # A failure from here consumes the first opening, including malformed files.
    test = read_partition(directory, manifest, 'test')
    dataset = combine((development, test))
    if digest(dataset.split.assignments) != manifest['source_digest']:
        raise ForecastDataError('bundle_source_mismatch')
    result = evaluate(dataset, models, plan['calibration_plan'], calibration_dataset=development,
                      check_budget=budget.check)
    attach_assessment(result, dataset, models, costs, budget.snapshot(), plan['calibration_plan'])
    result['holdout'] = {'reservation': reservation, 'prior_access': manifest['prior_access'],
                         'bundle_sha': manifest['bundle_sha']}
    # A converted dataset was accessible before sealing; the ledger cannot erase that.
    result['generalization']['test_prior_use'] = manifest['prior_access']
    budget.check()
    if len(canonical(result).encode()) > MAX_REPORT_BYTES:
        raise ForecastDataError('comparison_report_size_limit')
    ledger.finish(dataset_sha=seal['dataset_sha'], run_id=run_id, report_sha=digest(result))
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='stage', required=True)
    export = commands.add_parser('export')
    export.add_argument('--dataset', type=Path, required=True)
    export.add_argument('--bundle', type=Path, required=True)
    create = commands.add_parser('create-ledger')
    create.add_argument('--ledger', type=Path, required=True)
    for stage in ('seal', 'prepare', 'evaluate', 'retire'):
        command = commands.add_parser(stage)
        command.add_argument('--bundle', type=Path, required=True)
        if stage != 'prepare':
            command.add_argument('--ledger', type=Path, required=True)
        if stage in ('prepare', 'evaluate'):
            command.add_argument('--output', type=Path, required=True)
        if stage == 'evaluate':
            command.add_argument('--plan', type=Path, required=True)
        if stage == 'retire':
            command.add_argument('--reason', choices=('tuning_after_open', 'contaminated', 'abandoned'), required=True)
    args = parser.parse_args(argv)
    if getattr(args, 'output', None) is not None and args.output.exists():
        parser.error('output already exists')
    if args.stage == 'export':
        write_bundle(read_dataset(args.dataset), args.bundle)
        return
    if args.stage == 'create-ledger':
        HoldoutLedger.create(args.ledger)
        return
    if args.stage == 'prepare':
        result = prepare(args.bundle)
    else:
        ledger = HoldoutLedger(args.ledger)
        seal = read_manifest(args.bundle)['partitions']['test']
        if args.stage == 'seal':
            ledger.seal(**seal)
            return
        if args.stage == 'retire':
            ledger.retire(dataset_sha=seal['dataset_sha'], reason=args.reason)
            return
        result = evaluate_once(args.bundle, _json(_read(args.plan)), ledger)
    with args.output.open('x', encoding='utf-8') as stream:
        stream.write(canonical(result) + '\n')


if __name__ == '__main__':
    main()
