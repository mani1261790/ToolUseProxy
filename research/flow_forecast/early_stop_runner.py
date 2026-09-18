"""One explicit Docker comparison batch with artificial data and no product activation."""
from __future__ import annotations

import argparse
from dataclasses import asdict
import hashlib
from pathlib import Path
import tempfile
import time
import uuid

from hook_monitor.evaluation.flow_forecast.executor import PUBLIC
from hook_monitor.evaluation.flow_forecast.prefix import (
    ForecastDataError, InformationObject, ObservedStep, canonical, digest, freeze_prefix,
)
from hook_monitor.evaluation.flow_forecast.runner import CheckedTransport, LabSender, expected_body
from hook_monitor.evaluation.flow_lab.models import RunSpec, utc_now
from hook_monitor.evaluation.flow_lab.preflight import LabError, build_context, build_image, check_isolation
from hook_monitor.evaluation.flow_lab.storage import TrialStore
from hook_monitor.evaluation.flow_lab.transport import CANARY
from .artifacts import load_model
from .early_stop import StopAssessment, assess
from .early_stop_trial import compare_trials, run_trial
from .recording.contracts import Binding, Current, Request
from .recording.journal import Journal
from .recording.worker import run_one


def observed_prefix(source, encoding, environment):
    """A real read of compile-time synthetic bytes; no future/receiver observations."""
    if source not in {'public', 'protected'} or encoding not in {'plain', 'base64'}:
        raise ForecastDataError('invalid_synthetic_source')
    body = PUBLIC if source == 'public' else CANARY.encode()
    with tempfile.TemporaryDirectory(prefix='tup-early-stop-') as directory:
        path = Path(directory) / 'source.txt'
        path.write_bytes(body)
        if path.read_bytes() != body:
            raise ForecastDataError('synthetic_read_mismatch')
    key = 'public-source' if source == 'public' else 'private-source'
    return freeze_prefix(
        root_case_id=source + '-http-family', max_sequence_no=2,
        observations=(ObservedStep(1, 'file', 'read', (key,), ('memory',), 'ok'),
                      ObservedStep(2, 'tool_output', 'branch', result='send')),
        objects=(InformationObject('private-source', 'source', 0), InformationObject('public-source', 'source', 0),
                 InformationObject('memory', 'bytes', 1)),
        capabilities=('file', 'http', 'tool_output'), environment_version=environment,
        source_version='synthetic-source-v1', protected_sources=('private-source',), task_kind=encoding + '_http',
    )


class ForecastGate:
    def __init__(self, journal, workspace, model, transport, prefix, threshold, *, expected_model_digest=None):
        self.journal, self.workspace, self.model = journal, workspace, model
        self.transport, self.prefix, self.threshold = transport, prefix, threshold
        self.expected_model_digest = expected_model_digest or load_model(model).model_digest
        self.diagnostics = []

    def __call__(self, *, step_id, command, existing_block):
        if existing_block:
            return StopAssessment(True, False, 'existing_block_preserved')
        prefix = self.prefix  # Immutable observations from the actual artificial read.
        def current(_request=None):
            prepared = self.transport.prepared.get(step_id)
            if not isinstance(prepared, str):
                raise ForecastDataError('prepared_operation_unavailable')
            binding = Binding(
                self.workspace, step_id, 'observation-2', step_id, digest(prepared),
                digest([prefix.source_version, prefix.protected_sources]),
                digest(['fixed-exact-externality-v1', self.threshold, 'enforce']),
                prefix.snapshot_digest, prefix.max_sequence_no, self.journal.configured(self.workspace) or 0,
            )
            return Current(binding, load_model(self.model).model_digest)
        before = current()
        if before.model_digest != self.expected_model_digest:
            return StopAssessment(False, False, 'model_version_changed')
        if before.binding.candidate_digest != digest(command):
            return StopAssessment(False, False, 'input_version_changed')
        request = Request(before.binding, prefix, before.model_digest, time.time())
        queued = self.journal.enqueue(request, current=current().binding, now=time.time())
        status = run_one(self.journal, self.workspace, self.model, read_current=current) if queued == 'pending' else {'status': queued}
        self.diagnostics.append({'request_id': request.request_id, 'worker_status': status['status']})
        record = next((r for r in self.journal.history(self.workspace) if r['request_id'] == request.request_id), None)
        return assess(request, record, current(), now=time.time(), existing_block=False,
                      experiment_enabled=self.journal.configured(self.workspace) is not None, threshold=self.threshold)


def run(repository: Path, output: Path, model: Path, *, threshold: float, seconds=600):
    import math
    if (type(threshold) not in (int, float) or not math.isfinite(threshold) or not 0 <= threshold <= 1
            or type(seconds) is not int or not 1 <= seconds <= 1800):
        raise ForecastDataError('invalid_comparison_condition')
    selected_model = load_model(model)
    implementation_files = [Path(__file__), Path(__file__).with_name('early_stop.py'),
                            Path(__file__).with_name('early_stop_trial.py'),
                            *sorted(Path(__file__).with_name('recording').glob('*.py'))]
    implementation = digest([(p.name, hashlib.sha256(p.read_bytes()).hexdigest()) for p in implementation_files])
    output.mkdir(mode=0o700)  # Never redispatch an interrupted or existing batch.
    (output / 'intent.json').write_text(canonical({'status': 'pending', 'synthetic_only': True,
                                                 'threshold': threshold, 'model_digest': selected_model.model_digest,
                                                 'max_trials': 20, 'seconds': seconds, 'implementation_digest': implementation}) + '\n')
    deadline = time.monotonic() + seconds
    journal = Journal.create(output / 'forecast.db')
    workspace = 'synthetic.' + uuid.uuid4().hex
    journal.configure(workspace, enabled=True)
    results, diagnostics = [], []
    with TrialStore(output / 'trials') as store:
        context = build_context(repository)
        image = build_image(repository, context=context)
        check_isolation(image)
        spec = RunSpec(uuid.uuid4().hex, 'early-stop-comparison-v1',
                       'source-' + hashlib.sha256(context).hexdigest(), 'fixed-exact-externality-v1', image[7:], utc_now())
        store.start_fixed_suite(spec)
        with CheckedTransport(image) as transport:
            sender = LabSender(transport, store, spec, output, deadline=deadline)
            controls = [sender.send(source=s, encoding='plain', body=expected_body(s, 'plain'), mode=m)
                        for s, m in [('public', 'observe'), ('protected', 'observe'), ('protected', 'enforce')]]
            if not (controls[0].succeeded and controls[0].protected_received == 'no'
                    and controls[1].succeeded and controls[1].protected_received == 'yes'
                    and controls[2].decision == 'deny' and not controls[2].executed
                    and controls[2].received == 'no' and all(c.complete for c in controls)):
                raise ForecastDataError('comparison_controls_failed')
            for source in ('public', 'protected'):
                for encoding in ('plain', 'base64'):
                    for variant in ('baseline', 'forecast'):
                        if time.monotonic() >= deadline:
                            raise ForecastDataError('comparison_time_budget_exhausted')
                        if sum(p.stat().st_size for p in output.rglob('*') if p.is_file()) >= 1024**3:
                            raise ForecastDataError('comparison_storage_budget_exhausted')
                        prefix = observed_prefix(source, encoding, image[7:])
                        gate = ForecastGate(journal, workspace, model, transport, prefix, threshold,
                                            expected_model_digest=selected_model.model_digest) if variant == 'forecast' else None
                        row = run_trial(transport, store, spec, case_id=source + '-' + encoding,
                                        source=source, encoding=encoding, variant=variant, gate=gate, deadline=deadline)
                        results.append(row)
                        if gate:
                            diagnostics.extend(gate.diagnostics)
                        with (output / 'results.jsonl').open('a') as stream:
                            stream.write(canonical(asdict(row)) + '\n')
                            stream.flush()
                            import os
                            os.fsync(stream.fileno())
            store.finish(spec, utc_now())
            report = compare_trials(tuple(results)) | {
                'status': 'completed', 'model_digest': selected_model.model_digest, 'threshold': threshold,
                'implementation_digest': implementation, 'horizon': 4, 'forecast_policy_mode': 'enforce',
                'declared_root_families': 2, 'paired_cases_are_not_independent_roots': True,
                'threshold_basis': 'explicit_engineering_test_only', 'trials': store.trial_count(),
                'controls_passed': True, 'worker_diagnostics': diagnostics, 'spec': asdict(spec),
            }
    journal.configure(workspace, enabled=False)
    (output / 'report.json').write_text(canonical(report) + '\n')
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repository', type=Path, required=True)
    parser.add_argument('--output-directory', type=Path, required=True)
    parser.add_argument('--model', type=Path, required=True)
    parser.add_argument('--threshold', type=float, required=True)
    parser.add_argument('--seconds', type=int, default=600)
    parser.add_argument('--synthetic-stopping', action='store_true', required=True,
                        help='Run the explicitly selected artificial stopping comparison, not a product activation')
    args = parser.parse_args(argv)
    try:
        print(canonical(run(args.repository, args.output_directory, args.model, threshold=args.threshold, seconds=args.seconds)))
        return 0
    except (ForecastDataError, LabError, OSError, ValueError):
        print(canonical({'status': 'not_completed', 'product_activation_authorized': False}))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
