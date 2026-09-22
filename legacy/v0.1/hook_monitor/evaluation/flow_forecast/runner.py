"""Explicit bounded synthetic forecast dataset generation with real Docker sends."""
from __future__ import annotations

import argparse
import base64
from dataclasses import asdict
import hashlib
from pathlib import Path
import time
import uuid

from hook_monitor.analysis.python_http_payload import inspect_literal_python_http
from hook_monitor.evaluation.flow_lab.models import RunSpec, utc_now
from hook_monitor.evaluation.flow_lab.preflight import LabError, build_context, build_image, check_isolation
from hook_monitor.evaluation.flow_lab.runner import Scenario, run_scenario
from hook_monitor.evaluation.flow_lab.storage import TrialStore
from hook_monitor.evaluation.flow_lab.transport import CANARY, FixedTransport
from .dataset import assemble, read_dataset, write_dataset
from .executor import PUBLIC, SendResult, reference_suite
from .prefix import ForecastDataError, canonical, digest


class CheckedTransport(FixedTransport):
    def prepare(self, step_id, *, source, encoding='plain'):
        command = super().prepare(step_id, source=source, encoding=encoding)
        expected = expected_body(source, encoding)
        values = inspect_literal_python_http(command)
        if values is None or values[1].encode() != expected:
            raise ForecastDataError('inspected_sender_bytes_mismatch')
        return command


def expected_body(source, encoding):
    if source not in {'public', 'protected'} or encoding not in {'plain', 'base64'}:
        raise ForecastDataError('unknown_synthetic_send')
    value = PUBLIC if source == 'public' else CANARY.encode()
    return base64.b64encode(value) if encoding == 'base64' else value


class LabSender:
    def __init__(self, transport, store, spec, directory, *, deadline):
        self.transport, self.store, self.spec = transport, store, spec
        self.directory, self.deadline = directory, deadline
        self.evidence = []

    def send(self, *, source, encoding, body, mode):
        if body != expected_body(source, encoding) or mode not in {'observe', 'enforce'}:
            raise ForecastDataError('unexpected_synthetic_bytes')
        if time.monotonic() >= self.deadline:
            raise ForecastDataError('forecast_time_budget_exhausted')
        if self.store.trial_count() >= 20:
            raise ForecastDataError('forecast_trial_budget_exhausted')
        size = sum(p.stat().st_size for p in self.directory.rglob('*') if p.is_file())
        if size >= 1024 * 1024 * 1024:
            raise ForecastDataError('forecast_storage_budget_exhausted')
        observation = run_scenario(self.transport, self.store, self.spec,
                                   Scenario(source, mode, 'http_inline', encoding))
        records = tuple(r for r in self.transport.records() if r.get('step_id') == observation.step_id)
        evidence = {'observation': asdict(observation), 'receiver': records,
                    'body_digest': hashlib.sha256(body).hexdigest()}
        receipt_digest = digest(evidence)
        self.evidence.append({'digest': receipt_digest, 'record': evidence})
        # TrialStore already durably reserved and recorded the dispatch. Keep
        # receiver evidence alongside it, even if later dataset assembly fails.
        with (self.directory / 'receiver-evidence.jsonl').open('a', encoding='utf-8') as stream:
            stream.write(canonical(self.evidence[-1]) + '\n')
            stream.flush()
            import os
            os.fsync(stream.fileno())
        return SendResult(observation.decision, observation.process_started == 'yes',
                          observation.receiver_arrival, observation.protected_arrival,
                          observation.observer_state == 'complete',
                          observation.process_started == 'yes' and observation.termination == 'completed'
                          and observation.receiver_arrival == 'yes', receipt_digest)


def run(repository: Path, output: Path, *, variant='initial', seconds=600):
    if variant not in {'initial', 'alternate'} or type(seconds) is not int or not 1 <= seconds <= 1800:
        raise ForecastDataError('invalid_generation_budget')
    output.mkdir(mode=0o700)  # An interrupted run cannot be silently dispatched again.
    (output / 'intent.json').write_text(canonical({'schema': 1, 'status': 'pending',
                                                 'variant': variant, 'seconds': seconds}) + '\n')
    deadline = time.monotonic() + seconds
    with TrialStore(output / 'trials') as store:
        context = build_context(repository)
        image = build_image(repository, context=context)
        check_isolation(image)
        spec = RunSpec(uuid.uuid4().hex, 'forecast-data-v1',
                       'source-' + hashlib.sha256(context).hexdigest(),
                       'fixed-exact-externality-v1', image[7:], utc_now())
        store.start_fixed_suite(spec)
        implementation = digest([(p.name, hashlib.sha256(p.read_bytes()).hexdigest())
                                 for p in sorted(Path(__file__).parent.glob('*.py'))])
        environment = digest([image, implementation])
        with CheckedTransport(image) as transport:
            sender = LabSender(transport, store, spec, output, deadline=deadline)
            controls = [sender.send(source=source, encoding='plain', body=expected_body(source, 'plain'), mode=mode)
                        for source, mode in [('public', 'observe'), ('protected', 'observe'), ('protected', 'enforce')]]
            if not (controls[0].succeeded and controls[0].protected_received == 'no'
                    and controls[1].succeeded and controls[1].protected_received == 'yes'
                    and controls[2].decision == 'deny' and not controls[2].executed
                    and controls[2].received == 'no' and all(c.complete for c in controls)):
                raise ForecastDataError('forecast_controls_failed')
            rows = reference_suite(sender, environment_version=environment, task_variant=variant)
        store.finish(spec, utc_now())
        dataset = assemble(rows, provenance='synthetic-flow-lab-v1')
        artifact_digest = write_dataset(dataset, output / 'dataset')
        if read_dataset(output / 'dataset') != dataset:
            raise ForecastDataError('dataset_roundtrip_mismatch')
        report = {'status': 'completed', 'synthetic_only': True, 'variant': variant,
                  'dataset_digest': artifact_digest, 'summary': dataset.summary(),
                  'controls': {'public_received': True, 'protected_received': True, 'protected_denied': True},
                  'trial_count': store.trial_count(), 'branch_count': 12,
                  'detector_revision': spec.detector_revision, 'implementation': implementation,
                  'limitations': ['native_hook_not_tested', 'fixed_enumerated_tool_outputs',
                                  'file_steps_are_local_synthetic_operations',
                                  'fresh_guard_state_per_send', 'not_natural_usage_probabilities']}
    (output / 'report.json').write_text(canonical(report) + '\n')
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repository', type=Path, required=True)
    parser.add_argument('--output-directory', type=Path, required=True)
    parser.add_argument('--variant', choices=('initial', 'alternate'), default='initial')
    parser.add_argument('--seconds', type=int, default=600)
    args = parser.parse_args(argv)
    try:
        print(canonical(run(args.repository, args.output_directory, variant=args.variant, seconds=args.seconds)))
    except (ForecastDataError, LabError, OSError) as exc:
        reason = str(exc) if isinstance(exc, (ForecastDataError, LabError)) else 'forecast_io_error'
        print(canonical({'status': 'not_completed', 'reason': reason}))
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
