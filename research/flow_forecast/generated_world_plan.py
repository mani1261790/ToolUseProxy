"""Reserve one generation call and seal its task-world plan before execution."""
import argparse
from dataclasses import asdict
import hashlib
from pathlib import Path
import re
import time
import uuid

from hook_monitor.evaluation.flow_forecast.dataset import _json, _read
from hook_monitor.evaluation.flow_forecast.prefix import ForecastDataError, canonical, digest
from hook_monitor.evaluation.flow_lab.call_history import summarize
from hook_monitor.evaluation.flow_lab.generation_evidence import validate as validate_receipt
from hook_monitor.evaluation.flow_lab.models import utc_now, version, identifier, timestamp, RecordError
from hook_monitor.evaluation.flow_lab.preflight import LabError
from .provenance import source_provenance
from .task_catalog import _write_private
from .task_worlds import definition
from .world_plan_provider import Plan, WorldPlanProvider, prompt


def validate(value):
    try:
        if (type(value) is not dict or set(value) != {'schema', 'world', 'definition', 'model', 'plan',
                'generation', 'implementation_sha', 'request_sha', 'prepared_sha'}
                or type(value['schema']) is not int or value['schema'] != 1
                or value['definition'] != definition(value['world'])
                or value['prepared_sha'] != digest({k: v for k, v in value.items() if k != 'prepared_sha'})):
            raise ValueError
        plan = Plan.parse(value['plan'])
        if not plan.executable():
            raise ValueError
        validate_receipt(value['generation'], plan, value['model'])
        text = prompt([], 'benign_task', {'world': value['world']})
        request = {'schema': 1, 'world': value['world'], 'definition': value['definition'],
                   'model': value['model'], 'maximum_model_calls': 1, 'reply_limit': 16384,
                   'implementation_sha': value['implementation_sha'], 'prompt_sha': hashlib.sha256(text.encode()).hexdigest()}
        if (value['request_sha'] != digest(request) or value['generation']['prompt_sha'] != request['prompt_sha']
                or type(value['implementation_sha']) is not str or re.fullmatch('[a-f0-9]{64}', value['implementation_sha']) is None):
            raise ValueError
        return value
    except (KeyError, TypeError, ValueError, LabError, RecordError) as error:
        raise ForecastDataError('invalid_generated_world_plan') from error


def prepare(world, provider, output, *, timeout=60, clock=time.monotonic):
    task = definition(world)
    version(provider.model_id)
    if type(timeout) is not int or not 1 <= timeout <= 60:
        raise ForecastDataError('invalid_world_generation_budget')
    implementation = source_provenance(Path(__file__).resolve().parents[2])
    request = {'schema': 1, 'world': world, 'definition': task, 'model': provider.model_id,
               'maximum_model_calls': 1, 'reply_limit': 16384, 'implementation_sha': digest(implementation),
               'prompt_sha': hashlib.sha256(prompt([], 'benign_task', {'world': world}).encode()).hexdigest()}
    output.mkdir(mode=0o700)
    for name, document in [('implementation', implementation), ('request', request)]:
        _write_private(output / (name + '.json'), canonical(document).encode())
    record = {'number': 1, 'call_id': uuid.uuid4().hex, 'started_at': utc_now(), 'reply_limit': 16384,
              'elapsed_ms': None, 'outcome': 'pending', 'error': None, 'proposal': None,
              'generation': None, 'execution': None}
    _write_private(output / 'reservation.json', canonical(record).encode())
    started, value, rejection = clock(), None, None
    try:
        raw = provider.propose([], task_mode='benign_task', timeout=timeout, max_bytes=16384, task_context={'world': world})
        plan = Plan.parse(raw)
        record.update(outcome='response', proposal=_json(canonical(asdict(plan))))
        receipt = getattr(provider, 'last_evidence', None)
        if receipt is None:
            raise LabError('world_generation_receipt_missing')
        validate_receipt(receipt, plan, provider.model_id)
        record['generation'] = receipt
        if not plan.executable():
            raise LabError('world_plan_not_executable')
        content = {'schema': 1, 'world': world, 'definition': task, 'model': provider.model_id,
                   'plan': record['proposal'], 'generation': receipt,
                   'implementation_sha': digest(implementation), 'request_sha': digest(request)}
        value = validate({**content, 'prepared_sha': digest(content)})
        if source_provenance(Path(__file__).resolve().parents[2]) != implementation:
            raise LabError('world_generation_implementation_changed')
    except (LabError, ForecastDataError, OSError) as error:
        allowed = {'world_generation_receipt_missing', 'world_plan_not_executable', 'world_generation_implementation_changed',
                   'model_timeout', 'model_auth_required', 'model_quota_exhausted', 'invalid_model_proposal'}
        value, rejection = None, str(error) if str(error) in allowed else 'world_generation_failed'
        if record['outcome'] == 'pending':
            record.update(outcome='error', error=rejection)
    except BaseException:
        value, rejection = None, 'world_generation_interrupted'
        record.update(outcome='error', error=rejection)
        raise
    finally:
        elapsed = clock() - started
        if not 0 <= elapsed <= 120:
            value, rejection = None, 'world_generation_clock_invalid'
        record['elapsed_ms'] = int(elapsed * 1000) if 0 <= elapsed <= 120 else None
        execution = getattr(provider, 'last_execution', None)
        if execution is not None:
            try:
                validate_receipt(execution, None, provider.model_id)
                if execution['prompt_sha'] != request['prompt_sha'] or (record['generation'] is not None and any(
                        execution[k] != record['generation'][k] for k in ('call_id', 'requested_model', 'cli_version',
                                                                        'events_sha', 'prompt_sha', 'usage'))):
                    raise LabError('world_execution_mismatch')
                record['execution'] = execution
            except LabError:
                value, rejection = None, 'world_execution_invalid'
        result = {'schema': 1, 'status': 'prepared' if value is not None else 'not_prepared',
                  'rejection': rejection, 'call': record, 'costs': summarize({'calls': 1, 'call_records': [record]})}
        _write_private(output / 'call-result.json', canonical(result).encode())
    if value is not None:
        _write_private(output / 'generated-plan.json', canonical(value).encode())
    return result


def load(directory):
    if directory.is_symlink() or not directory.is_dir():
        raise ForecastDataError('invalid_world_plan_directory')
    def read(name):
        raw = _read(directory / (name + '.json'))
        if len(raw) > 128 * 1024:
            raise ForecastDataError('world_plan_size_limit')
        return _json(raw)
    value = validate(read('generated-plan'))
    try:
        result, reservation = read('call-result'), read('reservation')
        call = result['call']
        identifier(call['call_id'])
        timestamp(call['started_at'])
        if (digest(read('request')) != value['request_sha'] or digest(read('implementation')) != value['implementation_sha']
                or result['status'] != 'prepared' or result['rejection'] is not None
                or call['proposal'] != value['plan'] or call['generation'] != value['generation']
                or call['outcome'] != 'response' or call['error'] is not None
                or reservation['outcome'] != 'pending' or type(call['number']) is not int or call['number'] != 1
                or type(call['reply_limit']) is not int or call['reply_limit'] != 16384
                or any(call[k] != reservation[k] for k in ('number', 'call_id', 'started_at', 'reply_limit'))
                or type(call['elapsed_ms']) is not int or not 0 <= call['elapsed_ms'] <= 120000
                or result['costs'] != summarize({'calls': 1, 'call_records': [call]})):
            raise ValueError
        if call['execution'] is not None:
            validate_receipt(call['execution'], None, value['model'])
            if any(call['execution'][k] != value['generation'][k] for k in (
                    'call_id', 'requested_model', 'cli_version', 'events_sha', 'prompt_sha', 'usage')):
                raise ValueError
    except (KeyError, TypeError, ValueError, LabError, RecordError) as error:
        raise ForecastDataError('invalid_world_plan_artifacts') from error
    return value


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('stage', choices=('prepare', 'collect'))
    parser.add_argument('--world', choices=('inventory', 'calendar', 'ledger'))
    parser.add_argument('--model')
    parser.add_argument('--prepared', type=Path)
    parser.add_argument('--repository', type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args(argv)
    if args.stage == 'prepare':
        if not args.world or not args.model:
            parser.error('prepare requires --world and --model')
        result = prepare(args.world, WorldPlanProvider(args.model), args.output)
    else:
        if args.prepared is None or args.repository is None:
            parser.error('collect requires --prepared and --repository')
        from .task_world_collection import run
        value = load(args.prepared)
        result = run(args.repository, value['world'], value['plan']['export'], args.output, generation=value)
    print(canonical(result))
    return 0 if result['status'] in ('prepared', 'completed') else 1


if __name__ == '__main__':
    raise SystemExit(main())
