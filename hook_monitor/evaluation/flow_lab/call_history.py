"""Every charged generation call, including unknown outcomes and missing usage."""
from .agent import Proposal
from .generation_evidence import validate as validate_generation
from .models import identifier, timestamp
from .preflight import LabError

ERRORS = {'model_auth_required', 'model_quota_exhausted', 'model_refused', 'model_timeout',
          'model_unavailable', 'invalid_model_proposal'}


def validate_history(state, budget):
    if 'call_records' not in state:
        return  # Legacy records are explicitly incomplete, never inferred from plans.
    records = state['call_records']
    if type(records) is not list or len(records) != state['calls']:
        raise LabError('invalid_call_history')
    ids, generation_ids = set(), set()
    for number, record in enumerate(records, 1):
        if type(record) is not dict or set(record) != {
                'number', 'call_id', 'started_at', 'reply_limit', 'elapsed_ms',
                'outcome', 'error', 'proposal', 'generation'}:
            raise LabError('invalid_call_history')
        identifier(record['call_id'])
        timestamp(record['started_at'])
        if (type(record['number']) is not int or record['number'] != number
                or record['call_id'] in ids or type(record['reply_limit']) is not int
                or record['reply_limit'] != budget.reply_allowance(number - 1)):
            raise LabError('invalid_call_history')
        ids.add(record['call_id'])
        outcome = record['outcome']
        if outcome == 'pending':
            if (number != len(records) or state['phase'] != 'requesting'
                    or any(record[key] is not None for key in ('elapsed_ms', 'error', 'proposal', 'generation'))):
                raise LabError('invalid_call_history')
            continue
        if type(record['elapsed_ms']) is not int or record['elapsed_ms'] < 0:
            raise LabError('invalid_call_history')
        if outcome == 'error':
            if (record['error'] not in ERRORS or record['proposal'] is not None
                    or record['generation'] is not None):
                raise LabError('invalid_call_history')
        elif outcome == 'response':
            if record['error'] is not None:
                raise LabError('invalid_call_history')
            proposal = Proposal.parse(record['proposal'])
            if record['generation'] is not None:
                validate_generation(record['generation'], proposal, state['identity']['model'])
                identity = record['generation']['call_id']
                if identity in generation_ids:
                    raise LabError('invalid_call_history')
                generation_ids.add(identity)
        else:
            raise LabError('invalid_call_history')
    if state['phase'] == 'requesting' and (not records or records[-1]['outcome'] != 'pending'):
        raise LabError('invalid_call_history')
    saved = {row['generation']['call_id']: row['generation'] for row in records if row['generation']}
    for plan in state['plans']:
        if 'generation' in plan and saved.get(plan['generation']['call_id']) != plan['generation']:
            raise LabError('plan_call_history_mismatch')


def summarize(state):
    """Input must have passed controller validation; missing tokens are not zero."""
    records = state.get('call_records', [])
    known = [r['generation']['usage'] for r in records
             if r['generation'] is not None and r['generation']['usage'] is not None]
    complete = len(records) == state['calls'] and 'call_records' in state
    totals = {key: sum(row[key] for row in known)
              for key in ('input_tokens', 'cached_input_tokens', 'output_tokens')}
    return {'charged_calls': state['calls'], 'recorded_calls': len(records),
            'call_history_complete': complete, 'calls_with_usage': len(known),
            'calls_without_usage': state['calls'] - len(known),
            'token_totals_complete': complete and len(known) == state['calls'],
            'known_token_totals': totals if known else None,
            'observed_call_milliseconds': sum(r['elapsed_ms'] for r in records if r['elapsed_ms'] is not None),
            'call_time_complete': complete and all(r['elapsed_ms'] is not None for r in records),
            'pending_calls': sum(r['outcome'] == 'pending' for r in records),
            'failed_calls': sum(r['outcome'] == 'error' for r in records),
            'provider_cost': None, 'pricing_source': None}
