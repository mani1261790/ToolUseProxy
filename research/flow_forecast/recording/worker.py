"""Record one request outside the Hook; prediction can never change a policy decision."""
from __future__ import annotations

from dataclasses import asdict
from pathlib import Path
import json
import math
import sqlite3
import subprocess
import sys
import time

from hook_monitor.evaluation.flow_forecast.predictions import Forecast, Outcome, Route
from hook_monitor.evaluation.flow_forecast.prefix import ForecastDataError, canonical
from .contracts import Current, MAX_REQUEST_BYTES
from .journal import Journal
from ..model import ALGORITHM


CHILD_FAILURES = frozenset({'out_of_domain', 'model_missing', 'model_invalid', 'model_version_changed', 'worker_failed'})


def isolated_prediction(request, model_path: Path, *, timeout=3):
    if type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0 < timeout <= 3:
        raise ForecastDataError('invalid_recording_worker_timeout')
    try:
        result = subprocess.run([sys.executable, '-m', 'research.flow_forecast.recording.child', str(model_path)],
                                input=canonical(asdict(request)).encode(), capture_output=True,
                                timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        return {'status': 'timeout'}
    except OSError:
        return {'status': 'worker_failed'}
    if result.returncode or len(result.stdout) > MAX_REQUEST_BYTES:
        return {'status': 'worker_failed'}
    try:
        return json.loads(result.stdout)
    except (ValueError, UnicodeError):
        return {'status': 'worker_failed'}


def checked_result(value, request):
    if type(value) is not dict or value.get('status') != 'recorded' or set(value) != {'status', 'model_digest', 'forecast'}:
        raise ForecastDataError('invalid_child_result')
    if value['model_digest'] != request.model_digest:
        raise ForecastDataError('child_model_mismatch')
    try:
        raw = value['forecast']
        outcomes = tuple(Outcome(tuple(Route(r['source'], r['anchor'], tuple(tuple(s) for s in r['steps']))
                                      for r in outcome['routes']), outcome['probability']) for outcome in raw['outcomes'])
        forecast = Forecast(**{**raw, 'outcomes': outcomes})
        forecast.validate_for(request.prefix, policy_mode=request.policy_mode, horizon=request.horizon)
        if forecast.model_version != ALGORITHM + '-' + request.model_digest[:12]:
            raise ForecastDataError('child_model_version_mismatch')
    except (TypeError, ValueError, KeyError, AttributeError):
        raise ForecastDataError('invalid_child_forecast') from None
    return {'request_id': request.request_id, 'binding': asdict(request.binding),
            'model_digest': request.model_digest, 'forecast': asdict(forecast), 'record_only': True}


def run_one(journal: Journal, workspace: str, model_path: Path, *, read_current,
            clock=time.time, predictor=isolated_prediction):
    """read_current obtains a fresh binding before and after the disposable process.

    Live integration must supply its real source/authority adapter. No request's
    own binding is accepted as proof of current state by this worker.
    """
    try:
        claimed = journal.claim(workspace, now=clock(), lease_seconds=5)
    except (ForecastDataError, OSError):
        return {'status': 'recording_database_failure'}
    if claimed is None:
        return {'status': 'idle'}
    request, token = claimed
    result = None
    try:
        before = read_current(request)
        if type(before) is not Current:
            raise ForecastDataError('invalid_current_recording_state')
        status = request.validity(before.binding, before.model_digest, clock())
        if status == 'current':
            if request.input_scope != 'synthetic':
                status = 'out_of_domain'  # F04 efficacy and structural-domain proof are pending.
            else:
                output = predictor(request, model_path)
                if type(output) is not dict:
                    raise ForecastDataError('invalid_child_result')
                status = output.get('status')
                if status == 'recorded':
                    result = checked_result(output, request)
                elif status not in CHILD_FAILURES | {'timeout'}:
                    raise ForecastDataError('invalid_child_status')
                after = read_current(request)
                if type(after) is not Current:
                    raise ForecastDataError('invalid_current_recording_state')
                fresh = request.validity(after.binding, after.model_digest, clock())
                if fresh != 'current':
                    status, result = fresh, None
    except sqlite3.Error:
        status, result = 'input_database_failure', None
    except Exception:
        # Faults are diagnostics only. Interrupts still leave a recoverable lease.
        status, result = 'worker_failed', None
    try:
        status = journal.finish(request, token, status=status, result=result, now=clock())
    except (ForecastDataError, OSError):
        return {'status': 'recording_database_failure'}
    return {'status': status, 'request_id': request.request_id}
