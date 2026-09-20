"""One bounded synthetic prediction in a disposable process; no Hook imports."""
from dataclasses import asdict
import json
from pathlib import Path
import sys

from hook_monitor.evaluation.flow_forecast.prefix import ForecastDataError, canonical
from research.flow_forecast.artifacts import load_model
from research.flow_forecast.budget import Budget
from .contracts import MAX_REQUEST_BYTES, parse_request


def predict_one(request, model_path):
    if request.input_scope != 'synthetic':
        return {'status': 'out_of_domain'}
    budget = Budget(seconds=5)
    if not model_path.is_file():
        return {'status': 'model_missing'}
    try:
        model = load_model(model_path)
    except (ForecastDataError, OSError):
        return {'status': 'model_invalid'}
    if model.model_digest != request.model_digest:
        return {'status': 'model_version_changed'}
    budget.check()
    forecast = model.predict(request.prefix, policy_mode=request.policy_mode, horizon=request.horizon)
    budget.check()
    return {'status': 'recorded', 'model_digest': model.model_digest, 'forecast': asdict(forecast)}


def main():
    try:
        if len(sys.argv) != 2:
            raise ForecastDataError('invalid_child_arguments')
        raw = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
        if len(raw) > MAX_REQUEST_BYTES:
            raise ForecastDataError('recording_request_size_limit')
        request = parse_request(json.loads(raw))
        result = predict_one(request, Path(sys.argv[1]))
        encoded = canonical(result)
        if len(encoded.encode()) > MAX_REQUEST_BYTES:
            raise ForecastDataError('recording_result_size_limit')
        print(encoded)
    except (ForecastDataError, OSError, ValueError, TypeError):
        print('{"status":"worker_failed"}')


if __name__ == '__main__':
    main()
