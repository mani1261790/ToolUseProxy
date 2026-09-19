import json

import pytest

from hook_monitor.evaluation.flow_forecast.prefix import ForecastDataError
from research.flow_forecast import generated_agenda, generated_world_plan
from test_flow_forecast_generated_agenda import provider as agenda_provider
from test_flow_forecast_generated_world_plan import provider as world_provider


@pytest.mark.parametrize('kind', ['agenda', 'world'])
@pytest.mark.parametrize('field', ['elapsed_ms', 'error', 'proposal', 'generation', 'execution'])
@pytest.mark.parametrize('mutation', ['completed_value', 'missing', 'extra'])
def test_only_pre_call_reservations_are_accepted(tmp_path, kind, field, mutation):
    out = tmp_path / 'prepared'
    if kind == 'agenda':
        module = generated_agenda
        result = module.prepare(agenda_provider(tmp_path), out, timeout=2)
    else:
        module = generated_world_plan
        result = module.prepare('inventory', world_provider(tmp_path), out, timeout=2)
    module.load(out)
    path = out / 'reservation.json'
    reservation = json.loads(path.read_text())
    if mutation == 'completed_value':
        value = result['call'][field]
        reservation[field] = value if value is not None else 'changed'
    elif mutation == 'missing':
        del reservation[field]
    else:
        reservation['unexpected_' + field] = None
    path.write_text(json.dumps(reservation))
    with pytest.raises(ForecastDataError, match='invalid_.*_plan_artifacts'):
        module.load(out)
