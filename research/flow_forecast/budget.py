"""CPU-only research resource accounting, checked during bounded fitting."""
from dataclasses import dataclass, field
import math
import resource
import sys
import time

from hook_monitor.evaluation.flow_forecast.prefix import ForecastDataError


def peak_memory_bytes():
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return peak if sys.platform == 'darwin' else peak * 1024


@dataclass
class Budget:
    seconds: float = 300
    memory_bytes: int = 1024 * 1024 * 1024
    started: float = field(default_factory=time.perf_counter, init=False)
    cpu_started: float = field(default_factory=time.process_time, init=False)

    def __post_init__(self):
        if (type(self.seconds) not in (float, int) or not math.isfinite(self.seconds)
                or not 0 < self.seconds <= 300 or type(self.memory_bytes) is not int
                or not 1024 <= self.memory_bytes <= 1024 * 1024 * 1024):
            raise ForecastDataError('invalid_research_budget')

    def snapshot(self):
        return {'wall_seconds': time.perf_counter() - self.started,
                'cpu_seconds': time.process_time() - self.cpu_started,
                'peak_process_memory_bytes': peak_memory_bytes(),
                'device': 'cpu', 'accelerator_used': False}

    def check(self):
        if time.perf_counter() - self.started > self.seconds:
            raise ForecastDataError('research_time_budget_exceeded')
        if peak_memory_bytes() > self.memory_bytes:
            raise ForecastDataError('research_memory_budget_exceeded')
