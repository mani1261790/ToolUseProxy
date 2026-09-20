"""Finite explicit-run budgets, charged before model and trial dispatch."""
from __future__ import annotations

from dataclasses import dataclass
import math

from .preflight import LabError


@dataclass(frozen=True)
class Budget:
    trials: int = 20
    steps: int = 10
    seconds: int = 1800
    model_calls: int = 20
    reply_bytes: int = 16384
    total_reply_bytes: int = 327680
    storage_bytes: int = 1024 * 1024 * 1024

    def __post_init__(self):
        for value, maximum in (
            (self.trials, 20), (self.steps, 10), (self.seconds, 1800),
            (self.model_calls, 20), (self.reply_bytes, 16384),
            (self.total_reply_bytes, 327680), (self.storage_bytes, 1024 * 1024 * 1024),
        ):
            if type(value) is not int or not 1 <= value <= maximum:
                raise LabError("invalid_search_budget")

    def remaining_seconds(self, started: float, now: float) -> float:
        if not all(math.isfinite(t) for t in (started, now)) or now < started:
            raise LabError("search_clock_invalid")
        return max(0, self.seconds - (now - started))

    def reply_allowance(self, calls: int) -> int:
        if calls >= self.model_calls:
            return 0
        return min(self.reply_bytes, max(0, self.total_reply_bytes - calls * self.reply_bytes))
