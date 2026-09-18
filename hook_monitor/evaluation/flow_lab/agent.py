"""Closed proposal language for the synthetic lab; model text is never code."""
from __future__ import annotations

from dataclasses import dataclass
import json
from typing import Protocol

from .preflight import LabError


PROPOSAL_SCHEMA = {
    "type": "object", "additionalProperties": False,
    "properties": {
        "status": {"type": "string", "enum": ["propose", "complete", "refused"]},
        "actions": {"type": "array", "maxItems": 10, "items": {
            "type": "object", "additionalProperties": False,
            "properties": {
                "source": {"type": "string", "enum": ["public", "protected", "file"]},
                "encoding": {"type": "string", "enum": ["plain", "base64"]},
            }, "required": ["source", "encoding"],
        }},
    }, "required": ["status", "actions"],
}


@dataclass(frozen=True)
class Action:
    source: str
    encoding: str


@dataclass(frozen=True)
class Proposal:
    status: str
    actions: tuple[Action, ...]

    @classmethod
    def parse(cls, value: object) -> Proposal:
        if not isinstance(value, dict) or set(value) != {"status", "actions"}:
            raise LabError("invalid_model_proposal")
        if value["status"] not in ("propose", "complete", "refused"):
            raise LabError("invalid_model_proposal")
        actions = value["actions"]
        if not isinstance(actions, list) or len(actions) > 10:
            raise LabError("invalid_model_proposal")
        if bool(actions) != (value["status"] == "propose"):
            raise LabError("invalid_model_proposal")
        parsed = []
        for action in actions:
            if not isinstance(action, dict) or set(action) != {"source", "encoding"}:
                raise LabError("invalid_model_proposal")
            if action["source"] not in ("public", "protected", "file") or action[
                "encoding"
            ] not in ("plain", "base64"):
                raise LabError("invalid_model_proposal")
            parsed.append(Action(**action))
        return cls(value["status"], tuple(parsed))

    @property
    def key(self) -> str:
        return json.dumps([(a.source, a.encoding) for a in self.actions], separators=(",", ":"))


class ProposalProvider(Protocol):
    """Only artificial task and closed observation fields cross this boundary.

    Implementations must enforce timeout/token limits and provide no host tools.
    Authentication stays in the controller, never in the trial container.
    """

    model_id: str

    def propose(self, feedback: list[dict], *, timeout: float, max_tokens: int) -> object: ...
