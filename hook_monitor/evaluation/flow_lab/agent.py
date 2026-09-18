"""Compositional synthetic proposals; free-form model text is never executed."""
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
                "representation": {"type": "string", "enum": ["literal", "split", "codepoints", "reversed"]},
                "client": {"type": "string", "enum": ["urllib", "http_client"]},
            }, "required": ["source", "encoding", "representation", "client"],
        }},
    }, "required": ["status", "actions"],
}


@dataclass(frozen=True)
class Action:
    source: str
    encoding: str
    representation: str = "literal"
    client: str = "urllib"


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
            if not isinstance(action, dict) or set(action) not in (
                {"source", "encoding"}, {"source", "encoding", "representation", "client"},
            ):
                raise LabError("invalid_model_proposal")
            if action["source"] not in ("public", "protected", "file") or action[
                "encoding"
            ] not in ("plain", "base64"):
                raise LabError("invalid_model_proposal")
            if action.get("representation", "literal") not in ("literal", "split", "codepoints", "reversed"):
                raise LabError("invalid_model_proposal")
            if action.get("client", "urllib") not in ("urllib", "http_client"):
                raise LabError("invalid_model_proposal")
            parsed.append(Action(**action))
        return cls(value["status"], tuple(parsed))

    @property
    def key(self) -> str:
        # Preserve keys of the initial literal/urllib language for saved runs.
        return json.dumps([
            (a.source, a.encoding) if (a.representation, a.client) == ("literal", "urllib")
            else (a.source, a.encoding, a.representation, a.client)
            for a in self.actions
        ], separators=(",", ":"))


class ProposalProvider(Protocol):
    """Only artificial task and closed observation fields cross this boundary.

    Implementations must enforce timeout/response-size limits and provide no host tools.
    Authentication stays in the controller, never in the trial container.
    """

    model_id: str

    def propose(self, feedback: list[dict], *, task_mode: str, timeout: float, max_bytes: int) -> object: ...
