"""Frozen evaluation rules, changed only by an explicit new protocol version."""
from pathlib import Path
import hashlib
import json

from .prefix import ForecastDataError

PROTOCOL_SHA256 = "b4047e93e69b1959c36db2f9d61f71df54c46f82a7043bc7b1068f0f04fe983c"

def load_protocol(path: Path | None = None) -> dict:
    path = path or Path(__file__).resolve().parents[3] / 'research/flow_forecast/protocol-v1.json'
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != PROTOCOL_SHA256:
        raise ForecastDataError('frozen_protocol_changed')
    return json.loads(raw)
