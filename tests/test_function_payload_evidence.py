import hashlib

import pytest

from hook_monitor.analysis.function_payload_evidence import verify_literal_function_payload
from hook_monitor.runtime.models import SourceChunk


SECRET = "synthetic protected design threshold"
CHUNK = SourceChunk(
    chunk_id="chunk", source_id="source", ordinal=0, text=SECRET,
    normalized_text=SECRET, text_hash=hashlib.sha256(SECRET.encode()).hexdigest(),
    shingle_fingerprint="[]", token_count=4,
)


@pytest.mark.parametrize("payload", [
    {"questions": [{"title": "Continue?"}]},
    {"questions": [{"title": "Continue?", "options": ["Yes", "No"]}]},
])
def test_public_literal_questions_verified(payload):
    result = verify_literal_function_payload("request_user_input_async", payload, (CHUNK,))
    assert result.status == "safe"


@pytest.mark.parametrize("payload", [
    {}, [], {"questions": []}, {"questions": "Continue?"},
    {"questions": [{"title": "Continue?", "command": "execute()"}]},
    {"questions": [{"title": "Continue?"}], "path": "private.py"},
    {"questions": [{"title": {"path": "private.py"}}]},
    {"questions": [{"title": "Continue?", "options": "Yes"}]},
    {"questions": [{"title": "Continue?", "options": [1]}]},
    {"questions": [{"title": "Continue?", "options": []}]},
    {"questions": [{"title": "Continue?", "options": ["Yes"] * 17}]},
    {"questions": [{"title": "Continue?"}] * 17},
    {"questions": [{"title": " "}]},
])
def test_invalid_or_extended_contract_remains_unresolved(payload):
    assert verify_literal_function_payload("request_user_input_async", payload, (CHUNK,)).status == "unsupported"


@pytest.mark.parametrize("tool", [
    "custom_publish", "exec", "functions.exec", "request_user_input_async_extra",
    "custom.request_user_input_async", "REQUEST_USER_INPUT_ASYNC", None,
])
def test_unknown_tools_not_allowed_even_with_question_shaped_input(tool):
    assert verify_literal_function_payload(tool, {"questions": [{"title": "Continue?"}]}, (CHUNK,)).status == "unsupported"


@pytest.mark.parametrize("question", [
    {"title": SECRET}, {"title": "Continue?", "options": [SECRET]},
])
def test_every_displayed_text_compared(question):
    assert verify_literal_function_payload("request_user_input_async", {"questions": [question]}, (CHUNK,)).status == "matched"
