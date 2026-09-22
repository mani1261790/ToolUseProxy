"""Bounded PreToolUse bridge to an explicitly started external forecast worker."""
import json
import time

from .journal import Journal
from .source import snapshot

WAIT_SECONDS = .10


def apply_forecast(database, event, existing_output):
    """Never relax existing decisions. Missing/off transport does no DB work.

    The worker must already be running. This function starts no process and
    accepts no code, model path, or policy setting from a ToolCall payload.
    """
    specific = (existing_output or {}).get('hookSpecificOutput', {})
    if specific.get('permissionDecision') == 'deny':
        return existing_output
    path = database.parent / 'forecast.db'
    if not path.is_file() or path.is_symlink() or not event.workspace_id or not event.session_id:
        return existing_output
    journal = Journal(path)
    request_id = None
    try:
        config = journal.configuration(event.workspace_id)
        if config is None or config['mode'] not in {'record', 'stop'}:
            return existing_output
        structure = snapshot(database, event.workspace_id, event.session_id, event.event_id)
        request_id = journal.enqueue(structure, config)
        if config['mode'] == 'record':
            journal.applied(request_id, 'record_only')
            return existing_output
        deadline = time.monotonic() + WAIT_SECONDS
        while True:
            record = journal.get(request_id)
            if not record or record['application'] != 'waiting':
                # An old result, including a retried Hook, is not fresh permission to stop.
                return existing_output
            if record['state'] == 'ready':
                break
            if record['state'] in {'discarded', 'expired'}:
                journal.applied(request_id, 'stale')
                return existing_output
            if time.monotonic() >= deadline:
                journal.applied(request_id, 'timeout')
                return existing_output
            time.sleep(min(.005, max(0, deadline - time.monotonic())))
        if (not record['created'] <= time.time() < record['expires']
                or snapshot(database, event.workspace_id, event.session_id, event.event_id) != structure
                or journal.configuration(event.workspace_id) != config):
            journal.applied(request_id, 'stale')
            return existing_output
        result = json.loads(record['result'])
        probability = result['probability']
        if (result['status'] != 'predicted' or result['model'] != config['model']
                or type(probability) not in (int, float) or not 0 <= probability <= 1
                or probability < config['threshold']):
            journal.applied(request_id, 'no_stop')
            return existing_output
        if not journal.consume_stop(request_id, config):
            return existing_output
        return {'hookSpecificOutput': {
            'hookEventName': 'PreToolUse', 'permissionDecision': 'deny',
            'permissionDecisionReason': 'ToolUseProxy: 将来予測の試験設定により、この呼び出しを実行前に停止しました。'
                                        '予測の有効性は未検証です。既存の保護によるブロックとは別の追加停止です。',
        }}
    except Exception:
        # Forecast availability cannot loosen an existing block or turn an unknown
        # prediction into a stop. No payload/exception strings go to Hook output.
        if request_id:
            try:
                journal.applied(request_id, 'unavailable')
            except Exception:
                pass
        return existing_output
