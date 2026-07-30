#!/bin/sh

phase=${1:-}

emit_inactive() {
    code=$1
    detail=$2
    case "$phase" in
        pre-tool-use)
            printf '{"hookSpecificOutput":{"hookEventName":"PreToolUse","additionalContext":"ToolUseProxy inactive (%s): %s"}}\n' "$code" "$detail"
            ;;
        post-tool-use)
            printf '{"hookSpecificOutput":{"hookEventName":"PostToolUse","additionalContext":"ToolUseProxy inactive (%s): %s"}}\n' "$code" "$detail"
            ;;
        stop)
            printf '{"systemMessage":"ToolUseProxy inactive (%s): %s"}\n' "$code" "$detail"
            ;;
        *)
            printf 'ToolUseProxy inactive (%s): %s\n' "$code" "$detail" >&2
            ;;
    esac
}

if [ -z "$phase" ] || [ -z "${PLUGIN_ROOT:-}" ] || [ -z "${PLUGIN_DATA:-}" ]; then
    emit_inactive "plugin_environment" "PLUGIN_ROOT and PLUGIN_DATA are required"
    exit 0
fi

for python in "${TOOLUSEPROXY_PYTHON:-}" python3.12 python3.11 python3; do
    if [ -z "$python" ] || ! command -v "$python" >/dev/null 2>&1; then
        continue
    fi
    if ! "$python" -c 'import sys; raise SystemExit(sys.version_info < (3, 11) or sys.version_info >= (3, 13))' >/dev/null 2>&1; then
        continue
    fi
    if output=$(
        "$python" "$PLUGIN_ROOT/tooluseproxy_plugin.py" \
            hook "$phase" --data-dir "$PLUGIN_DATA" 2>/dev/null
    ); then
        if [ -n "$output" ]; then
            printf '%s\n' "$output"
        fi
        exit 0
    fi
    emit_inactive \
        "runtime_start_failed" \
        "the local Hook runtime could not start"
    exit 0
done

emit_inactive "python_missing" "Python 3.11 or 3.12 is required"
exit 0
