#!/bin/sh

phase=${1:-}
if [ -z "$phase" ] || [ -z "${PLUGIN_ROOT:-}" ] || [ -z "${PLUGIN_DATA:-}" ]; then
    echo "ToolUseProxy inactive (plugin_environment): PLUGIN_ROOT and PLUGIN_DATA are required" >&2
    exit 0
fi

for python in "${TOOLUSEPROXY_PYTHON:-}" python3.13 python3.12 python3.11 python3; do
    if [ -z "$python" ] || ! command -v "$python" >/dev/null 2>&1; then
        continue
    fi
    if ! "$python" -c 'import sys; raise SystemExit(sys.version_info < (3, 11))' >/dev/null 2>&1; then
        continue
    fi
    "$python" "$PLUGIN_ROOT/tooluseproxy_plugin.py" hook "$phase" --data-dir "$PLUGIN_DATA"
    exit 0
done

echo "ToolUseProxy inactive (python_missing): Python 3.11 or newer is required" >&2
exit 0
