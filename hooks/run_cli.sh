#!/bin/sh

if [ "$#" -eq 0 ]; then
    echo "使い方: run_cli.sh <ToolUseProxyの引数>" >&2
    exit 2
fi

plugin_root=${PLUGIN_ROOT:-}
if [ -z "$plugin_root" ]; then
    plugin_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
fi
TOOLUSEPROXY_CODEX_PLUGIN_ROOT=$plugin_root
export TOOLUSEPROXY_CODEX_PLUGIN_ROOT

for python in "${TOOLUSEPROXY_PYTHON:-}" python3.12 python3.11 python3; do
    if [ -z "$python" ] || ! command -v "$python" >/dev/null 2>&1; then
        continue
    fi
    if ! "$python" -c 'import sys; raise SystemExit(sys.version_info < (3, 11) or sys.version_info >= (3, 13))' >/dev/null 2>&1; then
        continue
    fi
    exec "$python" "$plugin_root/tooluseproxy_plugin.py" "$@"
done

echo "ToolUseProxyの実行にはPython 3.11または3.12が必要です。" >&2
exit 1
