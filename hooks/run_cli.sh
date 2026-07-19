#!/bin/sh

if [ "$#" -eq 0 ]; then
    echo "usage: run_cli.sh <tooluseproxy arguments>" >&2
    exit 2
fi

plugin_root=${PLUGIN_ROOT:-}
if [ -z "$plugin_root" ]; then
    plugin_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
fi

for python in "${TOOLUSEPROXY_PYTHON:-}" python3.12 python3.11 python3; do
    if [ -z "$python" ] || ! command -v "$python" >/dev/null 2>&1; then
        continue
    fi
    if ! "$python" -c 'import sys; raise SystemExit(sys.version_info < (3, 11) or sys.version_info >= (3, 13))' >/dev/null 2>&1; then
        continue
    fi
    exec "$python" "$plugin_root/tooluseproxy_plugin.py" "$@"
done

echo "tooluseproxy: Python 3.11 or 3.12 is required" >&2
exit 1
