#!/bin/sh

phase=${1:-}

emit_inactive() {
    code=$1
    case "$code" in
        plugin_environment)
            message="ToolUseProxy Pluginの設定を読み込めないため、保護機能は動作していません。"
            ;;
        python_missing)
            message="Python 3.11または3.12が見つからないため、ToolUseProxyの保護機能は動作していません。"
            ;;
        *)
            message="ToolUseProxyを開始できなかったため、保護機能は動作していません。"
            ;;
    esac
    case "$phase" in
        session-start)
            printf '{"hookSpecificOutput":{"hookEventName":"SessionStart","additionalContext":"%s WebSearchなどのhosted toolはToolUseProxyで検査・遮断できません。保護対象やそこから得た内容をhosted toolへ入力しないでください。（技術情報: %s）"}}\n' "$message" "$code"
            ;;
        subagent-start)
            printf '{"hookSpecificOutput":{"hookEventName":"SubagentStart","additionalContext":"%s WebSearchなどのhosted toolはToolUseProxyで検査・遮断できません。保護対象やそこから得た内容をhosted toolへ入力しないでください。（技術情報: %s）"}}\n' "$message" "$code"
            ;;
        pre-tool-use)
            printf '{"hookSpecificOutput":{"hookEventName":"PreToolUse","additionalContext":"%s（技術情報: %s）","permissionDecision":"deny","permissionDecisionReason":"ToolUseProxyが操作を実行前に止めました。保護判定を安全に開始できないため、この操作を許可できません。Pluginの状態を確認してからやり直してください。\\n結果：外部操作は実行されていません。保護対象の内容も表示していません。"}}\n' "$message" "$code"
            ;;
        post-tool-use)
            printf '{"hookSpecificOutput":{"hookEventName":"PostToolUse","additionalContext":"%s（技術情報: %s）"}}\n' "$message" "$code"
            ;;
        stop)
            printf '{"systemMessage":"%s（技術情報: %s）"}\n' "$message" "$code"
            ;;
        *)
            printf '%s（技術情報: %s）\n' "$message" "$code" >&2
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
