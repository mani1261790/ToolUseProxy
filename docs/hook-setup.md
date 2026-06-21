# Hook Setup

このリポジトリには、Codex の `PreToolUse` / `PostToolUse` に接続するための最小スクリプトだけを置いています。

## 置いてあるもの

- `hooks/monitor_pre_tool.py`
- `hooks/monitor_post_tool.py`

どちらも現時点では no-op です。stdin を読むだけで、まだ解析・記録・判定はしません。

## 使い方

Codex の GUI か設定ファイルで、次の command を指定します。

- `PreToolUse` -> `python3 /Users/mani/Developer/ToolUseProxy/hooks/monitor_pre_tool.py`
- `PostToolUse` -> `python3 /Users/mani/Developer/ToolUseProxy/hooks/monitor_post_tool.py`

この段階の目的は、まず hook から I/O を受け取れる入口を固定することです。観測、記録、情報流追跡は次の段階で足します。
