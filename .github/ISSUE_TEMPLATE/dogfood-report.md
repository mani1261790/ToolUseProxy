---
name: Dogfood report
about: ToolUseProxyを実projectで試した結果を値非保持で報告する
title: "[Dogfood] "
labels: evaluation, productization
assignees: ""
---

## 公開してよい情報だけを記載

このIssueへproject名、repository path、ユーザー名を含むabsolute path、source値、secret、token、raw Hook payload、`events.db`、task transcriptを貼らないでください。security-sensitiveな結果は公開Issueを作らず、`SECURITY.md`の非公開窓口を使用してください。

## 環境

- OSとversion:
- surface: `codex_cli_tui` / Codex Desktop/GUI
- Codex DesktopまたはCLIのversion:
- ToolUseProxy Plugin version:
- install元: `public-alpha` / immutable tag / local candidate
- 新規install / update / reinstall:

## Setup

- ToolUseProxy Pluginの有効数: 1 / その他
- 3 Hookをreviewした: yes / no
- 3 Hookがtrusted: yes / no
- setup apply: passed / failed / not run
- read-only verification: passed / failed / not run
- 表示されたcommand承認回数:
- 承認理由はworkspace外のPlugin data操作だと理解できた: yes / no
- 広い再利用可能permissionを要求された: yes / no

## 動作結果

- public operation: allowed / blocked / not run
- protected operation: blocked before execution / executed / not run
- public side effect件数:
- protected side effect件数:
- exact block件数:
- raw protected value exposure件数:
- 通常作業での予期しないblock件数:

## 分かりやすさ

- Hook trustの判断は分かりやすかった: yes / no
- setup承認の判断は分かりやすかった: yes / no
- protected source登録の判断は分かりやすかった: yes / no / not used
- 追加で必要だった質問の件数:
- 迷った画面や説明（protected dataを含めずに記載）:

## Failureまたは停止

- status: passed / needs_followup / stopped
- value-freeなfailure code:
- 失敗後に同じ操作を再試行した: yes / no
- Plugin codeをdisable / removeした: yes / no
- Plugin dataを保持した: yes / no

## 補足

期待結果と実結果の差を、syntheticな名称と件数だけで記載してください。
