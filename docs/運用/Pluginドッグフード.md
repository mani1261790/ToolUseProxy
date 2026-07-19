# Pluginドッグフード

clean Plugin marketplace artifactから、public alphaのlifecycleをsynthetic dataだけで反復する手順です。CodexのHook trustはユーザーがdefinitionをreviewして行うmanual gateであり、このrunnerは承認を自動化・迂回しません。

## 自動Phase A

Codex CLIを使うisolated lifecycleを実行します。

```bash
python3.11 scripts/dogfood_plugin.py --installation-mode codex
```

runnerは一時directoryとisolated `CODEX_HOME`を使い、次を順番に検証します。

1. clean Plugin ZIPをbuildし、SHA-256を計算
2. marketplace addとPlugin install
3. `init` / `status`
4. synthetic `.env`を`protect scan`し、保存されたexact proposalをapprove
5. public Bash / MCPがallowされることを確認
6. protected Bash / MCPがPreToolUseでdenyされることを確認
7. protected final answerがStopで`continue_review`になることを確認
8. decision traceを`--no-preview`で取得
9. Pluginとmarketplaceをremove
10. Plugin codeの残留0とlocal SQLite data保持を確認
11. 配布artifactの`uninstall plan`をreviewし、exact confirmation tokenによる管理data削除を確認

外部commandやMCP callそのものは実行せず、Hook payloadだけをinstalled launcherへ渡すため、外部side effectは0です。出力はsynthetic protected valueを含まないJSON summaryだけで、artifact SHA-256、Plugin version、各check、最初のblockまでの時間を返します。

Codex CLIなしでartifact runtimeだけを検証するときは次を使います。

```bash
python3.11 scripts/dogfood_plugin.py --installation-mode extracted
```

## manual Phase B

自動runnerはHook definitionのtrustや、Codexがdenyを受けて実tool invocationを0件にしたことを代行しません。pre-release候補では新しいCodex taskを作り、次を人間が確認します。

1. Codexが表示するHook definitionとartifact version / SHA-256をreviewしてtrustする
2. synthetic workspaceで`init`、`doctor`、`status`を実行する
3. public fixtureをBash / MCPへ送り、false blockがないことを確認する
4. synthetic protected fixtureの送信を依頼し、deny時の実side effectが0であることを確認する
5. final answer reviewとtraceの説明が値を含まないことを確認する
6. update後にapproved sourceと監査dataが残り、古いproposalがstaleになることを確認する
7. remove後にactive Hookが残らず、data保持方針が表示どおりであることを確認する
8. uninstall planのfile数 / byte数 / 管理外entry数をreviewし、明示apply後だけ管理dataが消えることを確認する

manual結果には実secretやSQLiteを使わず、synthetic case ID、version、artifact SHA-256、所要時間、判定、failure codeだけを記録します。
