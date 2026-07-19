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
4. `protect suggest`のexact proposalを1件rejectし、別の1件をignore
5. 提案後に内容を変更したsourceのapproveが`source_changed`で拒否されることを確認
6. synthetic `.env`を`protect scan`し、保存されたexact proposalをapprove
7. 再scanでreject / ignoreが抑止され、approved sourceが再提示されないことを確認
8. public Bash / MCPがallowされることを確認
9. protected Bash / MCPがPreToolUseでdenyされることを確認
10. protected final answerがStopで`continue_review`になることを確認
11. decision traceを`--no-preview`で取得
12. Pluginとmarketplaceをremove
13. Plugin codeの残留0とlocal SQLite data保持を確認
14. 配布artifactの`uninstall plan`をreviewし、exact confirmation tokenによる管理data削除を確認

外部commandやMCP callそのものは実行せず、Hook payloadだけをinstalled launcherへ渡すため、外部side effectは0です。出力はsynthetic protected valueを含まないschema v2 JSON summaryだけで、artifact SHA-256、Plugin version、各check、最初のblockまでの時間に加え、`bounded_scan` / `explicit_suggestion`のproposal件数、approve / reject / ignore件数、stale proposal拒否件数を返します。これはworkflow coverageであり、人間が説明を理解・承認したという利用実績ではありません。

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

説明UXのdogfoodでは、JSONやsource値を保存せず、次の集約値だけを記録します。

- sourceを手作業でJSON登録しようとした回数
- `scan`と明示path `suggest`の利用回数
- agent説明後にapprove / reject / ignoreを選んだ件数
- proposalを理解するために追加質問が必要だった件数
- 最初のproposal提示から明示判断までの時間

自動Phase Aの件数をmanual Phase Bの実利用値へ合算しません。Hook trust、実tool side effect、agent説明の理解度は人間が確認したrunだけを実利用として扱います。

immutable alpha.1と現在release候補のupgrade / rollback / disable / removeは[Pluginライフサイクル](Pluginライフサイクル.md)の独立runnerで検証します。
