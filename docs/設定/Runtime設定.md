# Workspace runtime設定

ToolUseProxyの実行時policyは、workspaceごとに`PLUGIN_DATA/events.db`へ保存できます。Desktopや別taskでも同じworkspace登録と`PLUGIN_DATA`を使えば設定が引き継がれ、Plugin codeをremove / reinstallしてもmanaged dataを明示削除しない限り残ります。

## 設定できる項目

| key | 役割 | 既定値 |
| --- | --- | --- |
| `pre-tool-policy` | Bashの外部sinkをPreToolUseで評価する | off |
| `file-payload-shadow` | file-backed payloadのexact比較をobserve-onlyで記録する | off |
| `file-payload-exact-enforcement` | 確定したexact / substring一致を実行前blockへ昇格する | off |
| `externality-protection` | adapter外のunknown callを値非保持queueへ入れ、protected flowがあれば初回からdenyし、承認済み完全一致ruleを照合する。Hook内networkなし | off |

`file-payload-shadow`、`file-payload-exact-enforcement`、`externality-protection`をonにする前に、`pre-tool-policy`をonにする必要があります。依存項目がonの間は`pre-tool-policy`をoffまたはunsetにできません。

## 確認と変更

最初に現在のrevisionを取得します。

```bash
sh "<PLUGIN_ROOT>/hooks/run_cli.sh" config show \
  --workspace "$PWD" \
  --data-dir "<PLUGIN_DATA>" \
  --json
```

変更には直前に確認した`settings_revision`が必要です。これは別taskや別processの更新を誤って上書きしないためのcompare-and-setです。

```bash
sh "<PLUGIN_ROOT>/hooks/run_cli.sh" config set pre-tool-policy on \
  --expected-revision "<SETTINGS_REVISION>" \
  --workspace "$PWD" \
  --data-dir "<PLUGIN_DATA>" \
  --json
```

一つ変更するたびに新しいrevisionが返るため、次の変更にはその新しい値を使います。workspace設定を削除して既定値へ戻す場合は`unset`を使います。

```bash
sh "<PLUGIN_ROOT>/hooks/run_cli.sh" config unset pre-tool-policy \
  --expected-revision "<SETTINGS_REVISION>" \
  --workspace "$PWD" \
  --data-dir "<PLUGIN_DATA>" \
  --json
```

値を含まない変更履歴は次で確認できます。

```bash
sh "<PLUGIN_ROOT>/hooks/run_cli.sh" config history \
  --workspace "$PWD" \
  --data-dir "<PLUGIN_DATA>" \
  --limit 20 \
  --json
```

`doctor`と`status`にもcurrent / effective value、適用元、診断codeが表示されます。

## 優先順位と安全境界

有効値の優先順位は`有効な環境変数 > workspace設定 > offの既定値`です。既存の環境変数との互換性は維持しますが、不正な環境変数値はworkspace設定へ黙ってfallbackせず、その項目をoffにして`environment_value_invalid`を診断します。

Hookは設定を短いread-only transactionで読みます。Hook内ではschema migration、設定変更、workspace scanを行いません。DB lock、schema不一致、設定破損では永続設定をfail-openで使わず、明示された有効な環境変数と安全な既定値だけへ戻ります。migrationが必要な場合はHook外で`init --codex`を実行します。

Externality JudgeのHook処理はnetworkを使いません。Hook外workerはworkspace設定に加えて`codex` routeを明示し、事前probe receiptが一致した場合だけ、jobごとの新しい隔離済みCodex一時セッションを使います。Codex CLIは`0.145.0`以上を必要とします。receiptは24時間以内で、現在のCodex executableのbinary SHA-256、canonical path SHA-256、version、judge contract、modelがすべて一致する必要があります。期限切れまたは不一致ならworkerは起動しません。別provider、fallback、OpenAI API直接呼出し、API key設定はありません。既存のsetup profileには含まれません。送信項目、review、failure時の扱いは[Externality Judge](../設計/ExternalityJudge.md)、保持境界は[プライバシーとデータ保持](../../PRIVACY.md)を参照してください。

設定storeへsecret本文や任意文字列は保存しません。保存対象は固定keyのboolean、revision、workspace ID、値を含まない変更監査だけです。
