# プライバシーとデータ保持

ToolUseProxy `0.1.0-alpha.3`のlocal runtimeが扱うデータ、保存場所、保持期間、削除時の境界を説明します。ToolUseProxyはCodexとは別のlocal Hook processとして動作し、ToolUseProxy自身はtelemetry、remote embedding、外部API、network送信を行いません。

## 保存するデータ

ToolUseProxyは情報流を再構築するため、次のデータをlocal SQLiteへ保存します。

| 種類 | 内容 | 機密性に関する注意 |
| --- | --- | --- |
| Hook event | tool名、phase、session / turn / tool use ID、時刻、workspace | workspaceの絶対pathを含み得る |
| raw Hook payload | Codexから渡されたtool input、tool response、final answer | source code、command、出力、secretなどの平文を含み得る |
| artifact / fragment | payloadから抽出したtext、path、query、content、stdoutなど | 抽出後のtextと正規化textを平文で保存する |
| protected source chunk | manifestで指定したsourceから解析したchunk | protected sourceの内容を平文で保存し得る |
| graph / finding / policy | source、artifact、resource、sinkの関係、score、判断理由 | 内容そのものに加え、機密情報の存在や流れを推測できるmetadataを含む |
| candidate / review | 候補path、selector、rule、confidence、再検証用hash / stat、review状態 | agent向け出力には値を出さないが、pathやdictionary-test可能なhashは機密になり得る |
| migration backup | SQLiteや`protected_sources.json`の更新前backup | 元データと同じ機密性を持つ |

候補scanの外向きJSONとreview監査にはsource本文やsecret値を含めません。ただし、これはSQLite全体がhash-onlyまたは匿名化済みという意味ではありません。通常のHook payload、artifact、source chunk、analysis snapshotには平文が残り得ます。

## 保存場所

Codex Pluginでは、Codexが渡す`PLUGIN_DATA`の下に`events.db`と必要なbackupを保存します。明示的な`--data-dir`、`--db`、`TOOLUSEPROXY_DATA_DIR`、`TOOLUSEPROXY_DB_PATH`を指定した場合は、その場所を優先します。

通常packageの既定値は次の通りです。

| OS | 既定data directory |
| --- | --- |
| macOS | `~/Library/Application Support/ToolUseProxy` |
| Linux | `$XDG_STATE_HOME/tooluseproxy`または`~/.local/state/tooluseproxy` |
| Windows | `%LOCALAPPDATA%\ToolUseProxy`または`~/AppData/Local/ToolUseProxy` |

`init`、`doctor --json`、`status --json`は解決した`data_dir`または`db_path`を確認するために使えます。POSIXでは新規data directoryをmode `0700`、databaseを`0600`にしますが、SQLiteはapplication-level encryptionを行いません。OS accountの分離とdisk encryptionを併用してください。

## networkとtelemetry

- ToolUseProxy Hook、CLI、analysisはnetwork requestを開始しません
- remote embeddingやremote classifierを使いません
- telemetry、crash report、usage analyticsを送信しません
- GitHub Actionsやpackage buildは開発・release工程であり、local Hook runtimeからは起動しません

Codex自体や、Codexが呼び出す外部tool / MCP serverの通信はToolUseProxyの通信ではありません。PreToolUse blockは既定で無効であり、有効化しても解析不能・schema不整合・内部例外では原則fail-openします。

## 保持期間

一般のevent、artifact、source chunk、graph、finding、candidate、backupに自動expirationはありません。明示的に削除するまで残ります。一部のredaction auditにはdry-runを既定とするcleanup scriptがありますが、database全体のretention policyや一括uninstallではありません。

Pluginのdisable、remove、marketplace remove、package uninstallはlocal dataを自動削除しません。これは誤削除を防ぎ、監査やupgrade後の再利用を可能にするためのalpha既定です。

## 削除手順

1. Codex Pluginをdisableまたはremoveし、新しいHook実行を止める
2. `status --json`またはPluginが表示したcommandで対象の`data_dir` / `db_path`を確認する
3. 必要な監査dataをbackupするか、不要であることを確認する
4. Codexの関連taskとToolUseProxy processを終了する
5. 確認したdata directoryをOSのfile操作で明示的に削除する

複数workspaceが同じdatabaseを共有している場合、directory削除は全workspaceの履歴を削除します。alpha.3にはworkspace単位の完全なerase command、secure erase、backup追跡、復元不能性の保証はありません。SSD、filesystem snapshot、backup serviceには削除後もcopyが残る可能性があります。

## 共有時の注意

`events.db`、SQLite WAL / SHM、migration backup、analysis export、trace JSONをGitへcommitしたりIssueへ添付したりしないでください。bug reportにはraw payload、protected value、absolute pathを貼らず、syntheticな再現データを使ってください。

## 変更方針

将来telemetry、remote model、network service、自動uploadを導入する場合は、既定off、送信項目、送信先、retention、同意と無効化方法を別の明示契約として先に追加します。silentに現在のlocal-only契約を変更しません。
