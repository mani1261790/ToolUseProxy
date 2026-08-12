# プライバシーとデータ保持

ToolUseProxy `0.1.0-alpha.7`候補のlocal runtimeが扱うデータ、保存場所、保持期間、削除時の境界を説明します。ToolUseProxyはCodexとは別のlocal Hook processとして動作し、既定ではtelemetry、remote embedding、外部API、network送信を行いません。実験的なExternality Judge shadowだけは、利用者がworkspace設定とproviderを両方明示した場合に限り、値非保持の構造要約を選択済みproviderへ送ります。

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
| Externality Judge評価 | event / workspace / sessionの内部ID、構造要約hash、Codex model名のhash、closed verdict、件数、時間、値を含まないfailure code | raw command、source code、URL、host、path、protected source identity、model名を保存しない。ToolUseProxyはAPI keyを受け取らない |
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

- 通常のToolUseProxy Hook、CLI、analysisはnetwork requestを開始しません
- Externality Judgeは既定offで、既存のsetup profileからも有効化しません
- `externality-protection`を有効にしてもHookはnetwork通信せず、未知callの値非保持envelopeをlocal queueへ積み、protected flowが到達した初見unknownを保守的に実行前denyします
- LLM分類にはHook外workerと`codex` routeの両方を明示する必要があります。別providerやfallbackはありません
- ToolUseProxyはOpenAI API endpointを直接呼ばず、API keyを受け取りません
- Codex routeは、実行ファイル、version、model、judge契約に結び付いた事前probe receiptが一致する場合だけ、インストール済みCodexをjobごとの新しい一時セッションとして隔離設定で呼びます
- remote embeddingは使いません
- telemetry、crash report、usage analyticsを送信しません
- GitHub Actionsやpackage buildは開発・release工程であり、local Hook runtimeからは起動しません

Externality Judgeへ送る構造要約には、tool family、解析coverage、executable category、HTTP / socket / DNS / child processなどのclosed capability、dynamic code / 未知executable / workspace外参照などのclosed risk signal、bounded countだけを含めます。次は送信しません。

- raw command、argument、source code、tool response、final answer
- protected source、user prompt、transcript
- URL、host、DNS label、workspace path、file name、独自identifier
- credential、環境変数値

Codex一時セッションには同じ値非保持envelopeだけが送られます。Codex service側の一時的な処理・保持をゼロと保証するものではないため、利用しているCodexのデータ利用・保持条件は別途確認してください。ToolUseProxyが認証情報を取得・保存・転送することはありません。

LLM分類自体は人間review前にruleへ昇格しません。ただし初見unknownの保守的sinkはreview前から有効で、protected flowが到達すればdenyします。timeout、refusal、HTTP error、schema不一致、provider不在はfailureとして値非保持で記録し、`local`やallowへ変換しません。承認済みriskは完全一致したcallにexternal sinkを維持し、承認済みlocal分類は同じworkspace・構造の保守的unknown sinkだけを外します。既存adapter/static blockは解除しません。無効化するには`externality-protection`をoff / unsetにします。provider routeを`off`にするとHook外workerの通信も停止します。

Codex自体や、Codexが呼び出す外部tool / MCP serverの通信は、上記の明示されたExternality Judge routeを除きToolUseProxyの通信ではありません。PreToolUse blockは既定で無効であり、有効化しても解析不能・schema不整合・内部例外では原則fail-openします。

## 保持期間

一般のevent、artifact、source chunk、graph、finding、candidate、backupに自動expirationはありません。明示的に削除するまで残ります。一部のredaction auditにはdry-runを既定とするcleanup scriptがありますが、database全体の自動retention policyではありません。

Pluginのdisable、remove、marketplace remove、package uninstallはlocal dataを自動削除しません。これは誤削除を防ぎ、監査やupgrade後の再利用を可能にするためのalpha既定です。

## 削除手順

1. Codex Pluginをdisableまたはremoveし、新しいHook実行を止める
2. `status --json`またはPluginが表示したcommandで対象の`data_dir` / `db_path`を確認する
3. 必要な監査dataをbackupするか、不要であることを確認する
4. Codexの関連taskとToolUseProxy processを終了する
5. `tooluseproxy uninstall plan --data-dir <DATA_DIR> --json`を実行し、管理file数、byte数、管理外entry数をreviewする
6. 出力された現在内容固有のtokenを`tooluseproxy uninstall apply --data-dir <DATA_DIR> --confirmation-token <TOKEN> --json`へ明示的に渡す

`init`はdata directoryへ値を含まないprivateな識別markerを作成します。既存directoryにmarkerがない場合はToolUseProxy SQLite schemaを識別できた場合だけ削除planを作ります。`apply`はmarker、`events.db`とSQLite sidecar、migration backup、`manifest-backups`だけを管理対象として削除します。管理外entryは削除せずdata directoryを残します。plan後に管理dataの内容が変化した場合、tokenは無効になり再planが必要です。symlinkやgroup / otherから読めるdata directoryは拒否します。

複数workspaceが同じdatabaseを共有している場合、uninstallは全workspaceの履歴を削除します。現在の`0.1.0-alpha.7`候補にはworkspace単位の完全なerase command、secure erase、外部backup追跡、復元不能性の保証はありません。SSD、filesystem snapshot、backup serviceには削除後もcopyが残る可能性があります。

## 共有時の注意

`events.db`、SQLite WAL / SHM、migration backup、analysis export、trace JSONをGitへcommitしたりIssueへ添付したりしないでください。bug reportにはraw payload、protected value、absolute pathを貼らず、syntheticな再現データを使ってください。

## 変更方針

将来telemetry、別のremote model、network service、自動uploadを導入する場合は、既定off、送信項目、送信先、retention、同意と無効化方法を別の明示契約として先に追加します。Externality Judgeについても送信項目やproviderをsilentに広げません。
