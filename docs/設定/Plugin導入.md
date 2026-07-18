# Codex Plugin 導入

ToolUseProxyのCodex Pluginは、repository rootを自己完結したPlugin bundleとして配布します。`.codex-plugin/plugin.json`、`hooks/hooks.json`、setup skill、pure Python runtimeが同じversionに含まれます。Hook commandにcheckout先の絶対pathは書かず、Codexが渡す`PLUGIN_ROOT`からcodeを起動し、mutableなSQLite stateは`PLUGIN_DATA`へ保存します。

## 現在のsupport範囲

- Python 3.11以上
- macOS: local package、relocated Plugin bundle、Codex CLIのisolated local marketplace installを自動検証
- Linux: launcherとdata-directory規約を実装済み。clean environment CIは未検証
- Windows: `py -3.11`を使うlauncherを同梱。実機検証は未完了で、protected-source登録workflow全体は現在未対応
- Hook内network access、remote embedding、telemetry: なし

## install

現在のalpha開発版は、可変なremote `main`を実行元にしないため、checkoutをrepository-local marketplaceとして追加します。

```bash
codex plugin marketplace add /absolute/path/to/ToolUseProxy
codex plugin add tooluseproxy@tooluseproxy
```

この絶対pathはmarketplaceを登録する開発時の1回だけに使い、Hook definitionには保存されません。公開配布はimmutableなrelease tagまたはcommitへpinし、Plugin version、checksum、release notes、変更後のHook再review方針を揃えてから有効にします。remote `main`を直接実行元にはしません。

installまたはHook定義の更新後は、Codexが示すHook definitionを確認してtrustします。ToolUseProxyはこのreviewを迂回しません。新しいPlugin componentとskillを確実に読み込むため、trust後は新しいtaskを開始します。

## 初期化

Plugin Hookは未初期化DBを検出してもschema migrationやworkspace変更を行わず、fail-openで終了します。その際、`PLUGIN_ROOT`と`PLUGIN_DATA`から作った初期化commandをstderrへ表示します。対象workspaceのrootへ移動し、表示されたcommandを実行してください。形式は次の通りです。

```bash
sh "<PLUGIN_ROOT>/hooks/run_cli.sh" init --codex --data-dir "<PLUGIN_DATA>"
```

このcommandは次を行います。

- `PLUGIN_DATA/events.db`を候補の承認予約と監査tableを含むschema v4へ初期化または明示的にmigrationする
- 古いschemaをmigrationする前にSQLite backupを作る
- canonical workspace rootをDBへ登録する
- `protected_sources.json`がない場合だけ、schema v2の空manifestをatomicに作る
- 既存の有効なmanifestは変更しない

続けて、同じworkspaceとdata directoryを指定して診断します。

```bash
sh "<PLUGIN_ROOT>/hooks/run_cli.sh" doctor \
  --workspace "$PWD" \
  --data-dir "<PLUGIN_DATA>"

sh "<PLUGIN_ROOT>/hooks/run_cli.sh" status \
  --workspace "$PWD" \
  --data-dir "<PLUGIN_DATA>"
```

`status: active`になるには、DB schema、canonical workspace登録、`protected_sources.json`の3つが同じworkspaceについて有効である必要があります。schema v2 selectorを使うmanifestでは、`doctor` / `status`が宣言だけでなく現在fileのkey / JSON Pointer解決まで検証します。SQLite schema upgradeが必要な場合はHook内でmigrationせず、再度`init --codex`を実行します。

## safe default

- `PostToolUse`: eventとhash-bounded evidenceをlocal DBへ記録
- `Stop`: final answerのlineageを検査
- `PreToolUse` block: 既定では無効
- MCP PreToolUse block: 既定では無効
- runtime redact / `updatedInput`: 無効

protected sourceは初期化時やHook実行中には自動登録しません。初期化が作るのは空のmanifestだけです。coding agentはユーザーが指定したworkspace内の`.env` / `.env.*` / JSON pathについて、次の2段階CLIを使えます。

```bash
sh "<PLUGIN_ROOT>/hooks/run_cli.sh" protect suggest \
  --path config/secrets.json \
  --workspace "$PWD" \
  --data-dir "<PLUGIN_DATA>" \
  --json
```

`suggest`はsourceとmanifestに対してread-onlyで、両方を変更しません。一方、local runtime DBにはvalue-freeな候補・review監査と内部再検証用のsource hash/statを保存します。sourceの値や本文断片、source hashは表示せず、review監査にも保存しません。外向きには相対path、検出rule、confidence、dotenv keyまたはJSON Pointerを含む提案だけを返します。coding agentはこの提案をユーザーへ示し、同じ提案に対する明示承認を得ます。承認後だけ、返されたopaque revisionとmanifest SHA-256を変更せず渡します。

```bash
sh "<PLUGIN_ROOT>/hooks/run_cli.sh" protect approve <CANDIDATE_ID> \
  --candidate-revision <OPAQUE_REVISION> \
  --expected-manifest-sha256 <MANIFEST_SHA256> \
  --workspace "$PWD" \
  --data-dir "<PLUGIN_DATA>" \
  --json
```

承認時はworkspace lockを取得してから候補を`proposed`から`approving`へ予約し、sourceのidentity・内容・selector解決とexpected manifest hashによる楽観的な事前条件を再検証します。lockは同一directoryの一時file、file fsync、atomic replace、directory fsync、DB確定または安全なreleaseまで保持し、その間の`reject` / `ignore`と別の承認試行を防ぎます。途中停止や一時的なstate errorでは、同じcandidate ID、opaque revision、manifest SHA-256のapprove入力を再実行します。exact登録の回復はdirectory fsyncと再検証に成功した後だけDBをapprovedへ進めます。workspace lockが直列化するのはToolUseProxyの協調writer同士です。同一UIDの非協調的な外部editorはlockに従わないため、filesystemの最終再検証からatomic replaceまで、またはdurability再確認からDB確定までの競合を含むfilesystem / DB横断の直列化は保証外です。sourceまたはmanifestが提案後に変わっていれば登録せず、再提案を要求します。`reject` / `ignore`は同じ内容・検出versionの再提示を抑止します。CLIは任意entryを承認時に受け取らないため、agentが提案JSONを書き換えて登録することはできません。この登録workflowは現在POSIX（macOS/Linux）のみ対応し、Windowsでは`protect suggest / approve / reject / ignore`を未対応とします。

この段階の候補検出は明示pathだけです。workspace全体の探索、Hook中の探索、一括承認、無承認の自動登録は行いません。またschema v1またはschema省略のlegacy manifestは読み取り互換のままですが、このwriterでは暗黙にv2へ変更しません。v1→v2の自動migration CLIは未実装なため、明示的にreviewしたv2 migrationが完了するまでこの登録workflowは使えません。coding agentはlegacy manifestを独断で書き換えません。

## package CLIの開発install

Pluginと同じCoreを通常のPython packageとして検証できます。

```bash
python3.11 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install .
.venv/bin/tooluseproxy --version
```

wheel install後はcheckout外のdirectoryからも`tooluseproxy init`、`doctor`、`status`、`protect`、`trace`、内部Hook entrypointを実行できます。

release artifactは、古い`build/`や`.DS_Store`を混入させないclean stage builderで作成します。

```bash
python3.11 scripts/build_package.py --outdir dist --sdist
```

## disable / uninstall

Pluginを外すときはCodexのPlugin commandを使います。

```bash
codex plugin remove tooluseproxy@tooluseproxy
codex plugin marketplace remove tooluseproxy
```

現段階では、Pluginをremoveしてもlocal監査dataを自動削除しません。保持・削除を選べる`tooluseproxy uninstall`は未実装です。dataを削除する場合も、対象の`PLUGIN_DATA`を確認し、明示的なユーザー承認を得てから行ってください。

## trustとfailure時の挙動

- 未trustのPlugin HookはCodex側でskipされます
- Python 3.11が見つからない場合、launcherは理由をstderrへ出してfail-openします
- DBがない、古い、新しすぎる、不完全な場合、runtime HookはDBを変更せずfail-openします
- migrationは`init`だけが行い、通常のPlugin HookはDDLやbackfillを実行しません
- 壊れたmanifestや未登録workspaceは`doctor/status`でactive扱いにしません
