# Codex Plugin 導入

ToolUseProxyのCodex Pluginは、repository rootを自己完結したPlugin bundleとして配布します。`.codex-plugin/plugin.json`、`hooks/hooks.json`、setup skill、pure Python runtimeが同じversionに含まれます。Hook commandにcheckout先の絶対pathは書かず、Codexが渡す`PLUGIN_ROOT`からcodeを起動し、mutableなSQLite stateは`PLUGIN_DATA`へ保存します。

## 現在のsupport範囲

- Python 3.11以上
- macOS: local package、relocated Plugin bundle、Codex CLIのisolated local marketplace installを自動検証
- Linux: launcherとdata-directory規約を実装済み。clean environment CIは未検証
- Windows: `py -3.11`を使うlauncherを同梱。実機検証は未完了
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

- `PLUGIN_DATA/events.db`を初期化または明示的にmigrationする
- 古いschemaをmigrationする前にSQLite backupを作る
- canonical workspace rootをDBへ登録する
- `protected_sources.json`がない場合だけ、空のmanifestをatomicに作る
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

`status: active`になるには、DB schema、canonical workspace登録、`protected_sources.json`の3つが同じworkspaceについて有効である必要があります。

## safe default

- `PostToolUse`: eventとhash-bounded evidenceをlocal DBへ記録
- `Stop`: final answerのlineageを検査
- `PreToolUse` block: 既定では無効
- MCP PreToolUse block: 既定では無効
- runtime redact / `updatedInput`: 無効

protected sourceは自動登録しません。初期化が作るのは空のmanifestだけです。source候補の追加は、候補、理由、対象pathをユーザーへ提示し、明示的な承認を得た後に行います。

## package CLIの開発install

Pluginと同じCoreを通常のPython packageとして検証できます。

```bash
python3.11 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install .
.venv/bin/tooluseproxy --version
```

wheel install後はcheckout外のdirectoryからも`tooluseproxy init`、`doctor`、`status`、`trace`、内部Hook entrypointを実行できます。

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
