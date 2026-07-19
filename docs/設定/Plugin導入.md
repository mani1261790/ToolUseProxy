# Codex Plugin 導入

ToolUseProxyのCodex Pluginは、repository全体ではなく、生成時にallowlist化した自己完結Plugin bundleとして配布します。`.codex-plugin/plugin.json`、`hooks/hooks.json`、setup skill、pure Python runtimeが同じversionに含まれます。Hook commandにcheckout先の絶対pathは書かず、Codexが渡す`PLUGIN_ROOT`からcodeを起動し、mutableなSQLite stateは`PLUGIN_DATA`へ保存します。

## 現在のsupport範囲

- Python 3.11 / 3.12。3.13以降は現在未対応
- macOS: local package、relocated Plugin bundle、Codex CLIのisolated local marketplace install、alpha.1→alpha.3 upgrade / safe rollbackを検証。Python 3.12 package smokeはCIで継続確認
- Linux: Ubuntu CIでPython 3.11 / 3.12のfull suite、package、relocated Plugin bundle、wheelのcheckout外実行を検証。Codex CLI marketplace installの実環境E2Eは未検証
- Windows: `py -3.11`を使うlauncherを同梱するexperimental範囲。実機検証は未完了で、protected-source登録workflow全体は現在未対応
- Hook内network access、remote embedding、telemetry: なし

詳細は[サポート範囲と既知の制限](../../SUPPORT.md)と[プライバシーとデータ保持](../../PRIVACY.md)を参照してください。Windows実機とLinux実Codex CLIのcross-platform E2Eはpublic alphaまでの残作業です。最新の優先順位は[実装タスク計画](../運用/実装タスク.md)を参照してください。

## 現在versionと更新

現在versionは`0.1.0-alpha.3`です。類似度profile v2とruntime graph v19を導入しています。既存sessionを次に解析する際は古いcandidate indexを使い続けず、そのsessionのgraphとindexを一度全再構築します。

SQLite schemaはv4のままなので、alpha.3への更新だけを理由にDB migrationや`init`を再実行する必要はありません。将来SQLite schema更新を伴うreleaseで`doctor` / `status`がupgrade必要と報告した場合だけ、Hook外で明示的な`init --codex`を実行します。更新後は新しいHook definitionをreview・trustして新しいtaskを開始し、`doctor` / `status`を実行してください。

## install

現在のalpha開発版は、可変なremote `main`を実行元にしないため、checkoutをrepository-local marketplaceとして追加できます。

```bash
codex plugin marketplace add /absolute/path/to/ToolUseProxy
codex plugin add tooluseproxy@tooluseproxy
```

この絶対pathはmarketplaceを登録する開発時の1回だけに使い、Hook definitionには保存されません。公開配布はimmutableなrelease tagまたはcommitへpinし、Plugin version、checksum、release notes、変更後のHook再review方針を揃えてから有効にします。remote `main`を直接実行元にはしません。

### clean marketplace bundleの作成

配布候補を検証するときはrepository rootをそのまま渡さず、専用builderで再現可能なZIPを作ります。

```bash
python3.11 scripts/build_plugin_bundle.py --outdir dist
```

出力は`dist/tooluseproxy-plugin-<version>.zip`です。同じsource treeから作ったZIPは同じSHA-256になります。展開後のrootにはmarketplace definitionがあり、その内側の`tooluseproxy/`だけがPlugin sourceです。

```text
extracted/
├── .agents/plugins/marketplace.json
└── tooluseproxy/
    ├── .codex-plugin/plugin.json
    ├── hooks/
    ├── skills/
    ├── hook_monitor/
    ├── tooluseproxy/
    └── tooluseproxy_plugin.py
```

```bash
codex plugin marketplace add /absolute/path/to/extracted
codex plugin add tooluseproxy@tooluseproxy
```

builderはruntime fileを明示的に選び、`.git`、`.github`、tests、内部設計docs、scripts、cache、virtual environment、local DB、legacy Hook entrypointをZIPへ含めません。展開したmarketplace rootにはREADME、support、privacy契約を含めますが、marketplace metadataとこれらの文書はinstall済みPluginには入りません。ZIPはまだ署名済みpublic releaseではないため、checksum公開、SBOM、release notes、LICENSE gateを満たすまでは開発・dogfood用途として扱います。

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

`status: active`になるには、DB schema、canonical workspace登録、`protected_sources.json`の3つが同じworkspaceについて有効である必要があります。schema v2 selectorを使うmanifestでは、`doctor` / `status`が宣言だけでなく現在fileのkey / JSON Pointer解決まで検証します。schema省略またはschema v1のlegacy manifestはruntime互換として有効なため`active`を維持しますが、`runtime_readable: true`、`registration_writable: false`、`migration_required: true`として、新しいsourceを登録する前に明示migrationが必要であることを区別します。SQLite schema upgradeが必要な場合はHook内でmigrationせず、再度`init --codex`を実行します。

## safe default

- `PostToolUse`: eventとhash-bounded evidenceをlocal DBへ記録
- `Stop`: final answerのlineageを検査
- `PreToolUse` block: 既定では無効
- MCP PreToolUse block: 既定では無効
- runtime redact / `updatedInput`: 無効

protected sourceは初期化時やHook実行中には自動登録しません。初期化が作るのは空のmanifestだけです。

### legacy manifestの明示migration

schema省略またはschema v1のlegacy manifestは、selectorなしの従来形式としてruntimeで読み続けます。`init`、通常のHook、`doctor`、`status`はこのmanifestを暗黙に書き換えません。新しいsourceを登録する前に、coding agentは次のvalue-freeなplanを取得します。

```bash
sh "<PLUGIN_ROOT>/hooks/run_cli.sh" protect migrate plan \
  --workspace "$PWD" \
  --data-dir "<PLUGIN_DATA>" \
  --json
```

planはmanifestを変更せず、旧schemaが明示されていたか省略されていたか、移行先schema、source数、`sources`追加の要否、formatting policy、backup名、入力・結果manifest SHA-256、opaque migration revisionだけを返します。manifest本文、unknown fieldの値、source本文、selector候補は表示しません。移行は既存source entry、source配列と既存keyの相対順序、unknown top-level / source fieldを意味的に保持し、schema宣言だけをv2へ変更します。legacy manifestに`sources`がない場合だけ、従来の既定値と意味的に等価な空配列を補います。selectorは推測・追加しないため、既存sourceの保護範囲は移行前と同じです。

coding agentはこの変更、selectorを追加しないこと、format正規化、backup作成をユーザーへ説明し、表示したexact planへの明示承認を待ちます。setupや別fileの編集許可、source登録依頼だけではmigration承認になりません。承認後だけ、planが返したrevisionと入力manifest SHA-256を変更せず渡します。

```bash
sh "<PLUGIN_ROOT>/hooks/run_cli.sh" protect migrate apply \
  --migration-revision <MIGRATION_REVISION> \
  --expected-manifest-sha256 <MANIFEST_SHA256> \
  --workspace "$PWD" \
  --data-dir "<PLUGIN_DATA>" \
  --json
```

applyは任意の置換JSONを受け取らず、revisionに結び付いたplanだけをworkspace lock下で再検証します。元manifestのexact bytesは`PLUGIN_DATA`または明示`--data-dir`配下へ別inode・private modeのbackupとして保存し、v2 manifestはUTF-8、2-space indent、LF、末尾newlineへ正規化します。JSON comment、duplicate key、NaN / Infinityはstrict JSONとして受け入れません。manifestがplan後に変わった場合は適用せず、新しいplanを提示して再承認を得ます。途中停止やdurability不明時は同じrevisionとmanifest SHA-256でapplyを再実行します。

workspace lockが直列化するのはToolUseProxyの協調writer同士です。同一UIDの非協調的な外部editorはlockに従わないため、filesystemの最終再検証からatomic replaceまで、またはdurability再確認から完了確定までの競合を含む直列化は保証外です。このmigration workflowはPOSIX（macOS/Linux）のみ対応し、Windowsでは未対応です。

migration applyの承認はprotected source候補の承認を兼ねません。移行後に`doctor` / `status`でschema v2と`registration_writable: true`を確認し、対象sourceについて改めて次の提案・承認を行います。

### bounded offline scanによる候補発見

schema v2と`registration_writable: true`を確認後、coding agentは次の明示commandでworkspace内の`.env` / `.env.*` / JSON候補をoffline探索できます。

```bash
sh "<PLUGIN_ROOT>/hooks/run_cli.sh" protect scan \
  --workspace "$PWD" \
  --data-dir "<PLUGIN_DATA>" \
  --json
```

`scan`はVCS、依存関係、virtual environment、build / cache directory、symlink、ToolUseProxyのruntime dataを除外し、深さ、entry数、file数、総read bytes、candidate数の固定上限内でだけ読みます。network、remote embedding、Hook runtimeは使いません。sourceとmanifestに対してread-onlyですが、local runtime DBにはvalue-freeな候補・review監査と内部再検証用のsource hash/statを保存します。sourceの値や本文断片、source hash、absolute pathは表示せず、review監査にもraw本文を保存しません。外向きには相対path、検出rule、confidence、dotenv keyまたはJSON Pointer、上限と集計値だけを返します。

1回のscanが表示するreview candidateはstableな相対path順の1件だけです。`remaining_candidate_count`は続きの有無、`continuation_required`は再scanが必要か、`scan_complete`は固定上限内で探索を完了できたかを示します。`scan_complete: false`の場合、agentは候補がないと言い切らず、到達した上限reasonと未探索範囲が残ることを説明します。同一内容とdetector versionでreject / ignoreされた候補は再提示せず、登録済みや承認処理中もcountにだけ反映します。

### Plugin更新時のpending候補

Plugin更新でprotected-source detector versionが変わると、更新前の`proposed`候補は現在の検出契約では未承認として扱えません。古いcandidate ID / opaque revisionを使った`approve`、`reject`、`ignore`はvalue-freeな`candidate_detector_stale`で終了し、manifest、candidate row、review rowを変更しません。coding agentはcached commandを再利用せず、`protect scan`を再実行して現在versionの新しいcandidate IDとrevisionを取得し、そのproposalをユーザーへ提示して新しい明示承認を得ます。同じ現在versionでの再scanはcandidate IDを維持してrevisionを回転させます。

reject / ignoreの抑止は同じfile内容とdetector versionの組に限定されるため、旧versionのnegative reviewは新versionの候補を抑止しません。一方、すでに`approved`となりmanifestへ登録されたsourceはuser-owned manifestをauthorityとして維持し、detector更新だけを理由に削除・再登録・selector変更しません。更新前に開始済みの`approving`または完了済み`approved`候補へ同じexact approve入力を再送する操作は、途中停止からのdurability recoveryに限って許可されます。新しい提案の承認には流用しません。

`PLUGIN_DATA`のcandidate / review監査はPlugin code更新後も保持します。通常のHookは候補scan、candidate migration、manifest変更を行いません。Plugin更新後は[現在versionと更新](#現在versionと更新)の手順を行ってからpending候補を再scanしてください。

### 明示pathのfallbackと候補承認

ユーザーまたはagentが対象pathを既に特定している場合、またはbounded scanの対象外を提案する場合は、従来の明示path commandを使います。

```bash
sh "<PLUGIN_ROOT>/hooks/run_cli.sh" protect suggest \
  --path config/secrets.json \
  --workspace "$PWD" \
  --data-dir "<PLUGIN_DATA>" \
  --json
```

`suggest`のsource / manifestに対するread-only性、value-freeなDB記録、外向きoutputの制限はscanと同じです。coding agentはscanまたはsuggestが返した提案entryをユーザーへ示し、そのexact proposalへの明示承認を得ます。承認後だけ、返されたopaque revisionとmanifest SHA-256を変更せず渡します。

```bash
sh "<PLUGIN_ROOT>/hooks/run_cli.sh" protect approve <CANDIDATE_ID> \
  --candidate-revision <OPAQUE_REVISION> \
  --expected-manifest-sha256 <MANIFEST_SHA256> \
  --workspace "$PWD" \
  --data-dir "<PLUGIN_DATA>" \
  --json
```

承認時はworkspace lockを取得してから候補を`proposed`から`approving`へ予約し、sourceのidentity・内容・selector解決とexpected manifest hashによる楽観的な事前条件を再検証します。lockは同一directoryの一時file、file fsync、atomic replace、directory fsync、DB確定または安全なreleaseまで保持し、その間の`reject` / `ignore`と別の承認試行を防ぎます。候補を1件approveするとmanifest hashが変わるため、別の候補に古いscanのrevision / hashを使ってはいけません。agentはapprove後にscanを再実行し、更新された次のexact proposalへ改めて明示承認を得ます。途中停止や一時的なstate errorでは、同じcandidate ID、opaque revision、manifest SHA-256のapprove入力を再実行します。exact登録の回復はdirectory fsyncと再検証に成功した後だけDBをapprovedへ進めます。workspace lockが直列化するのはToolUseProxyの協調writer同士です。同一UIDの非協調的な外部editorはlockに従わないため、filesystemの最終再検証からatomic replaceまで、またはdurability再確認からDB確定までの競合を含むfilesystem / DB横断の直列化は保証外です。sourceまたはmanifestが提案後に変わっていれば登録せず、再scanまたは再提案を要求します。`reject` / `ignore`は同じ内容・検出versionの再提示を抑止します。CLIは任意entryを承認時に受け取らないため、agentが提案JSONを書き換えて登録することはできません。この登録workflowは現在POSIX（macOS/Linux）のみ対応し、Windowsでは`protect scan / suggest / approve / reject / ignore`を未対応とします。

workspace探索は明示的なoffline `protect scan`に限定し、`init`やHook中では実行しません。一括承認、無承認の自動登録、scanの上限引き上げoptionはありません。legacy manifestはruntime読み取り互換を維持しますが、scanはsource fileを読む前に値のない`manifest_schema_legacy`で終了します。coding agentは`protect migrate plan`を提示せずに独断でv2へ変更しません。

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

wheel / sdist / Plugin ZIPはruntime allowlistへ固定し、Python 3.11 / 3.12でcheckout外installをCI検証します。release candidate builderはmanifest、SHA256SUMS、CycloneDX 1.7 SBOM、release notes候補を一括生成します。immutable tag、GitHub pre-release、LICENSE gateは[実装タスク計画](../運用/実装タスク.md)と[#19](https://github.com/mani1261790/ToolUseProxy/issues/19)で管理します。

## disable / uninstall

Pluginを外すときはCodexのPlugin commandを使います。

```bash
codex plugin remove tooluseproxy@tooluseproxy
codex plugin marketplace remove tooluseproxy
```

Pluginをremoveしてもlocal監査dataは自動削除されません。保持する場合は追加操作は不要です。削除する場合は、関連taskとToolUseProxy processを止め、install済みpackageまたは同じrelease artifactのlauncherからvalue-freeなplanを作ります。

```bash
sh "<PLUGIN_ROOT>/hooks/run_cli.sh" uninstall plan \
  --data-dir "<PLUGIN_DATA>" \
  --json
```

管理file数、byte数、管理外entry数を確認し、同じ`data_dir`に対して出力tokenを明示的に渡します。

```bash
sh "<PLUGIN_ROOT>/hooks/run_cli.sh" uninstall apply \
  --data-dir "<PLUGIN_DATA>" \
  --confirmation-token "<CONFIRMATION_TOKEN>" \
  --json
```

削除対象はSQLite database / sidecar、migration backup、manifest backupだけです。管理外fileは残し、plan後に内容が変わった場合はstale tokenを拒否します。workspace manifestやprotected source本体、symlink先、package codeは削除しません。secure eraseやfilesystem snapshotの削除は保証しません。

alpha.1からalpha.3候補へのupgrade / safe rollback手順と検証結果は[Pluginライフサイクル](../運用/Pluginライフサイクル.md)を参照してください。将来versionとcross-platformでの反復は引き続きpublic alphaのrelease gateです。

## trustとfailure時の挙動

- 未trustのPlugin HookはCodex側でskipされます
- Python 3.11が見つからない場合、launcherは理由をstderrへ出してfail-openします
- DBがない、古い、新しすぎる、不完全な場合、runtime HookはDBを変更せずfail-openします
- SQLite migrationは`init`だけ、protected source manifestのv1→v2 migrationは明示承認後の`protect migrate apply`だけが行い、通常のPlugin HookはDDL、backfill、manifest migrationを実行しません
- 壊れたmanifestや未登録workspaceは`doctor/status`でactive扱いにしません
