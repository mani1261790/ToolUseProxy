# Codex Plugin 導入

ToolUseProxyのCodex Pluginは、repository全体ではなく、生成時にallowlist化した自己完結Plugin bundleとして配布します。`.codex-plugin/plugin.json`、`hooks/hooks.json`、setup skill、pure Python runtimeが同じversionに含まれます。Hook commandにcheckout先の絶対pathは書かず、Codexが渡す`PLUGIN_ROOT`からcodeを起動し、mutableなSQLite stateは`PLUGIN_DATA`へ保存します。

## 現在のsupport範囲

- Python 3.11 / 3.12。3.13以降は現在未対応
- macOS: local package、relocated Plugin bundle、Codex CLIのisolated local marketplace install、alpha.1→alpha.7 upgrade / safe rollbackを検証。Python 3.12 package smokeはCIで継続確認
- Linux: Ubuntu CIでPython 3.11 / 3.12のfull suite、package、relocated Plugin bundle、wheelのcheckout外実行を検証。Codex CLI marketplace installの実環境E2Eは未検証
- Windows: `py -3.11`を使うlauncherを同梱するexperimental範囲。実機検証は未完了で、protected-source登録workflow全体は現在未対応
- Hookは常にlocal-only。remote embeddingとtelemetryはなし。実験的なExternality Judgeを別途明示設定すると、Hookは値非保持要約をlocal queueへ保存し、初見unknown＋protected flowを保守的にdeny。選択済みproviderへの送信はHook外workerの明示実行時だけ

詳細は[サポート範囲と既知の制限](../../SUPPORT.md)と[プライバシーとデータ保持](../../PRIVACY.md)を参照してください。Windows実機とLinux実Codex CLIのcross-platform E2Eはpublic alphaの既知の未検証範囲です。最新の優先順位は[実装タスク計画](../運用/実装タスク.md)を参照してください。

## 導入前の安全境界

導入、候補登録、更新、削除を始める前に、次の4点を一続きの契約として確認してください。

1. [プライバシーとデータ保持](../../PRIVACY.md): raw Hook payloadやprotected source chunkがlocal SQLiteへ平文で残り得て、自動expirationやsecure eraseがない
2. [サポート範囲と既知の制限](../../SUPPORT.md): Hook内部エラーは原則fail-openで、Windowsの登録workflowはalpha未対応
3. [Plugin upgrade / rollback rehearsal](../運用/Pluginライフサイクル.md): rollbackは新DBを旧runtimeでdowngradeせず、upgrade前backupを別data directoryへ復元する
4. この文書の[disable / uninstall](#disable--uninstall): Plugin codeのremoveはdata削除を意味せず、exact planへの別の明示承認が必要

alphaのthreat modelは、Pluginやcoding agentの無承認manifest変更、stale proposal、同じ候補の再提示、意図しないmanaged-data削除を防ぐことを対象にします。同一OS accountで任意file / SQLite writeができる攻撃者、Codexや外部tool自体のnetwork通信、filesystem snapshotや外部backupからの復元は防御範囲外です。workspace lockはToolUseProxyの協調writerだけを直列化し、同一UIDの非協調editorとの完全なfilesystem CASは保証しません。

## 現在versionと更新

現在のrelease candidateは`0.1.0-alpha.7`です。類似度profile v2とruntime graph v19を維持し、通常projectで内部pathを貼らずに行える限定setup、Markdown全文の1件ずつ登録、正確で読みやすい日本語の承認・block案内を追加しています。操作ごとの承認UIがあるmodeでは通常2回、UIがなく現在の権限でPlugin dataへaccessできるmodeでは0回で同じ固定setupを実行します。alpha.6候補は後者を誤って停止扱いにしたため`public-alpha`へ昇格していません。既存sessionを次に解析する際は古いcandidate indexを使い続けず、そのsessionのgraphとindexを一度全再構築します。

Codex CLIはPluginごとの自動更新commandではなく、登録済みGit marketplaceを明示的に更新する`codex plugin marketplace upgrade`を提供します。moving refを登録している場合、更新されたmarketplace snapshotからinstall済みPluginも置き換わります。ToolUseProxyは次の2方式を分けます。

| 方式 | `--ref` | 用途 | 更新 |
| --- | --- | --- | --- |
| public alpha更新チャンネル | `public-alpha` | 通常のdogfood / pilot | `marketplace upgrade`で明示更新 |
| immutable version固定 | `v0.1.0-alpha.7` | 再現実験、監査、rollback | tagは動かないため自動的に別versionへ進まない |

`public-alpha`はreview済み・CI green・公開済みのalpha release commitだけへfast-forwardする保護branchです。開発途中の`main`を実行元にはしません。更新は自動ではなく、ユーザーがcommandを実行した時だけ行われます。

Codex Desktopも同じmarketplaceからPluginをinstallし、複数workspaceで利用できます。Plugin codeのinstallはCodex環境単位ですが、初期化、protected source、runtime設定、監査dataはworkspace単位です。新しいworkspaceを使うたびに、そのworkspaceでbundled setup skillを実行し、保護対象を個別にreviewします。2026-08-09のmacOS実機runでは、3 Hookのreview / trust、PreToolUse / PostToolUse / Stop、public allow、file-backed protected payloadの実行前block、data migration、backup rollback、Disableなしの直接Removeを確認しました。fresh setup profile runは承認2回、public side effect 1、protected side effect 0、exact block 1、raw exposure 0で`passed`です。Desktop task履歴のshell名`exec_command`とHook APIのcanonical名`Bash`は別namespaceであり、画面表示だけでなくHook trust、定義hash、値なしmarker、Hook DB、task記録を証拠にします。hosted Web SearchはPreToolUse / PostToolUse Hookの対象外です。

SQLite schemaはalpha.3からalpha.7までv6のままなので、alpha.5からalpha.7への更新だけを理由にDB migrationを実行する必要はありません。古いschemaから更新した場合、またはbundled setup skillがsetup必要と判定した場合だけ、Hook外で明示的なatomic setup profileを適用します。更新後は変更されたHook definitionをreview・trustして新しいtaskを開始し、bundled skillのread-only verificationを実行してください。

## install

通常のpublic alpha利用では、保護された更新チャンネルを指定します。

```bash
codex plugin marketplace add mani1261790/ToolUseProxy --ref public-alpha
codex plugin add tooluseproxy@tooluseproxy
```

versionを固定する場合は最初のcommandを次に置き換えます。

```bash
codex plugin marketplace add mani1261790/ToolUseProxy --ref v0.1.0-alpha.7
```

install後はCodexが表示するPlugin source、version、3つのHook definitionを確認してtrustします。ToolUseProxyはこのreviewを迂回しません。以前trustしたHookでも、matcher、command、sourceなどの定義が変わると`modified`になり、再reviewが必要です。release artifact、checksum、SBOM、release notesは公開後の[`v0.1.0-alpha.7`](https://github.com/mani1261790/ToolUseProxy/releases/tag/v0.1.0-alpha.7)で確認できます。

### CLIで更新する

`public-alpha`を登録した環境では、新release公開後に次を実行します。

```bash
codex plugin marketplace upgrade tooluseproxy
codex plugin list --json
```

更新後は表示されたversionを確認し、変更されたHook definitionをreview・trustして、新しいCodex taskを開始します。対象projectで「ToolUseProxyの準備をして」と依頼すると、通常と同じsetup適用と読み取り確認を行います。同じ設定なら変更せず確認だけを完了し、異なる設定は上書きしません。schemaまたは保護対象リストの更新が必要な場合は、setup skillが値を表示しない更新計画を説明し、その更新だけを別に確認します。利用者が`doctor`、`status`、`init`、`PLUGIN_DATA`を組み立てる必要はありません。Plugin dataはmarketplace cacheと分離されるため、Plugin codeの置換では削除されません。

固定tagを登録している場合、`marketplace upgrade`は同じtagを再取得するだけで別versionへ進みません。将来の別tagへ移るには、Pluginとmarketplaceをremoveし、新しいtagを指定してmarketplaceとPluginを追加します。この操作でも`PLUGIN_DATA`は保持されます。managed dataを削除する`uninstall apply`は更新には使いません。

### rollback

codeだけを以前のversionへ戻す場合は、Pluginとmarketplaceをremoveし、戻したいimmutable tagを指定して再追加します。新しいschemaを古いruntimeで無理に開かないでください。旧runtimeが現在DBをinactiveと判定する場合は、upgrade前に`init --codex`が作成したSQLite backupを別の`PLUGIN_DATA`へ復元します。現在DBは上書きせず保持します。検証済みの手順は[Pluginライフサイクル](../運用/Pluginライフサイクル.md)にあります。

checkoutから開発版を試す場合だけ、repository rootをlocal marketplaceとして追加します。

```bash
codex plugin marketplace add /absolute/path/to/ToolUseProxy
codex plugin add tooluseproxy@tooluseproxy
```

この絶対pathはmarketplaceを登録する開発時の1回だけに使い、Hook definitionには保存されません。remote `main`を直接実行元にはしません。

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

builderはruntime fileを明示的に選び、`.git`、`.github`、tests、内部設計docs、scripts、cache、virtual environment、local DB、legacy Hook entrypointをZIPへ含めません。展開したmarketplace rootにはREADME、support、privacy / security契約、Apache-2.0 LICENSEを含め、install済みPluginにもLICENSEを残します。公開済みZIPを利用する場合はReleaseのSHA256SUMSと照合してください。

installまたはHook定義の更新後は、Codexが示すHook definitionを確認してtrustします。ToolUseProxyはこのreviewを迂回しません。PreToolUse / PostToolUse / Stopがすべて`trusted`であり、`modified` / `untrusted`が残っていないことを確認してください。新しいPlugin componentとskillを確実に読み込むため、trust後は新しいtaskを開始します。

## 初期化

通常のmarketplace installでは、setup skillがインストール済みlauncherからPlugin rootを取得し、Codex公式のPlugin store契約に従って専用data directoryを解決します。Plugin rootが`CODEX_HOME/plugins/cache/<marketplace>/<plugin>/<version>`に厳密に収まり、manifestのPlugin名が一致する場合だけ、対応する`CODEX_HOME/plugins/data/<plugin>-<marketplace>`を使用します。layout、identity、manifestのどれかが不一致なら推測せず停止します。

新しいworkspaceの通常setupは次の2コマンドです。1つ目はworkspace設定が空であることを前提条件に、初期化と3つの保護設定を原子的に適用します。2つ目は変更を伴わない一括確認です。既存設定が同じなら再実行はidempotentで、異なる設定が1件でもあれば上書きしません。

```bash
sh "<PLUGIN_ROOT>/hooks/run_cli.sh" setup apply file-payload-exact \
  --codex \
  --expect-empty-settings \
  --workspace "$PWD" \
  --json

sh "<PLUGIN_ROOT>/hooks/run_cli.sh" setup verify file-payload-exact \
  --workspace "$PWD" \
  --json
```

利用者へ`database_missing`診断、absolute path、初期化commandの貼り直しを要求しません。Hook診断は保護が動作していないことを知らせる安全側の補助情報であり、通常setupのpath discovery APIではありません。

以下はHook障害診断と手動Phase B検証のために残す低level契約であり、通常利用者がpathやcommandをコピーするための手順ではありません。

Plugin Hookは未初期化DBを検出してもschema migrationやworkspace変更を行わず、fail-openで終了します。PreToolUse / PostToolUseでは`additionalContext`、Stopではadvisoryな`systemMessage`を使い、未保護であることとCodexへ準備を依頼する短い案内だけを返します。診断へ初期化command、Plugin root、Plugin data pathは含めません。Python不足、runtime起動失敗、内部policy評価失敗も同じJSON契約で通知し、例外本文やHook inputは診断へ含めません。以前のstderrだけに出す形式はDesktopで表示されないため廃止しました。ただし、案内の表示自体をdispatch証拠にはせず、Desktopでは[Desktop Phase B](../運用/DesktopPhaseB.md)のtrusted probeが記録したdata pathだけを使います。cacheやprocess環境から`PLUGIN_DATA`を推測しません。

通常setupの固定profileは次を行います。

- `PLUGIN_DATA/events.db`を候補、監査、workspace runtime設定、Externality Judge job / reviewを含むschema v7へ初期化または明示的にmigrationする
- 古いschemaをmigrationする前にSQLite backupを作る
- canonical workspace rootをDBへ登録する
- `protected_sources.json`がない場合だけ、schema v2の空manifestをatomicに作る
- 既存の有効なmanifestは変更しない

`PLUGIN_DATA`は通常workspace外にあります。Codexが
`workspace-write`で動いている場合、coding agentはこのcommandを通常権限で先に
試してはいけません。対象commandだけに対するsandbox外実行の承認を要求し、
`exec_command`に`require_escalated`相当の機構があるsurfaceではそれを使います。
Full Accessは必須条件ではありません。1コマンド単位の昇格手段がなくても、現在の
permission profileがPlugin dataへのaccessを明示的に許可している通常installでは、
agentが短い内容説明を会話上へ示してから、選択済み権限のまま固定setupとread-only
verificationを続行します。この場合、承認UIの表示回数は0として正確に報告します。
利用者へ長い内部commandのコピーを通常導線として要求しません。必要pathへのaccessが
許可されていない場合、または`Operation not permitted`になった場合は停止し、別pathや
広いcommandへ自動的に変えて再試行しません。manual Phase Bの1コマンド単位承認契約は
この通常install向けfallbackの対象外です。

なお、agentが`require_escalated`相当を付けたことと、hostが個別承認UIを表示した
ことは同じではありません。Codex DesktopがUIを表示せず実行する場合もあるため、
検証時はsessionのtool argumentsと、人が実際に見た画面を別々に記録します。
承認UIが出なかった場合は「理解した」と推測せず、`not shown`として扱います。

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

PreToolUseとfile-backed payload policyは、環境変数だけでなくworkspace単位の永続設定でも明示opt-inできます。現在値、変更方法、優先順位、revision競合の扱いは[Workspace runtime設定](Runtime設定.md)を参照してください。

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

wheel / sdist / Plugin ZIPはruntime allowlistへ固定し、Python 3.11 / 3.12でcheckout外installをCI検証します。release candidate builderはApache-2.0 metadata、manifest、SHA256SUMS、CycloneDX 1.7 SBOM、release notes候補を一括生成します。公開済みのimmutable tagとGitHub pre-releaseは[Releases](https://github.com/mani1261790/ToolUseProxy/releases)で確認できます。

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

alpha.1からalpha.7へのupgrade / safe rollback手順と検証結果は[Pluginライフサイクル](../運用/Pluginライフサイクル.md)を参照してください。将来versionとcross-platformでの反復は引き続きpublic alphaの検証課題です。

pre-release候補で実際のHook trust、agent説明、実tool invocationを検証するときは、通常workspaceや実secretを使わず、[Pluginドッグフードのmanual Phase B](../運用/Pluginドッグフード.md#manual-phase-b)を実行します。prepare出力はlocal pathを含むため公開せず、raw値とpathを除外したverify結果だけをrelease evidenceとして扱います。

## trustとfailure時の挙動

- 未trustのPlugin HookはCodex側でskipされます
- 一度trustした定義でも、matcherやcommandなどが変わると`modified`になり、再reviewするまでskipされます
- Desktopでは正常終了したHookのstderrが画面へ表示されないため、Pluginの非active診断はphase別JSON stdoutを使います。表示の有無だけでは発火を判定しません
- Python 3.11 / 3.12が見つからない場合も、launcherは同じ非blocking JSONで理由を返してfail-openします
- DBがない、古い、新しすぎる、不完全な場合、runtime HookはDBを変更せずfail-openします
- SQLite migrationは`init`だけ、protected source manifestのv1→v2 migrationは明示承認後の`protect migrate apply`だけが行い、通常のPlugin HookはDDL、backfill、manifest migrationを実行しません
- 壊れたmanifestや未登録workspaceは`doctor/status`でactive扱いにしません
