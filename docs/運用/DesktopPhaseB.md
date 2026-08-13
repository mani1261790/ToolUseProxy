# Codex Desktop Phase B

Issue [#53](https://github.com/mani1261790/ToolUseProxy/issues/53)では、CLI TUIの結果を流用せず、Codex Desktop / GUI上のPlugin install、Hook review、public allow、protected block、disable / remove、同一版reinstallを人と実証します。

## 現在地

専用harnessは実装済みです。2026-07-28以降、Codex Desktop同梱のCodexで人による実機確認を行いました。2026-08-09までの結果は次のとおりです。

| 段階 | 結果 |
| --- | --- |
| HomeのPlugins検索から専用Pluginをinstall | 成功 |
| 最初のPreToolUse / PostToolUse / Stopをreview | 成功 |
| その後に変更したPreToolUse / PostToolUse定義 | `trustStatus: modified`。再reviewされておらず実行対象外 |
| Desktop task履歴上のlocal shell名 | `exec_command` |
| Hook matcherに渡るcanonical tool名 | `Bash` |
| 最新定義のtrusted Hook probe | PreToolUse / PostToolUse / Stop各1回、余分なtool call 0件で成功 |
| `workspace-write`でのPlugin data操作 | 10コマンドすべてに1回限定の`require_escalated`と日本語の理由を付けて発行 |
| 個別commandの承認UI | 表示を確認。短いplain textで内容は理解できたが、初期設定で約10回の承認が必要 |
| 保存済み2026-08-09 run | 最新exit-code wrapperを厳密に解析し、public 1 / protected 0 / exact block 1 / raw exposure 0で正式な`passed` |
| 2-command setup | fresh Desktopで承認UI 2回を確認。説明はある程度理解可能。public 1 / protected 0 / exact block 1 / raw exposure 0で正式な`passed` |
| public / protected call | publicは実行、protectedはPreToolUseが実行前block |
| disable / remove / 同一版reinstall | 管理DBとruntime設定を保持したまま完走 |
| final cleanup | Plugin、Marketplace、管理データ、synthetic workspaceを削除。他のPlugin / Marketplace一覧は開始時と一致 |
| Codex config | 非アクティブなproject / Hook trust履歴が残り、開始時のfile hashには戻らない |

以前は、Full AccessとDefaultの両方で最初の無害な`true`に初期化案内が表示されなかったことから、DesktopのHook dispatcherまで到達していない可能性を疑いました。しかし、これは根拠として不十分でした。PreToolUse / PostToolUseは定義変更によってtrustが無効になっており、正常終了したHookのstderrはDesktop画面へ表示されないためです。

Desktopのtask履歴で使われる`exec_command`は、Hook matcherのtool名ではありません。CodexがPreToolUse / PostToolUseへ渡すcanonical名はDesktopでも`Bash`です。したがってPluginのmatcherは`Bash`を使い、`exec_command`へ変更しません。ToolUseProxy内部の互換レイヤーはsession由来payloadなどの解析用として保持しますが、Hookを有効にする条件とは分けます。

最新runでは、3 Hookの`trustStatus`と定義hashを機械確認した後、値を含まない専用markerでPreToolUse、PostToolUse、Stop各1件を確認できました。markerはrun固有nonceでhash化したsession IDとtool-use IDに結び付き、別taskのHook eventでは合格できません。UIに診断が表示されるかどうかは合格条件にしていません。

以前のrunは、`workspace-write`のDesktop taskからworkspace外の`PLUGIN_DATA`へ通常権限で`init`し、OS拒否で停止しました。setup skillとPhase B promptを直した最新runでは、Plugin dataを実際に触る10コマンドすべてが`require_escalated`、空でない日本語の理由、再利用可能な`prefix_rule`なしで発行され、初期化からprotected blockまで完走しました。

ただし、承認の理由は外部通信ではありません。Desktop taskのworkspace外にある`PLUGIN_DATA`をCLIが読み書きするため、各commandに一時的な権限昇格が必要になります。2026-08-09のfresh runでは、短いplain textの説明、継続中commandのwait、public allow、protected blockまで機能上は完走しました。Hook review、command説明、block説明はいずれも理解できたという評価でしたが、初期設定で約10回の承認が必要な点は製品UXとして残っています。

承認理由は160文字以内のplain textとし、`行うこと：`、`変更されるもの：`、`外部通信：`、`確認が必要な理由：`の順で示し、最後に`この内容で実行してよいですか？`と尋ねます。ToolUseProxy側から許可・拒否を指示しません。absolute path、Markdown、過去の説明への参照を含めません。同じ文を承認直前とtool callのjustificationへ渡します。command toolがcell IDを返した場合は、CLIを再実行せず、そのIDによるwaitだけで元commandの完了まで待ちます。

Issue [#63](https://github.com/mani1261790/ToolUseProxy/issues/63)では、`init`と3つの明示設定を固定`file-payload-exact` profileの一括適用へ、`doctor` / `status` / `config show`を一つのread-only verificationへまとめました。3設定は一つのSQLite transactionと一つのrevisionで更新し、stale revisionでは変更せず停止します。新しいharnessはprofile apply 1回、verification 1回、再利用可能permission 0件を必須にします。Desktop session parserは、setupとsendではexactな`text(JSON.stringify(r));`だけを受理し、`text(r.output);`は単独probeとcontext・setup skillの固定読み取りだけに限定します。任意statement、追加command、同じoutput-only wrapperによるsetupやsendは拒否します。2026-08-09のfresh runは全checks trueで正式な`passed`です。

Plugin自体も、未初期化・Python不足・runtime起動失敗・内部policy評価失敗などの非active診断をstderrではなくCodexが解釈できるphase別JSON stdoutで返すように改修しました。例外本文とHook inputは診断へ含めません。これは利用者へ次の操作を伝えるための改善です。一方、dispatchの合否は引き続きmarkerで判定し、診断が画面に見えたかどうかとは分離します。

この切り分けは、Desktop同梱版と同じ`rust-v0.146.0-alpha.3.1`のCodex sourceでも確認しました。`exec_command` handlerはHook呼び出し時にcanonical名`Bash`へ変換され、Hook discoveryは`modified`な定義をactive command一覧へ含めません。PreToolUseのcommand HookはstdoutのJSONを応答として読みます。根拠は[exec_command handler](https://github.com/openai/codex/blob/rust-v0.146.0-alpha.3.1/codex-rs/core/src/tools/handlers/unified_exec/exec_command.rs#L408-L418)、[canonical Hook名](https://github.com/openai/codex/blob/rust-v0.146.0-alpha.3.1/codex-rs/core/src/tools/hook_names.rs#L53-L56)、[Hook discovery](https://github.com/openai/codex/blob/rust-v0.146.0-alpha.3.1/codex-rs/hooks/src/engine/discovery.rs#L535-L585)、[PreToolUse実行](https://github.com/openai/codex/blob/rust-v0.146.0-alpha.3.1/codex-rs/hooks/src/events/pre_tool_use.rs#L207-L293)です。

したがって、READMEとSUPPORTでは次を区別します。

- DesktopでPluginをinstallできる: 確認済み
- Desktopで最初のHook reviewを行える: 確認済み
- Hook定義を変更すると再reviewが必要になる: 確認済み
- DesktopのHook matcherでshellを表すcanonical名: `Bash`
- Desktopのtool useにToolUseProxy Hookが発火する: trusted probeで確認済み
- workspace外のPlugin dataへ通常権限で初期化できる: できない。1コマンド単位の権限昇格が必要
- Desktopでprotected payloadを実行前blockできる: 確認済み
- 個別commandの承認UIが表示される: 確認済み
- 個別commandの承認文を人が理解できる: 短文化後のrunで確認済み
- 初期設定の承認回数が実用的である: fresh runで2回を確認。説明は「ある程度わかりやすかった」と評価

Desktop / GUI上で今回のfile-backed exact-only保護が動くことは確認でき、機能とlifecycleは完走しました。保存済みrunと2-command setupのfresh runは、Desktop task記録、Hook DB、markerの相互照合まで正式な`passed`として記録済みです。fresh runのcommand承認は2回で、再利用可能permissionは0件でした。

2026-07-31にdisable、remove、同一版reinstall、final remove、cleanupを完走しました。Plugin登録、検証用Marketplace、約111MBの管理データ、synthetic workspaceは削除され、無関係なPlugin / MarketplaceのIDと設定は保持されています。一方、Codexは削除済みworkspaceのproject設定と、削除済みPluginのHook trust履歴を`config.toml`へ残しました。開始時のconfig本文を保存していないため自動編集はせず、`restored_with_inactive_config_residue`としてaggregate reportへ明記しています。該当Pluginが存在しないため、この履歴だけでHookが実行されることはありません。

同一版reinstallは「Plugin codeを削除しても`PLUGIN_DATA`の設定と監査DBが残り、再install時に再利用されること」を確認します。本物のupdateは異なる二つのimmutable versionが必要です。同じZIPを入れ直した結果をupdate成功とは数えません。

異versionのupdate、schema migration、安全なrollback、DisableなしのRemoveはIssue [#62](https://github.com/mani1261790/ToolUseProxy/issues/62)で扱います。専用harnessと自動testは実装済みで、次はDesktop実機runです。実装境界、人が行う操作、安全停止条件は[Codex Desktop update / rollback 検証計画](DesktopUpdateRollback.md)を正本にします。

## 安全境界

- 最初の`plan`は共有`~/.codex`を変更しない
- ToolUseProxyのPluginまたは同名系marketplaceが既にあれば衝突として停止する
- 検証用marketplaceは`tooluseproxy-desktop-phase-b`、Plugin IDは`tooluseproxy@tooluseproxy-desktop-phase-b`へ分離する
- 計測用launcherを加えたbundleにはrunごとの一意なSemVer prereleaseを付け、同じrelease version名の古いDesktop cacheを再利用しない
- 共有configとPlugin / marketplace一覧は変更直前にも比較し、plan後に変化していれば停止する
- Hook trustは迂回せず、Desktopで人が3件をreviewする
- PreToolUse / PostToolUse / Stopの`trustStatus`がすべて`trusted`であることを、送信テスト前に機械確認する。`modified` / `untrusted`なら停止する
- Desktop task履歴の`exec_command`をHook matcher名として流用せず、canonicalな`Bash`定義を確認する
- workspace外のPlugin dataへ書くsetup commandは通常権限で先に試さず、exactな1コマンドだけのsandbox昇格を要求する
- test sinkはnetworkへ接続せず、synthetic workspace内のmarkerだけを更新する
- verifierはDesktop session、Hook定義hash、dispatch marker、Hook DB、side-effect marker、Plugin source / versionを相互照合する
- verifierは全tool inputも確認し、指定context / setup skillのread、exactなToolUseProxy setup command、public / protected test call以外のWeb・MCP・編集・任意shellが1件でもあれば不合格にする
- cleanup-planでmanaged dataの件数・file数・byte数・未管理entry数とexact uninstall tokenを固定し、apply中に別の削除planへ差し替えない
- cleanupはPhase B専用dataとmarketplaceだけを削除し、未管理dataと無関係なPlugin / marketplaceを保持する。途中失敗時はdata削除前後・marketplace削除前後の保存済み段階から再開する

実secretや普段のworkspaceでは実行しません。rootはrepository外の本人だけが読める絶対pathを使います。

## 実行順序

clean commitから、まずread-only planを作ります。

```bash
python3.11 scripts/manual_desktop_phase_b.py plan \
  --root /Users/mani/.tooluseproxy-dogfood/desktop-phase-b-YYYYMMDD
```

出力の`planned_changes`、`cleanup_contract`、衝突検査を読みます。`local_only.confirmation_token`はlocal情報なのでIssueやchatへ貼りません。内容に同意した場合だけ次へ進みます。

```bash
python3.11 scripts/manual_desktop_phase_b.py prepare \
  --root /Users/mani/.tooluseproxy-dogfood/desktop-phase-b-YYYYMMDD \
  --confirmation-token '<planが返したtoken>'
```

`prepare`が変更するのは、共有Codex configへの専用local marketplace追加だけです。Codex DesktopのHomeから`Plugins`を開き、`ToolUseProxy`を検索します。設定画面の`Plugins`はinstall済み一覧であり、新規installの検索導線ではありません。表示されるsourceとversionがguideに一致するPhase B marketplaceのPluginだけをinstallします。その後、次を実行します。

現行DesktopではPlugin名`ToolUseProxy`とmarketplace表示名`ToolUseProxy Desktop Phase B`が別の検索結果に見える場合があります。Phase B版にはrelease versionへrun固有のsuffixを加えたversionが表示されます。install後は画面上の件数だけで判断せず、CLI inventoryが`tooluseproxy@tooluseproxy-desktop-phase-b`の1件だけで、versionがguideと完全一致することをcheckpointで確定します。local marketplaceはPluginを`~/.codex`へ複製せず、検証rootのsourceを直接参照する場合があります。この場合、removeで消えるのはPlugin登録であり、local source本体は最終cleanupまで保持されます。

```bash
python3.11 scripts/manual_desktop_phase_b.py checkpoint-installed \
  --root /Users/mani/.tooluseproxy-dogfood/desktop-phase-b-YYYYMMDD
```

checkpointが示す3件をCodex DesktopのHook review画面で確認します。ToolUseProxy由来のPreToolUse、PostToolUse、Stopだけを対象にし、source、version、command root、件数が違えばtrustせず停止します。

review後、実際のHook状態を確認します。画面で一度trustを選んだ記憶だけでは進めません。定義変更後の`modified`も未trustとして停止します。

```bash
python3.11 scripts/manual_desktop_phase_b.py checkpoint-hooks-trusted \
  --root /Users/mani/.tooluseproxy-dogfood/desktop-phase-b-YYYYMMDD
```

このcheckpointが返すprobe用taskを開き、生成済みpromptどおり無害な`true`だけを実行します。次のcheckpointは、Desktop画面のstderrではなく、専用launcherが残した値なしmarkerと新しいsessionのhash化IDを照合します。別taskの`true`やStop eventでは合格しません。

```bash
python3.11 scripts/manual_desktop_phase_b.py checkpoint-hook-probe \
  --root /Users/mani/.tooluseproxy-dogfood/desktop-phase-b-YYYYMMDD
```

PreToolUse 1件、PostToolUse 1件、Stop 1件以上、`true` 1件が一致した場合だけ、返された本試験用taskを開きます。probeが失敗した場合はpublic / protected callへ進みません。

task完了後、理解度を本人の評価で記録します。

```bash
python3.11 scripts/manual_desktop_phase_b.py verify \
  --root /Users/mani/.tooluseproxy-dogfood/desktop-phase-b-YYYYMMDD \
  --hook-review-understood yes \
  --command-approval-understood not-shown \
  --block-explanation-understood yes \
  --additional-question-count 0
```

承認UIが表示された場合だけ`yes`または`no`を指定し、表示されなければ`not-shown`を指定します。`not-shown`は理解できなかったという意味ではなく、評価対象のUIが観測できなかったという意味です。

`functional_status`と`ux_status`は別判定です。機能が正しくても説明を理解できなければ`needs_followup`、承認UIが表示されなければ`not_observed`となり、コマンドの終了codeは1です。この場合も証跡は保存され、次のlifecycle確認へ進めますが、Phase B全体の合格とは扱いません。

Desktopで専用Pluginをdisableしてから確認します。

```bash
python3.11 scripts/manual_desktop_phase_b.py checkpoint-disabled \
  --root /Users/mani/.tooluseproxy-dogfood/desktop-phase-b-YYYYMMDD
```

続いてDesktopで専用Pluginをremoveし、codeが消えてdataとruntime設定が残ることを確認します。

```bash
python3.11 scripts/manual_desktop_phase_b.py checkpoint-removed \
  --root /Users/mani/.tooluseproxy-dogfood/desktop-phase-b-YYYYMMDD
```

同じ専用PluginをHomeの`Plugins`検索から再installし、同一版reinstall後に同じdataと設定revisionを再利用できることを確認します。

```bash
python3.11 scripts/manual_desktop_phase_b.py checkpoint-reinstalled \
  --root /Users/mani/.tooluseproxy-dogfood/desktop-phase-b-YYYYMMDD
```

もう一度Desktopでdisable、removeを行い、最終削除を確認します。

```bash
python3.11 scripts/manual_desktop_phase_b.py checkpoint-final-removed \
  --root /Users/mani/.tooluseproxy-dogfood/desktop-phase-b-YYYYMMDD
```

最後に削除対象を先に表示し、別tokenで明示承認します。`cleanup-plan`はこの時点でToolUseProxy本体のvalue-freeなuninstall planも作り、managed entry / file / byte数と未管理entry数、marketplace tree / launcher hashを固定します。`cleanup-apply`は保存済みtokenだけを使い、apply直前にもsource treeとlauncherを再検証します。

```bash
python3.11 scripts/manual_desktop_phase_b.py cleanup-plan \
  --root /Users/mani/.tooluseproxy-dogfood/desktop-phase-b-YYYYMMDD

python3.11 scripts/manual_desktop_phase_b.py cleanup-apply \
  --root /Users/mani/.tooluseproxy-dogfood/desktop-phase-b-YYYYMMDD \
  --confirmation-token '<cleanup-planが返したtoken>'
```

`cleanup-apply`の途中でprocessやDesktop操作が失敗した場合は、同じrootと同じcleanup tokenで再実行します。harnessはapply直前にもmanaged / unmanaged inventory全体を保存済みplanと比較します。managed dataが既に消えていれば二重削除せず次段階へ進み、marketplaceが既に消えていれば共有inventoryが開始前と一致することを確認して復元処理を続けます。

review後または部分削除後にmanaged inventoryが変わっていれば、その呼び出しでは何も削除せず`cleanup_replan_required`へ移り、残存件数と新しいcleanup tokenを返します。表示された新しいplanを確認し、そのtokenで`cleanup-apply`を再実行してください。未管理entry数が変わっていれば自動replanもせず停止します。新tokenを受け取る前にprocessが終了した場合は、同じrootで`cleanup-plan`を再実行すると、現在の残存planを再照合してtokenだけを安全に再発行します。

`verify`より前に安全停止したrunは、通常のlifecycle cleanupへ進めません。その場合はabort対象を先に確認し、別tokenで明示適用します。

```bash
python3.11 scripts/manual_desktop_phase_b.py abort-plan \
  --root /Users/mani/.tooluseproxy-dogfood/desktop-phase-b-YYYYMMDD

python3.11 scripts/manual_desktop_phase_b.py abort-apply \
  --root /Users/mani/.tooluseproxy-dogfood/desktop-phase-b-YYYYMMDD \
  --confirmation-token '<abort-planが返したtoken>'
```

abortはPhase B専用のPlugin登録、marketplace、synthetic workspace、生成artifactとpromptだけを片付け、開始前のPlugin / marketplace一覧へ戻します。installやmarketplace追加が成功した直後にcheckpointだけが失敗した場合も、現在のID・version・source root・tree hashが今回のbundleと完全一致する対象だけを復元候補にします。Finderが後から`.DS_Store`を追加した場合だけは、その固定名を除いた全Plugin codeのhashが保存値と一致すれば同じbundleとして扱います。それ以外の追加fileやcode変更は拒否します。`PLUGIN_DATA`は既知でも未知でも推測削除せず、残る可能性をaggregate reportへ明記します。managed dataの削除が必要なら、正常な初期化後にToolUseProxy本体の`uninstall plan` / `uninstall apply`を別途使います。

## 合格条件

- `surface`が`codex_desktop`
- PreToolUse / PostToolUse / Stopがすべて`trusted`で、probe前後に定義hashが変わらない
- 無害な`true`のprobeでPreToolUse 1件、PostToolUse 1件、Stop 1件以上
- public callはPreToolUse、PostToolUse、markerが各1件
- protected callはPreToolUseとexact blockが各1件、PostToolUseとmarkerが0件
- file payload shadow observationがpublic / protectedの2件
- workspace runtime設定3項目が有効で、remove / reinstall後も同じrevision
- assistant、全tool input、tool output、shadow tableへのraw synthetic value露出が0
- 指定したread / setup / public / protected call以外のtool callが0
- Plugin dataを触る全CLI callが1回限定の権限昇格、空でない理由、再利用可能なprefixなし
- Hook review、command承認、block説明を人が理解できる
- Phase B Plugin / marketplace / managed dataを削除し、開始前の無関係な一覧を保持する

`desktop-phase-b-report.json`だけがaggregate resultです。reportにはrelease artifact hashに加え、run固有probeを組み込んだ実際のPlugin tree hashを記録します。state、prompt、guide、session、SQLite、absolute path、confirmation tokenはlocal-onlyで公開しません。

## Hookを確認できない場合

Desktopでは、正常終了したHookのstderrが画面へ表示されないことがあります。そのため、初期化先の案内が見えないことだけをHook未実行の証拠にしません。`checkpoint-hooks-trusted`と`checkpoint-hook-probe`のどちらかが失敗したrunは、そこで停止します。

- `PLUGIN_DATA`を推測しない
- cacheやprocess環境を広く検索してHookを迂回しない
- public / protected callへ進まない
- 「Pluginがinstall済み」「trust済み」だけで保護が動いたと報告しない
- `modified`を`trusted`として扱わない
- 同じ条件の再実行を繰り返さず、Codex version、権限mode、canonical Hook名、trust状態、定義hash、marker件数を値なしで記録する

2026-07-30の停止結果は、protected payloadの検出失敗でもDesktop dispatcherの不具合の証明でもありません。最新のPreToolUse / PostToolUseが再trustされていない状態で、画面に出ないstderrをprobeとしていたため、機能判定に使えないrunです。

## 未完了として残すもの

human runが合格しても、次は別gateです。

- Desktopのshell tool名・Hook matcher・payload正規化のversion互換性
- 異なる二つの署名・hash固定version間の本物のupdate / rollback
- Desktop version更新後の互換性再確認
- MCP、network observe-only、semantic一致
- hosted Web Search。現行CodexではPreToolUse / PostToolUse Hookの対象外で、このPhase Bでも遮断を検証しない
- Linux / Windowsの実surface
