# Codex Desktop Phase B

Issue [#53](https://github.com/mani1261790/ToolUseProxy/issues/53)では、CLI TUIの結果を流用せず、Codex Desktop / GUI上のPlugin install、Hook review、public allow、protected block、disable / remove、同一版reinstallを人と実証します。

## 現在地

専用harnessは実装済みです。2026-07-28にCodex Desktop同梱の`codex-cli 0.146.0-alpha.3.1`で人による実機確認を行い、次のところまで確認しました。

| 段階 | 結果 |
| --- | --- |
| HomeのPlugins検索から専用Pluginをinstall | 成功 |
| PreToolUse / PostToolUse / Stopの3件をreviewし、trustを保存 | 成功 |
| 新しいDesktop taskからlocal shell commandを実行 | `exec_command`として実行された |
| ToolUseProxy PreToolUse Hookの発火 | 確認できず |
| public / protected call | 安全のため未実行 |

Full AccessとDefaultの両方で、最初の無害な`true`にHook診断が出ませんでした。権限modeだけを変えても結果が同じだったため、Full Access固有の問題ではありません。

現在のPlugin Hook matcherはCLI TUIで観測した`Bash`を対象にしています。一方、今回のDesktop sessionにはshell toolが`exec_command`として記録されました。このtool名の違いが第一の調査対象ですが、matcherを広げるだけでHookがdispatchされるか、Desktop payloadを既存のBash解析へ安全に正規化できるかは修正版で再検証する必要があります。

したがって、READMEとSUPPORTでは次を区別します。

- DesktopでPluginをinstallできる: 確認済み
- DesktopでHook trustを保存できる: 確認済み
- Desktopのtool useにToolUseProxy Hookが発火する: 未確認
- Desktopでprotected payloadを実行前blockできる: 未確認

現時点でDesktop / GUI上のToolUseProxy保護を利用可能とは扱いません。

同一版reinstallは「Plugin codeを削除しても`PLUGIN_DATA`の設定と監査DBが残り、再install時に再利用されること」を確認します。本物のupdateは異なる二つのimmutable versionが必要です。同じZIPを入れ直した結果をupdate成功とは数えません。

## 安全境界

- 最初の`plan`は共有`~/.codex`を変更しない
- ToolUseProxyのPluginまたは同名系marketplaceが既にあれば衝突として停止する
- 検証用marketplaceは`tooluseproxy-desktop-phase-b`、Plugin IDは`tooluseproxy@tooluseproxy-desktop-phase-b`へ分離する
- 共有configとPlugin / marketplace一覧は変更直前にも比較し、plan後に変化していれば停止する
- Hook trustは迂回せず、Desktopで人が3件をreviewする
- test sinkはnetworkへ接続せず、synthetic workspace内のmarkerだけを更新する
- verifierはDesktop session、Hook DB、side-effect marker、Plugin source / versionを相互照合する
- cleanupはPhase B専用dataとmarketplaceだけを削除し、無関係なPlugin / marketplaceを保持する

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

現行DesktopではPlugin名`ToolUseProxy`とmarketplace表示名`ToolUseProxy Desktop Phase B`が別の検索結果に見える場合があります。install後は画面上の件数だけで判断せず、CLI inventoryが`tooluseproxy@tooluseproxy-desktop-phase-b`の1件だけであることをcheckpointで確定します。local marketplaceはPluginを`~/.codex`へ複製せず、検証rootのsourceを直接参照する場合があります。この場合、removeで消えるのはPlugin登録であり、local source本体は最終cleanupまで保持されます。

```bash
python3.11 scripts/manual_desktop_phase_b.py checkpoint-installed \
  --root /Users/mani/.tooluseproxy-dogfood/desktop-phase-b-YYYYMMDD
```

返された`local_only.task_url`で新しいDesktop taskを開きます。Hook reviewではToolUseProxy由来のPreToolUse、PostToolUse、Stopの3件だけを確認します。source、version、command root、件数が違えばtrustせず停止します。task内では生成済みpromptだけを使い、普段のworkspaceやsystem curlへ置き換えません。

task完了後、理解度を本人の評価で記録します。

```bash
python3.11 scripts/manual_desktop_phase_b.py verify \
  --root /Users/mani/.tooluseproxy-dogfood/desktop-phase-b-YYYYMMDD \
  --hook-review-understood yes \
  --command-approval-understood yes \
  --block-explanation-understood yes \
  --additional-question-count 0
```

`functional_status`と`ux_status`は別判定です。機能が正しくても説明を理解できなければ`needs_followup`となり、コマンドの終了codeは1です。この場合も証跡は保存され、次のlifecycle確認へ進めますが、Phase B合格とは扱いません。

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

最後に削除対象を先に表示し、別tokenで明示承認します。

```bash
python3.11 scripts/manual_desktop_phase_b.py cleanup-plan \
  --root /Users/mani/.tooluseproxy-dogfood/desktop-phase-b-YYYYMMDD

python3.11 scripts/manual_desktop_phase_b.py cleanup-apply \
  --root /Users/mani/.tooluseproxy-dogfood/desktop-phase-b-YYYYMMDD \
  --confirmation-token '<cleanup-planが返したtoken>'
```

## 合格条件

- `surface`が`codex_desktop`
- public callはPreToolUse、PostToolUse、markerが各1件
- protected callはPreToolUseとexact blockが各1件、PostToolUseとmarkerが0件
- file payload shadow observationがpublic / protectedの2件
- workspace runtime設定3項目が有効で、remove / reinstall後も同じrevision
- assistant、tool output、shadow tableへのraw synthetic value露出が0
- Hook review、command承認、block説明を人が理解できる
- Phase B Plugin / marketplace / managed dataを削除し、開始前の無関係な一覧を保持する

`desktop-phase-b-report.json`だけがaggregate resultです。state、prompt、guide、session、SQLite、absolute path、confirmation tokenはlocal-onlyで公開しません。

## Hookが発火しない場合

最初の無害な`true`に、trusted Hookから初期化先の案内が出なければ、そのrunはそこで停止します。

- `PLUGIN_DATA`を推測しない
- cacheやprocess環境を広く検索してHookを迂回しない
- public / protected callへ進まない
- 「Pluginがinstall済み」「trust済み」だけで保護が動いたと報告しない
- 同じ条件の再実行を繰り返さず、Codex version、権限mode、session上のtool名を値なしで記録する

今回の停止結果は、protected payloadの検出失敗ではありません。検出処理より前のHook発火境界に到達していないためです。

## 未完了として残すもの

human runが合格しても、次は別gateです。

- Desktopのshell tool名・Hook matcher・payload正規化のversion互換性
- 異なる二つの署名・hash固定version間の本物のupdate / rollback
- Desktop version更新後の互換性再確認
- MCP / Web検索、network observe-only、semantic一致
- Linux / Windowsの実surface
