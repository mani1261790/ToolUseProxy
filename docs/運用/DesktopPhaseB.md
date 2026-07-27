# Codex Desktop Phase B

Issue [#53](https://github.com/mani1261790/ToolUseProxy/issues/53)では、CLI TUIの結果を流用せず、Codex Desktop / GUI上のPlugin install、Hook review、public allow、protected block、disable / remove、同一版reinstallを人と実証します。

## 現在地

専用harnessは実装済みですが、人がDesktopで最後まで実行したaggregate reportはまだありません。したがって、READMEとSUPPORTの「Desktop未検証」はhuman runが完了するまで維持します。

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

`prepare`が変更するのは、共有Codex configへの専用local marketplace追加だけです。返された`local_only.install_url`をCodex Desktopで開き、表示されるsourceとversionがguideに一致するPluginだけをinstallします。その後、次を実行します。

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

同じ専用Pluginをinstall URLから再installし、同一版reinstall後に同じdataと設定revisionを再利用できることを確認します。

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

## 未完了として残すもの

human runが合格しても、次は別gateです。

- 異なる二つの署名・hash固定version間の本物のupdate / rollback
- Desktop version更新後の互換性再確認
- MCP / Web検索、network observe-only、semantic一致
- Linux / Windowsの実surface
