# Codex Desktop update / rollback 検証計画

Issue [#62](https://github.com/mani1261790/ToolUseProxy/issues/62)では、Codex Desktopで異なる二つのPlugin versionを入れ替え、管理データの保持、安全なrollback、Disableを挟まないRemoveを実機確認します。

同じbundleの再installはupdate成功に数えません。機能の合否と、承認画面の分かりやすさも別々に記録します。

## 現在地

2026-07-31に、実機run前のharnessと自動testを実装しました。

- 旧版と新版のversion、commit、元artifact、展開tree、Hook定義、launcherをread-only `plan`で固定
- 同じversion、commit、artifact、treeをupdateとして扱わず停止
- 旧版 / 新版それぞれで、installed Plugin identityとtrusted Hook 3件をcheckpoint
- trusted Hook probeからPlugin dataを取得し、pathを推測しない
- schema v1 baseline、旧版Remove後のDB hash保持、schema v6 migration backupを確認
- 新版でpublic side effect 1、protected side effect 0、exact block 1を確認
- 旧runtimeがschema v6をinactiveとして拒否し、DB hashとevent数を変えないことを確認
- schema v1 backupを別data directoryへ復元し、current schema v6 DBを保持
- enabledのままRemoveし、新しいDesktop taskで対象Hookが動かないことを確認
- current / rollback dataのexact uninstall plan、別のcleanup承認、共有inventory復元
- state遷移、artifact identity、path escape、secret field、cleanup inventoryの自動test

実装入口は`scripts/manual_desktop_update_rollback.py`、状態機械は`scripts/desktop_update_rollback_state.py`です。既存Desktop Phase BとPlugin lifecycleを含む全test suiteはgreenです。

まだ実機runは行っていません。したがって、以下は「harnessで検証条件を固定した」状態であり、Desktopでupdate / rollback / 直接Removeが実証済みという意味ではありません。次のgateは、clean commitからplanを作り、人が5〜7回のDesktop操作を行うことです。

## 今回証明すること

| 確認対象 | 合格条件 |
| --- | --- |
| version update | 旧版と新版のversion、source commit、artifact SHA-256、Plugin tree SHA-256が異なり、すべてrun開始時に固定されている |
| data保持 | updateでPlugin codeだけが置換され、workspace登録、protected source、監査DBが意図せず削除されない。alpha.1に存在しないruntime設定は新版で有効化して別に確認する |
| 新版の保護動作 | `doctor` / `status`がactive、public side effectが1件、protected side effectが0件、PreToolUse blockが1件 |
| safe rollback | 旧runtimeが新schemaを直接変更せずinactiveで停止し、更新前backupを別data directoryへ復元するとactiveになる |
| 直接Remove | Disableを先に押さずRemoveしても登録だけが消え、新しいtaskでは対象Hookがactiveにならない。管理データは残る |
| UX | Hook reviewと個別command承認UIを、機能結果とは別に`yes` / `no` / `not-shown`で記録する |
| cleanup | 検証用Plugin、marketplace、managed data、synthetic workspaceだけを削除し、開始前からある項目を保持する |

実secret、普段のworkspace、実networkは使いません。

## versionとartifactの固定

最初の実機runは、既に自動rehearsalで互換性を確認している次の境界を使います。

- 旧版: Plugin `0.1.0-alpha.1`、commit `22974427ab62e55a00d21af164d8fc837cb5e8b7`、SQLite schema v1
- 新版: Plugin `0.1.0-alpha.3`、run開始時に選んだclean commit、SQLite schema v6

旧版はimmutable commitの`git archive`、新版はrelease-candidate builderの検証済みPlugin ZIPから作ります。harnessは各artifactについて、少なくとも次をstateへ保存します。

- 宣言versionとPython package version
- source commit
- 元artifact SHA-256
- 展開後の全file inventoryとPlugin tree SHA-256
- Hook定義とlauncherのSHA-256
- marketplace名、Plugin ID、Codex Home、workspace、Plugin dataの対応

Desktop dispatchを値なしmarkerで確認するためにlauncherへ計測処理を追加する場合は、元artifactと計測用bundleを混同しません。`source_artifact_sha256`と`instrumented_tree_sha256`を別々に保存し、変更したfile一覧も固定します。計測用bundleにはrun固有suffixを持つversionを付け、Desktop cacheが別runのcodeを再利用できないようにします。報告では「公開artifactそのもの」と言わず、「固定artifactから作った計測用bundle」と明記します。

## 実装方針

### 1. 共通lifecycle部品を分離する

既存の`scripts/manual_desktop_phase_b.py`は同一版reinstallを完走でき、`scripts/rehearse_plugin_lifecycle.py`はalpha.1からalpha.3へのmigrationとbackup rollbackを自動検証できます。新しい実装はこの二つの安全契約を再利用します。

まずDesktop harnessから、次の汎用処理を小さなsupport moduleへ分離します。

- Codex Plugin / marketplace inventoryの取得と開始時snapshotとの比較
- Plugin source、version、tree、Hook定義、trust状態の照合
- run stateのatomic保存と許可された状態遷移
- Desktop task session、Hook DB、side-effect markerの相互照合
- cleanup / abortのinventory CASと再開処理

既存Phase BのCLIとstate fileは壊さず、回帰testを通した後にupdate / rollback用CLIを追加します。巨大な既存scriptへ条件分岐を積み重ねません。

### 2. 専用state machineを追加する

新しいCLIは`scripts/manual_desktop_update_rollback.py`とし、1回のcommandで複数のDesktop操作を推測実行しません。主要な状態は次の順です。

1. `planned`: 共有環境を変更せず、二artifactとcleanup範囲を固定
2. `old_marketplace_added`
3. `old_plugin_installed`
4. `old_hooks_trusted`
5. `baseline_initialized`: schema v1 DB、synthetic event、workspace状態を固定
6. `old_removed_for_update`: 旧code登録だけを削除し、data保持を確認
7. `new_marketplace_added`
8. `new_plugin_installed`
9. `new_hooks_trusted`
10. `updated`: 明示migration、backup、設定保持、新版保護動作を確認
11. `new_removed_for_rollback`
12. `old_plugin_reinstalled`
13. `rollback_incompatible_confirmed`: schema v6を旧版が変更せずinactiveで停止
14. `rollback_restored`: v1 backupを別data directoryへ復元し、旧版がactive
15. `direct_remove_verified`: 別caseでDisableなしのRemoveと新規taskのHook不在を確認
16. `cleanup_planned`
17. `restored`

各checkpointは、直前までのstate、共有inventory、artifact identityを再確認してから進みます。失敗時は現在stageと値を含まないerror codeを保存し、同じ確認を際限なく再実行しません。

### 3. updateを検証する

旧版をinstallして3 Hookをreviewした後、既知の専用data directoryへ初期化します。旧版で作るのはsynthetic workspace登録、schema v1 DB、値を含まないcanary eventです。

新版への切替では、旧Pluginと旧marketplaceをRemoveし、新版marketplaceと新版Pluginを追加します。固定tagは`marketplace upgrade`だけでは別versionへ進まないため、この置換をDesktopのimmutable-version更新手順とします。managed dataを削除する`uninstall apply`は使いません。

新版Hookは、schema v1 DBをHook内で暗黙migrationせず、初期化が必要な状態として止まることを確認します。その後、Hook外の明示`init --codex`で次を確認します。

- schema v1 backupが作られる
- current dataがschema v6になる
- baseline eventとworkspace登録が保持される
- 新版のruntime設定を有効化でき、revisionを固定できる
- protected sourceの値を出力せず登録状態を確認できる

最後に新しいDesktop taskを開き、trusted Hookの定義hashを再確認してから、local fake sinkへのpublic / protected callを1回ずつ行います。

### 4. rollbackを検証する

新版をRemoveして旧版を再installします。最初に旧版を現在のschema v6 DBへ向け、次の安全停止だけを確認します。

- statusはactiveにならない
- DB schema、event数、file hashが変わらない
- Hookがmigrationやdowngradeを行わない

続いて、更新前のschema v1 backupを別のrollback専用data directoryへSQLite backup APIでimportします。現在のschema v6 DBは上書きも削除もしません。旧版がrollback dataでactiveになり、baseline eventを保持し、更新後に追加したeventや設定を含まないことを確認します。

このrunで証明するrollbackは「過去の時点へ安全に戻ること」です。更新後の履歴を旧schemaへ変換して持ち帰ることは保証しません。

### 5. DisableなしのRemoveを分離して検証する

直接Removeはupdate / rollbackの途中結果を流用せず、復元後の独立caseとして行います。

1. Pluginがenabledで3 Hookがtrustedなことを固定
2. Disableを押さず、DesktopからRemove
3. Plugin inventoryから対象IDが消えたことを確認
4. managed dataが残っていることを確認
5. 必ず新しいDesktop taskを開き、対象Hookがactiveでないことを確認

Remove前から開いていたtaskに読み込み済みHookが残るかどうかは、別の観測値として記録します。古いtaskの挙動だけでRemove成功・失敗を判定しません。

## 人が行う操作

harnessは一度に一つだけ、次の操作を平易な文章で案内します。長い`sh ...`を理解している前提では説明しません。

1. 旧版Pluginをinstallする
2. 旧版の3 Hookをreviewする
3. 新版Pluginをinstallする
4. 新版の3 Hookをreviewする
5. 旧版へ戻して、必要なら3 Hookをreviewする
6. enabledのままPluginをRemoveする
7. 最後のcleanup内容を確認して承認する

見込みは5〜7回です。Desktopが既存trustを安全に再利用した場合など、不要なreviewは減ります。個別command承認UIが表示されなければ、ユーザーへ存在しない操作を求めず`not-shown`と記録します。

案内文は毎回、次の5項目を通常の文章と改行で表示します。

- 今から何をするか
- なぜ必要か
- 何が変わるか
- 外部通信の有無
- 画面で一致しなければ拒否する条件

Markdown記号を承認UI用の1行文字列へ埋め込みません。

## 自動testと実機gate

### 自動test

- 二artifactのversion / commit / hashが異なること
- state遷移の順序、途中再開、stale token拒否
- code Remove後のdata保持
- schema v6を旧runtimeが変更しないこと
- backupを別data directoryへだけ復元すること
- direct Remove後のinventory判定
- unmanaged Plugin / marketplace / dataを削除しないこと
- synthetic protected valueをreportや例外へ出さないこと
- approval UIの`yes` / `no` / `not-shown`集計

### 実機gate

- 旧版installとHook review
- 新版への実version切替とHook review
- 新版のpublic allow / protected block
- schema非互換の安全停止とbackup rollback
- DisableなしのRemove
- 新しいtaskでHookがactiveでないこと
- cleanup後の共有inventory復元

自動testがgreenでもDesktop実機gateの代わりにはしません。

## 集計結果

最終reportでは、少なくとも次を独立して返します。

- `code_update_verified`
- `data_reuse_verified`
- `hook_retrust_required` / `hook_retrust_observed`
- `new_runtime_protection_verified`
- `newer_schema_refusal_verified`
- `backup_rollback_verified`
- `direct_remove_new_task_verified`
- `approval_ui_status`
- `raw_protected_value_exposure`
- `shared_inventory_restored`
- `inactive_config_residue`

一つでも未観測なら、全体を単純な`passed`へ丸めません。機能合格、UX未観測、cleanup後の非active設定履歴を別々に説明します。

## 実装順序

1. 共通support moduleの抽出と既存Desktop Phase B回帰test
2. 二artifact builder / verifierとread-only `plan`
3. old install / baseline / update checkpoint
4. 新版migration、data保持、public / protected verifier
5. schema非互換停止とbackup rollback
6. direct Removeと新規task verifier
7. resumable cleanup / abort
8. unit / integration test、文書、Issue checklist更新
9. 人によるDesktop実機run

最初の実装sliceでは1〜7のharnessと自動testを追加しました。実機run結果は同じIssueへ追記し、失敗時の修正は観測結果に応じて分けます。
