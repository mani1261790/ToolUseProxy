# Plugin upgrade / rollback rehearsal

public alphaのinstall、明示upgrade、safe rollback、disable、remove、data保持、明示uninstallをsynthetic dataだけで反復します。

## version境界

baselineはPlugin packagingを導入したimmutable commit `22974427ab62e55a00d21af164d8fc837cb5e8b7`です。

- baseline: Plugin `0.1.0-alpha.1`、Python `0.1.0a1`、SQLite schema v1
- upgrade先: 現在の検証済みrelease candidate、Plugin `0.1.0-alpha.7`、SQLite schema v7

baseline treeは`git archive`から一時directoryへ展開します。CI checkoutはこのcompatibility fixtureを取得できるようfull historyを使います。repositoryやworkspaceは変更しません。

## 実行

### Codex native marketplace update

実Codex CLIがmoving marketplace refを更新し、install済みPluginをremove / reinstallなしに置き換える契約は専用testで検証します。

```bash
python3.11 -m pytest tests/test_codex_marketplace_upgrade.py
```

testはloopback HTTPだけを使う一時Git marketplaceを作り、同じrefをalpha.1から現在commitへfast-forwardします。`codex plugin marketplace upgrade tooluseproxy --json`後に、Plugin versionがalpha.7へ変わること、古いcacheが除かれること、Plugin dataが残ること、明示setupでmigration backupを作ってactiveになることを確認します。外部networkや実secretは使いません。

公開運用では同じmoving refとして保護branch `public-alpha`を使います。このbranchはreview済み・CI green・公開済みのrelease commitだけへfast-forwardし、force pushと削除を禁止します。immutable tagによるversion固定も引き続き提供します。

### Artifact transition and rollback

Codex CLIを介さずartifactのcode transitionを検証します。

```bash
python3.11 scripts/rehearse_plugin_lifecycle.py \
  --installation-mode extracted
```

isolated `CODEX_HOME`で実際のmarketplace add / Plugin add / Plugin remove / marketplace removeを検証します。

```bash
python3.11 scripts/rehearse_plugin_lifecycle.py \
  --installation-mode codex
```

既に作成した候補を指定する場合は、候補directory全体を渡します。runnerは実行前にmanifest、exact file set、checksums、artifact内部version、SBOM inventoryをoffline verifierで再確認します。

```bash
python3.11 scripts/rehearse_plugin_lifecycle.py \
  --installation-mode codex \
  --candidate "<RELEASE_CANDIDATE_DIRECTORY>"
```

## 検証順

1. alpha.1をinstallし、schema v1 DBへsynthetic eventを記録
2. PluginをremoveしてHook codeを無効化し、marketplace削除前後でdata保持を確認
3. alpha.7をinstallし、旧schemaに対するHookがfail-openしてDDLやevent書込みをしないことを確認
4. Hook外の明示`init --codex`でv1 backupを作り、schema v7へupgrade
5. baseline event、workspace登録、runtime activeを確認し、workspace runtime設定を保存してupgrade後eventを記録
6. alpha.7 codeをremoveしてdataを保持し、同じversionを再installしてruntime設定のrevisionと有効値が残ることを確認
7. alpha.1をinstallし、schema v7を旧runtimeがinactiveとして拒否してDBを変更しないことを確認
8. pre-migration v1 backupを別のrollback data directoryへSQLite backup APIでimport
9. alpha.1 runtimeがactiveになり、baseline eventを保持し、backup後のalpha.7 eventとruntime設定を含まないことを確認
10. Plugin / marketplaceをremoveし、両data directoryをcurrent artifactの`uninstall plan / apply`で明示削除

rollbackは新schema DBを旧runtimeで無理にdowngradeしません。upgrade後DBをそのまま保持し、pre-migration backupから別data directoryを作るため、rollback失敗時も新しい履歴を上書きしません。

runnerはHook payloadを直接渡すだけで、BashやMCP tool自体を実行しません。summaryはversion、commit、artifact SHA-256、schema version、value-free checksだけを返し、synthetic markerがstdout / stderrへ現れた場合は失敗します。Hook definition trustは自動化・迂回せずmanual gateとして残します。

## release channelの更新手順

1. `main`でversion、Plugin manifest、package metadataを揃え、全CIをgreenにする
2. immutable tagとGitHub prereleaseを作り、artifact、SHA256SUMS、SBOMを公開・検証する
3. release commitだけを`public-alpha`へfast-forwardするPRを作る
4. required checksと差分を確認してmergeする
5. cleanなisolated `CODEX_HOME`でinstallと`marketplace upgrade`を再検証する

`main`や未公開commitへ`public-alpha`を向けません。channel更新とrelease artifact公開の順序を逆転させません。
