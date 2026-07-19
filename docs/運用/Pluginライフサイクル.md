# Plugin upgrade / rollback rehearsal

public alpha候補のinstall、明示upgrade、safe rollback、disable、remove、data保持、明示uninstallをsynthetic dataだけで反復します。

## version境界

baselineはPlugin packagingを導入したimmutable commit `22974427ab62e55a00d21af164d8fc837cb5e8b7`です。

- baseline: Plugin `0.1.0-alpha.1`、Python `0.1.0a1`、SQLite schema v1
- upgrade先: 現在の検証済みrelease candidate、Plugin `0.1.0-alpha.3`、SQLite schema v4

baseline treeは`git archive`から一時directoryへ展開します。CI checkoutはこのcompatibility fixtureを取得できるようfull historyを使います。repositoryやworkspaceは変更しません。

## 実行

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
3. alpha.3候補をinstallし、旧schemaに対するHookがfail-openしてDDLやevent書込みをしないことを確認
4. Hook外の明示`init --codex`でv1 backupを作り、schema v4へupgrade
5. baseline event、workspace登録、runtime activeを確認し、upgrade後eventを記録
6. alpha.3 codeをremoveし、dataを保持
7. alpha.1をinstallし、schema v4を旧runtimeがinactiveとして拒否してDBを変更しないことを確認
8. pre-migration v1 backupを別のrollback data directoryへSQLite backup APIでimport
9. alpha.1 runtimeがactiveになり、baseline eventを保持し、backup後のalpha.3 eventを含まないことを確認
10. Plugin / marketplaceをremoveし、両data directoryをcurrent artifactの`uninstall plan / apply`で明示削除

rollbackは新schema DBを旧runtimeで無理にdowngradeしません。upgrade後DBをそのまま保持し、pre-migration backupから別data directoryを作るため、rollback失敗時も新しい履歴を上書きしません。

runnerはHook payloadを直接渡すだけで、BashやMCP tool自体を実行しません。summaryはversion、commit、artifact SHA-256、schema version、value-free checksだけを返し、synthetic markerがstdout / stderrへ現れた場合は失敗します。Hook definition trustは自動化・迂回せずmanual gateとして残します。
