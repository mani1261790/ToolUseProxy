# サポート範囲と既知の制限

ToolUseProxy `0.1.0-alpha.3`は研究用public alphaです。本番環境向けのSLA、security certification、完全なDLP、全toolの遮断保証は提供しません。対応と未対応をsilent fallbackで同一視せず、次の範囲を現在の契約とします。

## 実行環境

| 環境 | 状態 | 自動検証する範囲 |
| --- | --- | --- |
| Python 3.11 / Ubuntu | 対応 | full tests、evaluation gate、wheel / sdist、checkout外CLI / Hook |
| Python 3.12 / Ubuntu | 対応 | Python 3.11と同じfull matrix |
| Python 3.11 / macOS | 対応 | local package、relocated Plugin、isolated Codex marketplace install |
| Python 3.12 / macOS | 対応 | GitHub macOS runnerでartifact build、venv install、CLI / relocated Plugin smoke |
| Python 3.13以降 | 未対応 | package metadataで`<3.13`に制限 |
| Windows | experimental | `.cmd` launcherは同梱するが、実機CIとPlugin lifecycle E2Eは未完了 |

macOS Python 3.12はGitHub CI run `29672165132`でartifact build、nested venv、wheel install、CLI / relocated Plugin smokeを検証しました。localのuv-managed Python 3.12では`venv`内`ensurepip`が`SIGABRT`する環境事例があり、ToolUseProxy codeより前のPython配布環境問題として区別します。

Windowsでは既存manifestのruntime読み取りとlauncherを将来互換のため維持しますが、`protect scan / suggest / approve / reject / ignore`とmanifest migration applyはalphaでは未対応です。成功したように見せず、CLIの明示エラーとして扱います。

POSIX launcherもpackage metadataと同じPython 3.11 / 3.12だけを選びます。`TOOLUSEPROXY_PYTHON`や`python3`が3.13以降または3.10以前を指す場合は実行せず、別の対応runtimeを探した後に明示エラーまたはHook fail-openとします。

## Codex Plugin

- localでCodex CLIのmarketplace add / Plugin installを検証済み
- Gitのmoving refを使う`codex plugin marketplace upgrade`で、install済みPluginがremove / reinstallなしにalpha.1からalpha.3へ置き換わり、`PLUGIN_DATA`が保持されることを実Codex CLIで自動検証
- Hook definitionのreview / trustを迂回しない
- install後のcodeは`PLUGIN_ROOT`、mutable dataは`PLUGIN_DATA`へ分離
- remote `main`を実行元にせず、通常更新は保護されたfast-forward-only `public-alpha`、再現性優先時はimmutable release tagを使う
- isolated Codex CLIではinstall / protect / Hook payload allow-deny / trace / removeとdata保持を自動検証
- release candidate verifierはwheel / sdist / Plugin ZIP内部のunsafe path、重複entry、symlink等の非regular type、危険mode、想定外の実行file、過大展開をfail-closedで拒否
- GitHub Actionsはreview済みactionだけをfull commit SHAで固定し、checkout credentialを残さず、`contents: read`だけで実行する。DependabotがSHA更新候補をPRとして提示する
- release build toolchainは5つのpure Python wheelをexact versionとSHA-256で固定し、lockと異なる環境からのcandidate buildを拒否する
- public化前にreachable Git blob、commit / tag message、worktreeをaggregate-onlyで監査し、危険file、provider形式credential、未知binary、oversizeを拒否する。形式を持たないsecretや画像内文字の完全検出は保証しない
- Codex CLI TUI `0.145.0`ではmanual Hook trust、public call、protected PreToolUse block、side effect 0を確認済み。ただし自己完結型command承認説明のhuman再検証は未完了
- Codex Desktop / GUIはlocal Pluginを利用できる公式surfaceですが、ToolUseProxyのHook review・command承認・PreToolUse block・更新操作は未検証。CLI TUIの結果をGUI対応の根拠にしません
- Linux上の実Codex task、Windows、将来release間のupgrade / rollback反復E2Eは未完了

Codex Plugin APIやHook payloadはToolUseProxyとは別に変更され得ます。未検証のCodex CLI versionで異常が出た場合は、`doctor --json`、Codex version、synthetic payloadで再現し、protected dataを報告へ含めないでください。

## 機能別support

| 機能 | 状態 | 境界 |
| --- | --- | --- |
| PreToolUse / PostToolUse / Stop記録 | alpha対応 | 初期化不備や内部例外ではCodexを壊さないようfail-open |
| `init / doctor / status / trace` | alpha対応 | migrationは通常Hook内では行わない |
| protected source候補scan | POSIX対応 | bounded offline scan。上限到達時は完全探索と主張しない |
| candidate approve / reject / ignore | POSIX対応 | 1件ずつのexact proposalと明示承認が必要 |
| Bash / MCP PreToolUse deny | opt-in | 既定off。static evidenceと現在eventのcritical findingに限定 |
| Stop final-answer review | alpha対応 | critical findingを`continue_review`で差し戻す |
| runtime redact / `updatedInput` | 未対応 | 複数Hook後の最終採用inputを証明できないため無効 |
| remote embedding / telemetry | 非搭載 | Hook内network accessなし |
| explicit managed-data uninstall | macOS / Linux alpha対応 | Plugin removeは保持。`uninstall plan`のexact tokenを`apply`へ渡した場合だけ管理dataを削除 |

## 既知の制限

- Hookの解析失敗、DB lock、未知schema、未初期化では原則fail-openする
- Bashのshell変数、command substitution、未知option、複雑なpipelineを一般shellとして完全評価しない
- Codex Hook payloadに信頼できる終了statusがない操作は、write成功を推測せず`unknown`として扱う
- lexical similarityは意味的な言い換えを一般には検知しない
- candidate retrievalはartifact 50 / source 200の有限上限を持つ
- local SQLiteにはraw Hook payloadやprotected source由来textが平文で残り得る
- database、backup、trace exportの自動retention / secure eraseはない
- moving marketplace refによるalpha.1からalpha.3へのnative upgrade、immutable alpha.1からalpha.3へのlifecycle upgrade、backupを使うsafe rollback、Plugin / marketplace remove、data保持 / 明示uninstallはisolated Codex CLIで検証済み。Linux実Codex CLI、Windows実機、将来version間の反復は未完了
- runtime policyは他のHookやtool自体をexclusiveに制御できず、ToolUseProxy単独で完全な外部送信防止を保証しない

dataの詳細は[プライバシーとデータ保持](PRIVACY.md)、導入手順は[Codex Plugin導入](docs/設定/Plugin導入.md)、実装の優先順位は[実装タスク](docs/運用/実装タスク.md)を参照してください。

## 問題報告

[GitHub Issues](https://github.com/mani1261790/ToolUseProxy/issues)へ、OS、Python / Codex version、実行command、期待結果、実結果をsynthetic dataで報告してください。secret、raw Hook payload、`events.db`、absolute user pathは添付しないでください。security-sensitiveな内容は[非公開の脆弱性報告手順](SECURITY.md)を使用してください。
