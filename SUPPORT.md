# サポート範囲と既知の制限

ToolUseProxy `0.1.0-alpha.12`は現在の検証済みpublic alphaです。alpha.12は、現在のverification command自身へ届いたPreToolUseをsession、Plugin版、Hook定義hashに結び付け、別taskや過去sessionの成功と分けて表示します。本番環境向けのSLA、security certification、完全なDLP、全toolの遮断保証は提供しません。

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

Windowsでは既存manifestのruntime読み取りとlauncherを将来互換のため維持しますが、`protect scan / suggest / review / approve / reject / ignore`とmanifest migration applyはalphaでは未対応です。成功したように見せず、CLIの明示エラーとして扱います。

POSIX launcherもpackage metadataと同じPython 3.11 / 3.12だけを選びます。`TOOLUSEPROXY_PYTHON`や`python3`が3.13以降または3.10以前を指す場合は実行せず、別の対応runtimeを探した後にPreToolUseを安全停止します。PostToolUse / Stopは診断だけを返します。

## Codex Plugin

- localでCodex CLIのmarketplace add / Plugin installを検証済み
- Gitのmoving refを使う`codex plugin marketplace upgrade`で、alpha.1および3 Hook alpha.8からalpha.12へ置き換わり、Plugin dataが保持されることを実Codex CLIで自動検証。更新後の完全再起動とfresh Desktop配送もalpha.12で確認済み
- Hook definitionのreview / trustを迂回しない
- MCPはread-only名でもqueryをserverへ送るexternal boundaryとして扱う。上限内の全key/valueとactive source全体の比較を完了できたpublic inputだけを許可し、一致・上限超過・比較失敗は実行前deny
- install後のcodeは`PLUGIN_ROOT`、mutable dataは`PLUGIN_DATA`へ分離
- remote `main`を実行元にせず、通常更新は保護されたfast-forward-only `public-alpha`、再現性優先時はimmutable release tagを使う
- isolated Codex CLIではinstall / protect / Hook payload allow-deny / trace / removeとdata保持を自動検証
- release candidate verifierはwheel / sdist / Plugin ZIP内部のunsafe path、重複entry、symlink等の非regular type、危険mode、想定外の実行file、過大展開をfail-closedで拒否
- GitHub Actionsはreview済みactionだけをfull commit SHAで固定し、checkout credentialを残さず、`contents: read`だけで実行する。DependabotがSHA更新候補をPRとして提示する
- release build toolchainは5つのpure Python wheelをexact versionとSHA-256で固定し、lockと異なる環境からのcandidate buildを拒否する
- public化前にreachable Git blob、commit / tag message、worktreeをaggregate-onlyで監査し、危険file、provider形式credential、未知binary、oversizeを拒否する。形式を持たないsecretや画像内文字の完全検出は保証しない
- Codex CLI TUI `0.145.0`ではmanual Hook trust、public call、protected PreToolUse block、side effect 0を確認済み。ただし自己完結型command承認説明のhuman再検証は未完了
- Codex Desktop / GUIでは2026-08-31のmacOS alpha.12実機runが全35 checksで`passed`。command承認2回、public side effect 1、static / dynamic protected side effect各0、実行前block各1、raw protected value exposure 0、余分なtool call 0。同一版reinstallでmanaged stateを再利用し、final Removeとcleanupも確認した
- 通常setupは、操作ごとの承認UIを使うmodeでは限定commandごとに確認する。承認UIなしでも現在のpermission profileがPlugin dataへのaccessを明示的に許可していれば、選択済み権限内で固定setupとread-only verificationを続行し、UI表示回数を0と報告する。accessがなければ停止し、長い内部command、別path、広い権限へ自動fallbackしない
- Desktop taskの履歴上はshell toolが`exec_command`と記録されるが、Hook matcherのcanonical tool名は`Bash`。正常終了したHookのstderrもDesktop画面へ表示されないため、画面表示だけをdispatch証拠にせず、Hook trust状態、定義hash、値を含まないmarker、Hook DB、task記録を相互照合する
- Linux上の実Codex task、Windows、将来release間のupgrade / rollback反復E2Eは未完了

Codex Plugin APIやHook payloadはToolUseProxyとは別に変更され得ます。未検証のCodex CLI versionで異常が出た場合は、`doctor --json`、Codex version、synthetic payloadで再現し、protected dataを報告へ含めないでください。

## 機能別support

| 機能 | 状態 | 境界 |
| --- | --- | --- |
| SessionStart / SubagentStart / PreToolUse / PostToolUse / Stop | alpha対応 | SessionStartとSubagentStartはhosted tool境界をdeveloper contextで伝える。Pre/Postはmatcherに一致するlocal function toolが対象。未初期化DBだけはsetupを可能にするadvisory。Python / runtime起動失敗、未知schema、内部policy例外、解析不能payloadはPreToolUseでdenyし、入力や例外本文を表示しない |
| `init / doctor / status / trace` | alpha対応 | migrationは通常Hook内では行わない |
| protected source候補scan | POSIX対応 | bounded offline scan。上限到達時は完全探索と主張しない |
| candidate batch review | POSIX対応 | 最大10件のvalue-free proposalをまとめて提示し、候補ごとの明示判断を一度に反映。1件用commandも互換維持 |
| Hook-visible local toolのPreToolUse deny | 通常setupで有効 | 既知adapterを精密判定し、外部payloadを安全に確認できない場合は保護sourceがあるworkspaceで保守的にdeny。package既定値自体はoff |
| current-invocation health | alpha.12対応 | 毎回新しいopaque tokenでverification command自身のPreToolUse、解析run、Plugin版、Hook定義hashを同じsessionへ照合。設定だけなら`configured_unverified`、このcommandへの配送確認済みなら`active` |
| Stop final-answer review | alpha対応 | critical findingを`continue_review`で差し戻す |
| runtime redact / `updatedInput` | 未対応 | 複数Hook後の最終採用inputを証明できないため無効 |
| Externality Protection | local判定は通常setupで有効 | Hookはlocal static/cache判定を行い、未確認external payloadを保守的にdeny。LLM providerは既定offで、明示的なHook外worker、人間review、workspace単位の完全一致cacheを使い、LLM分類を自動昇格しない |
| remote embedding / telemetry | 非搭載 | Hook内network serviceなし。telemetryは送信しない |
| explicit managed-data uninstall | macOS / Linux alpha対応 | Plugin removeは保持。`uninstall plan`のexact tokenを`apply`へ渡した場合だけ管理dataを削除 |

## 既知の制限

- 未初期化DBだけは初回setupを可能にするためadvisory。保護設定後のPreToolUse解析失敗、DB / runtime失敗、未知schema、payload上限超過はfail-closedでdenyする
- hosted Web Searchは現在のPreToolUse / PostToolUse Hookへ現れず、技術的な実行前遮断の対象外。SessionStart / SubagentStartのdeveloper contextでprotected contentを渡さないよう指示するが、これは強制境界ではない
- 実行中processへ`write_stdin`で追加する入力は、新しいPreToolUseが発火しないため再検査できない
- Codexの特殊なtool経路がHookを省略する可能性は未検証であり、coverage statusでも`unverified`として扱う
- 現行Desktopの単一`tools.exec_command`固定wrapperはalpha.12実機で確認済み。別wrapper、複数command、他の入れ子tool、特殊経路は`unverified`のまま
- Bashのshell変数、command substitution、未知option、複雑なpipelineを一般shellとして完全評価しない。外部payloadを完全に評価できない場合はallowせずdenyするため、false blockが発生し得る
- Codex Hook payloadに信頼できる終了statusがない操作は、write成功を推測せず`unknown`として扱う
- lexical similarityは意味的な言い換えを一般には検知しない
- candidate retrievalはartifact 50 / source 200の有限上限を持つ
- local SQLiteにはraw Hook payloadやprotected source由来textが平文で残り得る
- database、backup、trace exportの自動retention / secure eraseはない
- moving marketplace refによるalpha.1およびstale alpha.8からalpha.12へのnative upgrade、immutable baselineからalpha.12へのlifecycle upgrade、backupを使うsafe rollback、Plugin / marketplace remove、data保持 / 明示uninstallはisolated Codex CLIで検証済み。fresh Desktop配送もmacOSで確認済み。Linux実Codex CLI、Windows実機、将来version間の反復は未完了
- runtime policyは他のHookやtool自体をexclusiveに制御できず、ToolUseProxy単独で完全な外部送信防止を保証しない
- Externality JudgeのCodex routeは事前probe合格と24時間以内のreceiptを要求する。実測latencyは約3.4〜6.3秒だが、この待ち時間はHook外workerに限定され、PreToolUseには入らない

dataの詳細は[プライバシーとデータ保持](PRIVACY.md)、導入手順は[Codex Plugin導入](docs/設定/Plugin導入.md)、実装の優先順位は[実装タスク](docs/運用/実装タスク.md)を参照してください。

## 問題報告

[GitHub Issues](https://github.com/mani1261790/ToolUseProxy/issues)へ、OS、Python / Codex version、実行command、期待結果、実結果をsynthetic dataで報告してください。secret、raw Hook payload、`events.db`、absolute user pathは添付しないでください。security-sensitiveな内容は[非公開の脆弱性報告手順](SECURITY.md)を使用してください。
