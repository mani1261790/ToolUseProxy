# ToolUseProxy

Codexのtool useをローカルで観測し、外部sinkへ送られるpayloadとprotected sourceの内容対応を検査し、必要に応じてprovenanceを補助証拠として流出を検知・制御する研究実装です。

本プロジェクトは、[SecHack365](https://sechack365.nict.go.jp/)での研究・開発成果物です。

> 現在は`0.1.0-alpha.3` public alphaです。中核機能、再現可能な配布物、Apache-2.0の配布契約、CLI TUIでのfile-backed exact-only enforcement検証は整いましたが、完全なDLPではありません。Codex DesktopではPluginの検索・install、Hook review、trusted Pre / Post / Stop probe、public allow、file-backed protected payloadの実行前blockまで実機確認しました。`workspace-write` taskではworkspace外のPlugin dataを触る各コマンドが一時的な権限昇格として発行されましたが、今回のDesktopでは個別承認UIが表示されなかったため、機能結果と承認UXを分けて記録しています。adapter外のnetwork egress、hosted Web Search、Linux実Codex task、Windows実機も引き続き検証中です。

- [研究紹介スライド（初めて知る方向け）](https://mani1261790.github.io/ToolUseProxy/slides/tooluseproxy-research.html)
- [Codex Pluginとして試す](docs/設定/Plugin導入.md)
- [5分quickstart / Five-minute quickstart](QUICKSTART.md)
- 30秒synthetic demo: `python3.11 scripts/demo_plugin.py`
- [English introduction](README.en.md)
- [対応環境と既知の制限](SUPPORT.md)
- [プライバシーとデータ保持](PRIVACY.md)
- [脆弱性の非公開報告](SECURITY.md)
- [Pluginドッグフード](docs/運用/Pluginドッグフード.md)
- [Plugin upgrade / rollback rehearsal](docs/運用/Pluginライフサイクル.md)
- [Release候補の作成と検証](docs/運用/Release候補.md)
- [現在地と実装ロードマップ](docs/運用/実装タスク.md)
- [Sink中心の情報流評価計画](docs/調査/Sink中心の情報流評価計画.md)
- [Network egress観測とAudit改善計画](docs/調査/NetworkEgress観測とAudit改善計画.md)
- [Sink-first比較評価の実行方法](docs/運用/Sink-first比較評価.md)
- [ドキュメント索引](docs/索引.md)
- [GitHub Project](https://github.com/users/mani1261790/projects/1)

## できること

- Codexの`PreToolUse` / `PostToolUse` / `Stop`をSQLiteへ記録する
- exact、substring、token-equivalent、shingle類似度とtool固有adapterから情報流グラフを構築する
- `.env` / JSONなどのprotected sourceを起点にlineageと漏えい候補を説明する
- opt-in時にcriticalなBash / MCP外部送信を実行前にdenyする
- final answerのcritical findingを`continue_review`で差し戻す
- coding agentが値を表示せず候補を提案し、ユーザーの明示承認後だけmanifestへ原子的に登録する

Hook内のnetwork access、remote embedding、telemetryは使いません。runtimeによるtool inputの書換えは、複数Hook間で最終入力を証明できないため意図的に無効です。

ToolUseProxyはLLM内部の状態や因果的な情報流を直接観測するものではありません。現在のgraphは、tool I/O、file operation、内容一致・類似から作る観測境界上のprovenance推定です。今後は[sink-first、provenance-assistedの比較評価](docs/調査/Sink中心の情報流評価計画.md)により、直接payload検査へsemantic comparisonやlineageを加える実効価値を測ります。

## 現在地

| 領域 | 状態 | 現在の境界 |
| --- | --- | --- |
| 1. Trace | 中核完了 | event / artifact / resource / sinkをworkspace・session単位で追跡し、再現可能な解析runを保存 |
| 2. Detect | 中核完了 | protected source binding、lineage、finding、policy、類似度profile v2.1を実装 |
| 3. Stop | alpha実装済み | Stopの`continue_review`と、opt-inのBash / MCP PreToolUse denyを提供。runtime redactは無効 |
| Plugin化 | alpha.3 | installable package、relocatable Plugin、`PLUGIN_ROOT` / `PLUGIN_DATA`、初期化・診断・traceを実装 |
| runtime設定 | 実装済み | workspace単位のboolean設定、環境変数override、revision付き更新、値なし監査、Plugin再導入後の保持 |
| protected source登録 | 明示承認型を実装済み | `scan` / `suggest` → exact proposal → `approve` / `reject` / `ignore`。無承認登録はしない |
| Public alpha | `0.1.0-alpha.3` | Apache-2.0、checksum / SBOM、archive内部、CI Action、hash-locked build、Git履歴監査、upgrade / rollback、自動dogfoodを完了。CLI TUIのfile-backed shadow / exact-only Phase Bは合格。Desktopもinstall、trust、実Hook probe、public allow、protected block、disable / remove / 同一版reinstall / cleanupまで機能確認済み。個別承認UIは未観測で、Codexが保持する非アクティブなproject / Hook trust履歴は残存。cross-platform実機、少人数pilotも継続課題 |
| 外部sink coverage | adapter allowlist | 既知のBash / MCP / Search等を分類。任意programの実network接続を網羅せず、hosted Web SearchはPreToolUse / PostToolUse Hookの観測対象外。実接続との偽陰性率は未測定 |

設計全体は[アーキテクチャ概要](docs/設計/アーキテクチャ.md)、詳細な完了範囲と残作業は[実装タスク計画](docs/運用/実装タスク.md)を参照してください。

## Pluginをインストールする

Python 3.11または3.12とCodex CLIを用意します。通常は、公開alphaだけをfast-forwardで配信する`public-alpha`更新チャンネルを追加してください。可変な開発branchの`main`を実行元にはしません。OS・機能別の境界は[サポート範囲](SUPPORT.md)を確認してください。

```bash
codex plugin marketplace add mani1261790/ToolUseProxy --ref public-alpha
codex plugin add tooluseproxy@tooluseproxy
```

更新は自動ではありません。新しいpublic alphaが出た後、次を明示的に実行します。

```bash
codex plugin marketplace upgrade tooluseproxy
codex plugin list --json
```

特定versionを固定したい場合は、`public-alpha`の代わりにimmutable tag `v0.1.0-alpha.3`を指定します。固定tagは`marketplace upgrade`を実行しても別versionへ移動しません。

installまたは更新後は、Codexが表示するHook definitionを確認してtrustし、新しいtaskを開始します。Pluginが示す`PLUGIN_ROOT` / `PLUGIN_DATA`を使って、対象workspaceで初期化と診断を行います。

```bash
sh "<PLUGIN_ROOT>/hooks/run_cli.sh" init --codex --data-dir "<PLUGIN_DATA>"
sh "<PLUGIN_ROOT>/hooks/run_cli.sh" doctor --workspace "$PWD" --data-dir "<PLUGIN_DATA>"
sh "<PLUGIN_ROOT>/hooks/run_cli.sh" status --workspace "$PWD" --data-dir "<PLUGIN_DATA>"
```

Hook trustで確認する内容、更新チャンネルと固定tagの違い、protected sourceの候補発見・承認、rollback、削除時のdata保持を含む完全な手順は[Plugin導入](docs/設定/Plugin導入.md)にあります。Codex Desktopはlocal Pluginを利用できるsurfaceで、[Desktop専用Phase B harness](docs/運用/DesktopPhaseB.md)まで実装済みです。2026-07-30の最新runでは、定義hashを固定した3 Hookのtrust、値を含まないmarkerによるPre / Post / Stop各1回の実配送、public allow、protected payloadの実行前blockを確認しました。`workspace-write` taskからworkspace外のPlugin dataを触るコマンドは1コマンド限定の権限昇格として発行されました。ただしDesktopが個別承認UIを表示せず進めたため、「昇格要求が正しく付いたこと」と「人が承認画面を理解できたこと」は別の結果として扱います。Codex CLIのMarketplace更新と保護動作は実機検証済みです。

## 安全側の既定値

- 初期化前、壊れた設定、未知のschemaではHookをfail-openし、Hook中にmigrationしない
- protected sourceは`init`やHookから自動登録しない
- 候補の本文・値・source hash・absolute pathをagent向け出力へ含めない
- PreToolUse blockとMCP blockは既定で無効
- runtime redact / `updatedInput`は無効
- local監査dataをPlugin削除時に自動削除せず、`uninstall plan / apply`の明示確認でだけ管理dataを削除する

## 品質ゲート

類似度profile v2.1はversioned synthetic corpusで次を固定しています。

- 42 pair、13 E2E scenario、16 candidate retrieval pool
- pair precision / recall / F1: `1.0`
- artifact recall@50、source recall@200: `1.0`
- E2E reachability / action: `1.0`
- false block、privacy exposure: `0`
- full / incremental / SQLite parity mismatch: `0`
- 1,000〜10,000候補のstress poolでsaturated recall: `1.0`

dataset digestは`0e7045219148a9e1ba45073e390802ca21ddb60b6c119afd532c66d76b399822`です。再現方法、split、既知の限界は[類似度評価](docs/運用/類似度評価.md)に記録しています。

Sink-first比較評価では、direct lexical、resolved lexical、任意のlocal semantic、現行runtime lineageを同条件比較します。v1.1のfile-backed corpusでは、direct end-to-end recall `0.333`に対し、bounded `--data-binary @file` resolverを加えたresolved recallは`0.667`、precisionは`1.0`、payload resolutionは4 / 4です。resolver v2はPOSIXでcomponent-wiseなdirectory FD traversalを使い、親path差し替えによるworkspace escapeを防ぎます。解決値を返さない[Sink payload evidence契約](docs/設計/SinkPayloadEvidence.md)はproduction Hookのshadow観測と、明示opt-inのexact-only enforcementへ接続しています。既定では無効で、semantic類似、unsupported payload、TOCTOU後の実送信bytesは保護済みと扱いません。実行方法、evaluated-only / end-to-end指標、限界は[Sink-first比較評価](docs/運用/Sink-first比較評価.md)を参照してください。

## 次に進めること

優先順位の正本は[実装タスク計画](docs/運用/実装タスク.md)とGitHub Issues / Projectです。

1. [#53](https://github.com/mani1261790/ToolUseProxy/issues/53): Codex Desktopで最新Hook定義を再trustし、UI表示に依存しないHook probeからpublic allow / protected block、update / removeまで完走する
2. [#54](https://github.com/mani1261790/ToolUseProxy/issues/54): adapter分類と実network egressをobserve-onlyで突き合わせ、外部sink判定の偽陰性を測る
3. [#55](https://github.com/mani1261790/ToolUseProxy/issues/55): Auditログを人間がlabelし、active learning・クラスタリング・rule miningで未知patternの調査を効率化する
4. [#38](https://github.com/mani1261790/ToolUseProxy/issues/38)でGit pushのoutgoing objectとbranch / worktree / 複数人開発を評価する
5. [#46](https://github.com/mani1261790/ToolUseProxy/issues/46)でlocal semantic backendをobserve-only比較し、[#37](https://github.com/mani1261790/ToolUseProxy/issues/37)でsession境界を測る

個別Issue番号と着手状況は[実装タスク計画](docs/運用/実装タスク.md)と[GitHub Project](https://github.com/users/mani1261790/projects/1)を正本にします。

## 研究の考え方

API keyのように文字列patternで判別しやすい秘密だけでなく、未公開コード、研究ノート、Git diff、設計方針など「由来によってprivateになる情報」を対象にします。流出防止では外部sinkの実payloadを最初に検査し、file参照、Git object、多段変換など直接比較だけで説明できない場合にlineageを補助証拠として使います。

研究は次の順に進めてきました。

1. Trace: 情報流を後から再構成できるようにする
2. Detect: protected sourceからsinkまでの到達を検知・説明する
3. Stop: 十分な根拠がある境界だけ、確認・差戻し・遮断へ接続する

現在は3段階の中核を維持しながら、sink直接検査だけで止められる範囲、semantic comparisonの追加効果、lineageが必要になる境界を分離評価しています。lineageを作ること自体ではなく、外部流出の検出率・誤停止・説明可能性を改善することを成功条件にします。

## 対象

- 未公開のソースコードやGit diff
- 研究ノート、Markdownメモ、実験ログ
- `.env`、SSH config、認証情報
- local database
- 公開前の設計方針、関数名、閾値、アイデア

企業向けの大規模DLPを導入しにくい個人開発者・学生研究者が、ローカルで軽量に試せる仕組みを目指します。

## ライセンス

ToolUseProxyは[Apache License 2.0](LICENSE)で提供します。

脆弱性の報告にsecret、protected source、local pathなどが含まれる可能性がある場合は、public Issueではなく[非公開の報告手順](SECURITY.md)を使用してください。

## 進捗管理

実装単位は[GitHub Issues](https://github.com/mani1261790/ToolUseProxy/issues)と[GitHub Project](https://github.com/users/mani1261790/projects/1)、public alphaの横断作業は[`v0.1.0 Public Alpha` milestone](https://github.com/mani1261790/ToolUseProxy/milestone/1)、週次の結果は[`weekly-report` Issue](https://github.com/mani1261790/ToolUseProxy/issues?q=label%3Aweekly-report)で管理します。運用規約は[進捗管理](docs/運用/進捗管理.md)にあります。
