# ToolUseProxy

Codexのtool useをローカルで観測し、protected sourceから外部toolや最終回答までの情報流を追跡・検知・制御するための研究実装です。

> 現在は`0.1.0-alpha.3`です。中核機能は動作しますが、公開release、配布物の供給網、cross-platform E2Eはまだ整備中です。

- [Codex Pluginとして試す](docs/設定/Plugin導入.md)
- [対応環境と既知の制限](SUPPORT.md)
- [プライバシーとデータ保持](PRIVACY.md)
- [Pluginドッグフード](docs/運用/Pluginドッグフード.md)
- [Release候補の作成と検証](docs/運用/Release候補.md)
- [現在地と実装ロードマップ](docs/運用/実装タスク.md)
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

## 現在地

| 領域 | 状態 | 現在の境界 |
| --- | --- | --- |
| 1. Trace | 中核完了 | event / artifact / resource / sinkをworkspace・session単位で追跡し、再現可能な解析runを保存 |
| 2. Detect | 中核完了 | protected source binding、lineage、finding、policy、類似度profile v2を実装 |
| 3. Stop | alpha実装済み | Stopの`continue_review`と、opt-inのBash / MCP PreToolUse denyを提供。runtime redactは無効 |
| Plugin化 | alpha.3 | installable package、relocatable Plugin、`PLUGIN_ROOT` / `PLUGIN_DATA`、初期化・診断・traceを実装 |
| protected source登録 | 明示承認型を実装済み | `scan` / `suggest` → exact proposal → `approve` / `reject` / `ignore`。無承認登録はしない |
| Public alpha | 準備中 | immutable release、LICENSE、checksum / SBOM、upgrade / rollback、cross-platform E2Eが未完了 |

設計全体は[アーキテクチャ概要](docs/設計/アーキテクチャ.md)、詳細な完了範囲と残作業は[実装タスク計画](docs/運用/実装タスク.md)を参照してください。

## Pluginを試す

Python 3.11または3.12とCodex CLIを用意し、現在のcheckoutをlocal marketplaceとして追加します。OS・機能別の境界は[サポート範囲](SUPPORT.md)を確認してください。

```bash
codex plugin marketplace add /absolute/path/to/ToolUseProxy
codex plugin add tooluseproxy@tooluseproxy
```

Codexが表示するHook definitionを確認してtrustし、新しいtaskを開始します。Pluginが示す`PLUGIN_ROOT` / `PLUGIN_DATA`を使って、対象workspaceで初期化と診断を行います。

```bash
sh "<PLUGIN_ROOT>/hooks/run_cli.sh" init --codex --data-dir "<PLUGIN_DATA>"
sh "<PLUGIN_ROOT>/hooks/run_cli.sh" doctor --workspace "$PWD" --data-dir "<PLUGIN_DATA>"
sh "<PLUGIN_ROOT>/hooks/run_cli.sh" status --workspace "$PWD" --data-dir "<PLUGIN_DATA>"
```

これは開発版の導入方法です。可変なremote `main`を実行元にせず、公開配布時はimmutableなtag / artifactへpinします。protected sourceの候補発見・承認、更新、削除時のdata保持を含む完全な手順は[Plugin導入](docs/設定/Plugin導入.md)にあります。

## 安全側の既定値

- 初期化前、壊れた設定、未知のschemaではHookをfail-openし、Hook中にmigrationしない
- protected sourceは`init`やHookから自動登録しない
- 候補の本文・値・source hash・absolute pathをagent向け出力へ含めない
- PreToolUse blockとMCP blockは既定で無効
- runtime redact / `updatedInput`は無効
- local監査dataをPlugin削除時に自動削除しない

## 品質ゲート

類似度profile v2はversioned synthetic corpusで次を固定しています。

- 38 pair、9 E2E scenario、16 candidate retrieval pool
- pair precision / recall / F1: `1.0`
- artifact recall@50、source recall@200: `1.0`
- E2E reachability / action: `1.0`
- false block、privacy exposure: `0`
- full / incremental parity: `9 / 9`

dataset digestは`241a4f536ea53694b8172accc5a528961673a843983f99702651357cff3619b3`です。再現方法、split、既知の限界は[類似度評価](docs/運用/類似度評価.md)に記録しています。

## 次に進めること

優先順位の正本は[実装タスク計画](docs/運用/実装タスク.md)とGitHub Issues / Projectです。

1. [#19](https://github.com/mani1261790/ToolUseProxy/issues/19): 固定済みartifact / Python 3.11・3.12 CI / support・privacy契約を検証し、LICENSEを決定する
2. [#19](https://github.com/mani1261790/ToolUseProxy/issues/19): 自動Phase A済みのalpha.3 dogfoodを、manual trustと実tool side effect 0を含むPhase Bで閉じる
3. [#20](https://github.com/mani1261790/ToolUseProxy/issues/20): 長い英字の公開compound誤検知と有限candidate capをadversarial corpusで改善・検証する
4. [#18](https://github.com/mani1261790/ToolUseProxy/issues/18): protected source onboardingを実Plugin E2Eで閉じ、runtime observed-pathやauto-enrollは別の研究判断として扱う
5. [#19](https://github.com/mani1261790/ToolUseProxy/issues/19): checksum / SBOM / release notes、upgrade / rollback、uninstall / retentionを揃えてpre-release化する

## 研究の考え方

API keyのように文字列patternで判別しやすい秘密だけでなく、未公開コード、研究ノート、Git diff、設計方針など「由来によってprivateになる情報」を対象にします。そのため、出力文字列だけを見るのではなく、どの入力・tool resultからどのtool input・最終回答へ移ったかを根拠に判断します。

研究は次の順に進めてきました。

1. Trace: 情報流を後から再構成できるようにする
2. Detect: protected sourceからsinkまでの到達を検知・説明する
3. Stop: 十分な根拠がある境界だけ、確認・差戻し・遮断へ接続する

現在は3段階の中核を維持しながら、第三者が安全に導入・更新・削除できるproductizationと、未知の反例に対するprecision hardeningへ進んでいます。

## 対象

- 未公開のソースコードやGit diff
- 研究ノート、Markdownメモ、実験ログ
- `.env`、SSH config、認証情報
- local database
- 公開前の設計方針、関数名、閾値、アイデア

企業向けの大規模DLPを導入しにくい個人開発者・学生研究者が、ローカルで軽量に試せる仕組みを目指します。

## 進捗管理

実装単位は[GitHub Issues](https://github.com/mani1261790/ToolUseProxy/issues)と[GitHub Project](https://github.com/users/mani1261790/projects/1)、public alphaの横断作業は[`v0.1.0 Public Alpha` milestone](https://github.com/mani1261790/ToolUseProxy/milestone/1)、週次の結果は[`weekly-report` Issue](https://github.com/mani1261790/ToolUseProxy/issues?q=label%3Aweekly-report)で管理します。運用規約は[進捗管理](docs/運用/進捗管理.md)にあります。
