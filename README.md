# ToolUseProxy

Codex の tool use における情報の流れを追跡し、ローカルの秘密情報が外部へ流出する過程を検知・制御するための研究プロジェクトです。

## 背景

LLM コーディングエージェントは、ローカルファイルの読み書き、shell 実行、Git 操作、Web 検索、MCP tool の呼び出しなどを組み合わせて開発を進めます。その過程では、エージェントが一度読み取った未公開コード、研究ノート、Git diff、実験ログ、`.env` などの情報が、後続の tool input や最終回答へ意図せず含まれる可能性があります。

API キーや認証情報のように文字列パターンで判別しやすい秘密だけでなく、未公開の実装方針や研究中のアイデアのように、由来や文脈によって private になる情報も対象です。このような情報は、出力された文字列だけを調べても秘密だと判断できない場合があります。

本プロジェクトでは、情報が「どの入力や tool result から来て、どの tool input や出力へ移ったのか」を記録し、その情報流を根拠として流出を検知する方法を検討します。最初から遮断機能を作るのではなく、次の3段階で研究と実装を進めます。

## 研究ロードマップ

### 1. 情報流を追跡可能にする

まず、Codex が扱う入力・tool use・出力を観測し、情報がどのように受け渡されたかを再構成できる状態を目指します。

- Codex の event と Hooks の実装・データ形式を解析する
- 必要に応じて MCP call に対象を絞り、tool の入出力を取得する方法を調査する
- tool の入出力間でコサイン類似度が情報流の推定に使えるか検証する
- コサイン類似度で不十分な場合は、完全一致、部分一致、n-gram、embedding などの手法を比較する
- 類似度や一致関係をもとに、入力から中間出力、最終出力までの情報の流れをたどる
- 入力・中間出力・最終出力に一意な ID を付与する
- 共通のイベントログ形式を設計する
- イベントログを時系列で保存する
- 情報流をグラフとして表現・可視化する

この段階では「漏えいかどうか」の判定よりも、後から情報の経路を説明できることを優先します。

### 2. 情報流から流出を検知する

追跡可能になった情報流を使い、秘密情報源から外部への流れを判定します。

- 情報流の源泉に、事前に指定した秘密情報源が含まれるかを調べる
- 秘密情報源との一致度や類似度から流出を検知する
- API キーや認証情報など、明確な秘密情報の流出も検知する
- プロンプト、tool input、tool output、最終回答を別々の検知点として扱う
- 判定ログに、検知理由と根拠になった情報流を残す
- secret canary を埋め込み、追跡・検知できるか実験する
- 誤検知と見逃しの事例を収集する
- ベンチマーク用の正常シナリオと攻撃シナリオを作成する

検知結果だけでなく、「どの秘密情報源から、どのイベントを経由して、どこへ到達したため危険と判断したのか」を説明できることを目標とします。

### 3. 情報流出を Stop する

流出を十分に検知できるようになった後、危険な tool use の実行前に介入します。

- MCP call などの実行前に DLP チェックを挟む
- 危険度に応じて、許可・ユーザー確認・マスク・遮断を切り替える
- tool arguments から秘密情報に該当する部分を削除または置換する
- ユーザー確認を必要とする条件を定義する
- ブロック時の代替応答を設計する
- 誤遮断を安全に解除する方法を設計する
- 遮断の理由と対象になった情報流をログに残す
- Codex Hooks、OpenClaw、または外部プロキシとの接続方法を検討する

## 現在地

現在は第3段階の実行時介入へ進み、外部tool送信とCodex最終応答をgraph上の出口として扱っています。Codexの`PreToolUse` / `PostToolUse` / `Stop` HooksからeventとartifactをSQLiteへ記録し、artifact fragment間の類似関係とadapterが作るstructured edgeから情報流グラフを構築します。`apply_patch`はfile operation単位、Bashは静的に理解できるsegment単位へ分解し、成功を確認できた`PostToolUse`では変更対象pathだけをbounded snapshotの候補にします。snapshot本文は既定で保存せず、安定して全体を読み取れたファイルのSHA-256をresource versionへ接続します。operation outcomeとsnapshotもsession差分解析へ統合しています。

`scripts/detect_leaks.py`はsource lineageが`sink_candidate`へ到達した場合にfindingを出し、`scripts/evaluate_policy.py`は`allow` / `warn` / `block` / `continue_review`へ変換します。実Hookでは、Stopが`final_answer`漏えい候補を`continue_review`で差し戻し、opt-inのBashとMCP PreToolUseがcriticalなexternal sinkを`permissionDecision: deny`で実行前遮断します。MCPは追加のopt-inを必要とし、write-like toolだけを対象にします。両方ともworkspace・session単位の差分解析を共有し、介入判断は`policy_decisions`へ保存します。

複数workspaceの分離も実装済みです。明示したcanonical workspace rootをidentityとし、event、source、cursor、resource、edge、解析runをworkspaceごとに分離します。runtimeは現在eventのworkspaceとsessionだけを更新し、offline CLIは`--analysis-run ID`または`--workspace-root PATH --latest`の明示を必須にします。completed offline runはedgeだけでなくnode metadataもcontent-addressed snapshotとして保持するため、後からlive DBのnodeが変わっても過去runを再現できます。`PermissionRequest`は実payload、公式実装、実Codexのdeny / allowを検証した結果、PreToolUseの代替にならず、現時点では汎用runtime接続を追加しないと判断しました。redactは現行Codexの複数rewrite競合を考慮し、runtimeへ即接続せず、MCP tool profileと実行しないpreview plannerから始める設計にしています。

Hook の構成と接続方法は [docs/設定/Hook設定.md](docs/設定/Hook設定.md) にまとめています。
ドキュメント全体の索引は [docs/索引.md](docs/索引.md) にまとめています。
情報流グラフと lineage の設計は [docs/設計/情報流追跡.md](docs/設計/情報流追跡.md) にまとめています。
tool固有のI/Oを共通グラフへ変換するadapterは [docs/設計/アダプター.md](docs/設計/アダプター.md) にまとめています。
外部流出候補を表す SinkCandidate と adapter の関係は [docs/設計/外部流出候補.md](docs/設計/外部流出候補.md) にまとめています。
情報流から漏えい候補を検知する設計とCLIは [docs/設計/漏えい検知.md](docs/設計/漏えい検知.md) にまとめています。
検知結果を実行判断へ変換するpolicy判断は [docs/設計/Policy判断.md](docs/設計/Policy判断.md) にまとめています。
tool inputの安全な書換境界とpreview-first rolloutは [docs/設計/Redact.md](docs/設計/Redact.md) にまとめています。
情報流グラフの経路確認とMermaid/DOT出力は [docs/設計/可視化.md](docs/設計/可視化.md) にまとめています。
関連文献の整理は [docs/調査/関連文献.md](docs/調査/関連文献.md) にまとめています。
次に実装するタスクは [docs/運用/実装タスク.md](docs/運用/実装タスク.md) にまとめています。

## 進捗管理

研究・実装タスクはGitHub IssuesとGitHub Projectで管理し、毎週の進捗は`weekly-report`ラベルを付けたIssueとして記録します。READMEには研究全体の目的と現在地だけを掲載し、週報本文は蓄積しません。

- [研究Project](https://github.com/users/mani1261790/projects/1)
- [週次進捗報告](https://github.com/mani1261790/ToolUseProxy/issues?q=label%3Aweekly-report)
- [進捗管理の運用方法](docs/運用/進捗管理.md)
- [実装タスク計画](docs/運用/実装タスク.md)

## 想定する対象

- 未公開のソースコードや Git diff
- 研究ノート、Obsidian、Markdown メモ
- `.env`、SSH config、認証情報
- ローカルデータベースや実験ログ
- 公開前の設計方針、関数名、閾値、アイデア

特に、企業向けの大規模な DLP や監査基盤を導入しにくい個人開発者・学生研究者が、ローカル環境で軽量に利用できる仕組みを目指します。
