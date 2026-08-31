# ToolUseProxy

ToolUseProxyは、AI coding agentがローカルの非公開情報を外部へ送ろうとしたとき、送信前に検知・停止するためのCodex Pluginです。

たとえば、未公開コード、研究ノート、`.env`、設計方針などを`protected source`として登録します。ToolUseProxyはCodexのtool useをローカルで観測し、外部送信候補へ保護情報が到達していないかを確認します。

本プロジェクトは[SecHack365](https://sechack365.nict.go.jp/)での研究・開発成果物です。現在の検証済みreleaseは`0.1.0-alpha.12`です。alpha.12では、設定や過去のblock記録が残っているだけで「保護中」と表示しません。現在のverification commandそのものに、インストール済みの同じPlugin版から`PreToolUse`が届いたことを確認して初めて`active`になります。研究用public alphaであり、完成したDLP製品ではありません。

Codex Pluginとしての導入、Hook配送確認、実行前停止、更新・削除はalpha.12で一区切りです。現在の開発テーマは、ToolUseProxy本体の検出精度です。実projectでfalse blockと見逃し候補を集め、sink payloadの解決、外部性判定、semantic、lineageのどこを改善すべきかを測ります。

> **以前の版から更新する場合:** `alpha.8`には、安全に確認できない外部payloadをblockせず実行する問題がありました。`alpha.9`は互換旧設定から更新できず、`alpha.10`は登録後に移動・削除された保護対象があるとローカル診断まで止まりました。`alpha.11`では過去セッションの成功を現在の保護状態と区別できませんでした。`alpha.12`へ更新し、Codexを完全に終了して起動し直した後、5 Hookを改めて確認してください。

- [5分クイックスタート](QUICKSTART.md)
- [詳しいPlugin導入ガイド](docs/設定/Plugin導入.md)
- [現行の研究方針](docs/研究/現行研究方針.md)
- [現在の実装順序](docs/運用/実装タスク.md)
- [対応環境と既知の制限](SUPPORT.md)
- [プライバシーとデータ保持](PRIVACY.md)
- [ドキュメント索引](docs/索引.md)
- [English introduction](README.en.md)

## 何をするものか

ToolUseProxyは、次の3段階で外部流出を調べます。

```text
守る情報を登録する
  -> Codexのtool useと情報の由来をローカルで追う
  -> 外部へ出る直前のpayloadを検査し、危険なら止める
```

現在利用できる主な機能は次のとおりです。

- `.env`、JSON、Markdownなどを、利用者の明示承認後だけ保護対象へ登録する
- protected sourceと送信payloadをexact、substring、token、shingleで比較する
- file read / writeやtool I/Oから、保護情報の到達経路を補助的に推定する
- Hookから見える全ローカルToolを`PreToolUse`で確認し、保護情報が外部へ渡る可能性がある入力を実行前に止める
- final answerにcriticalな候補がある場合、`Stop`で再確認を求める
- 判定根拠と監査記録をworkspaceごとのlocal SQLiteへ保存する

## 5分で試す

Python 3.11または3.12と、Plugin対応のCodex CLIまたはCodex Desktopを用意します。通常利用では、検証済みreleaseだけを配信する`public-alpha`を使います。

### 1. Pluginをインストールする

検証済みreleaseだけを配信する`public-alpha`からインストールします。

```bash
codex plugin marketplace add mani1261790/ToolUseProxy --ref public-alpha
codex plugin add tooluseproxy@tooluseproxy
```

これはCodex環境に対して1回だけ行います。Pluginは複数projectで使えますが、保護設定と監査dataはprojectごとに分離されます。

### 2. 5つのHookを確認する

Codexに表示されるsourceが`Plugin - tooluseproxy@tooluseproxy`で、`SessionStart`、`SubagentStart`、`PreToolUse`、`PostToolUse`、`Stop`の5件だけであることを確認してTrustします。source、件数、command pathが違う場合は許可しないでください。インストールや更新の直後は、Codexを完全に終了して起動し直してから新しいタスクを始めます。画面の版表示だけでは、実行中タスクが新しいHookを読み込んだ証拠になりません。

### 3. projectで有効にする

対象projectをCodexで開き、自然な言葉で依頼します。

> ToolUseProxyをこのプロジェクトで使えるようにして

これは入力例であり、この通りの言い方でなくても構いません。ToolUseProxyは初期設定と読み取り確認を行い、何を変更するか、外部通信があるか、なぜ許可が必要かをその場で説明します。設定だけが揃った状態は`configured_unverified`、現在のverification commandそのものへ実行前チェックが届き、実行中Pluginと一致した場合だけ`active`と表示します。内部では使い捨ての照合用tokenを使いますが、利用者が覚えたり入力したりするものではありません。通常、長い内部commandや保存先を利用者がコピーして貼り直す必要はありません。

### 4. 守る情報を選ぶ

続けて、たとえば次のように依頼できます。

> 守った方がよいファイルを探して

これも固定フレーズではありません。最大10件の候補について「どのファイルの何を守るか」「何を止められるか」「元ファイルを変更しないこと」を番号付きでまとめて説明します。「全部守る」「1と3は守る、2は見送る」のように一度に判断でき、ToolUseProxyが未判断の候補を無断で登録することはありません。

安全な試し方、更新、削除、data保持は[5分クイックスタート](QUICKSTART.md)にまとめています。

## 研究概要

ToolUseProxyの中心課題は、次の2つを組み合わせて漏えいを検知することです。

1. **送信内容を直接調べる**

   protected sourceをchunkに分け、外部sinkへ渡されるpayloadとの内容対応を調べます。完全一致だけでなく、部分一致や変形も段階的に評価します。

   MCPの`get`、`list`、`search`もqueryをserverへ送るため外部sinkです。上限内のMCP inputは全key/valueをactive source全体と比較し、比較を完了できない場合は実行前に止めます。

2. **情報の由来と送信先を調べる**

   tool I/Oやfile operationから情報の経路を推定し、保護情報が外部送信候補へ到達したかを調べます。外部通信する可能性は既知adapter、静的解析、保守的unknown判定を組み合わせます。

研究方針は`Sink-first, provenance-assisted`です。まず実際に送られるpayloadを検査し、直接比較だけでは分からないfile参照、Git object、多段変換などでprovenanceを補助証拠として使います。情報流graphを作ること自体は目的ではありません。

adapterにない未知のcallは、raw commandやpathなどを含まない構造要約だけをlocal queueへ保存できます。明示的にworkerを実行した場合に限り、jobごとの新しい`codex exec --ephemeral`セッションが外部通信可能性を分類します。ToolUseProxyはOpenAI APIやAPI keyを直接使わず、LLMの判断を自動で許可ruleへ昇格しません。この機能は実験段階で、既定では無効です。

仮説、検知モデル、評価指標、現在の証拠、未解決問題は[現行研究方針](docs/研究/現行研究方針.md)を正本とします。

## 現在の開発フェーズ

開発を2層に分けて管理します。

1. **Codex対応**

   alpha.12で完了しました。Hookから見えるローカルtoolについて、Plugin導入からprotected source登録、現在セッションのPreToolUse到達確認、実行前denyまでを実機で確認しています。Hosted toolなどHookへ届かない経路は、Codex側の既知境界として別に明示します。

2. **ToolUseProxy本体の検出精度**

   現在の開発対象です。直接一致とfile-backed payloadは実用可能ですが、動的shell、Git object、archive、言い換え・要約、多段変換、未知の外部通信候補には改善余地があります。安全に判定できないprotected flowは引き続き実行前denyし、そのうえでpublicな処理のfalse blockを減らします。

進行中の中心Issueは[実project pilot #99](https://github.com/mani1261790/ToolUseProxy/issues/99)と[Sink-first比較 #36](https://github.com/mani1261790/ToolUseProxy/issues/36)です。

## 現在地

| 領域 | 状態 | 現在の境界 |
| --- | --- | --- |
| Codex対応 | alpha.12で完了 | Plugin導入、workspace setup、protected source登録、現在のHook配送確認、実行前deny、update / rollback / removeを実証済み |
| Trace / Detect | 中核実装済み・精度改善中 | tool I/O、file operation、内容対応から観測可能なprovenanceを再構成。実project pilotでfalse blockと見逃し候補を測定 |
| Stop | 対応範囲内で実証済み | Hookから見えるローカルtoolを実行前判定し、protected flowの既知external / unknownをdeny。Stop再確認も提供 |
| Plugin配布 | alpha.12公開 | current-invocation照合、fresh Desktop、lifecycle、artifact、full testのrelease gateを通過したcommitだけを`public-alpha`へ配信 |
| 外部性判定 | local保護は通常setupで有効 | adapter、bounded static analysis、未確認external payloadのfail-closed、Codex-only background judge、人間review済みrule。LLM providerは既定off |
| 実network観測 | 評価専用 | Codex network proxyのOTLP eventは実行後かつtool単位join不能のため、production blockには不採用 |
| hosted tool境界 | 緩和のみ | SessionStart / SubagentStartでprotected contentをhosted toolへ渡さないdeveloper contextを注入。Hook非可視のため技術的遮断ではない |
| 現在のverification健全性 | alpha実装済み | 使い捨てtokenでverification command自身のPreToolUse eventを特定し、解析run、Plugin版、Hook定義hashを同一sessionで照合。別taskや過去sessionのblockは現在の`active`判定へ流用しない |

## 安全側の約束

- Hook内からnetwork、remote embedding、telemetryを使わない
- protected sourceを自動登録しない
- 移動・削除済みの保護対象は一括計画を示し、明示承認なしに登録を外さない
- 候補本文、raw command、URL、host、path、credentialをExternality Judgeへ送らない
- 初見unknownにprotected flowが到達した場合、background分類を待たず実行前に止める
- 外部payloadのoption、file size、入力形式、内部処理を安全に確認しきれない場合はallowせず実行前に止める
- LLM分類を自動採用せず、人間が確認した完全一致ruleだけをworkspace単位で使う
- 承認済みruleで既存adapterやstatic blockを弱めない
- runtimeによるtool inputの書換えは、最終入力を証明できないため無効にする
- 設定済み、Hook信頼済み、過去にblock済みという情報だけでは`active`にしない
- Plugin削除時にlocal監査dataを自動削除しない

## まだ保証しないこと

- 数学的な偽陰性ゼロ、または完全なDLP
- hosted Web Searchなど、Codex Hookへ現れない経路の技術的な実行前遮断（SessionStart / SubagentStartのdeveloper contextで誤送信を緩和するが、強制境界ではない）
- 実行中processへの`write_stdin`追加入力の再検査（新しい`PreToolUse`が発火しない）
- CodexがHookを省略する特殊なtool経路の遮断（現時点では未検証として表示する）
- 任意のprogrammatic nested tool経路の遮断。現在のCodex Desktopが使う、単一の`tools.exec_command`だけを含む固定wrapperはalpha.12実機で確認済みだが、別wrapper、複数command、他の入れ子toolへ一般化しない
- 任意program、暗号化・圧縮payload、Git objectの内容を常に自動判別すること。安全に確認できないHook-visible external操作は止めるため、false blockが発生し得る
- LLM内部の完全なtaint trackingや、意味類似度による因果関係の証明
- Linux / Windowsを含む全環境での同一動作

利用前に[対応環境と既知の制限](SUPPORT.md)と[プライバシーとデータ保持](PRIVACY.md)を確認してください。

## 文書の読み方

- 初めて使う: [5分クイックスタート](QUICKSTART.md)
- 研究内容を知る: [現行研究方針](docs/研究/現行研究方針.md)
- 実装を理解する: [アーキテクチャ](docs/設計/アーキテクチャ.md)
- 今後の作業を見る: [実装タスク](docs/運用/実装タスク.md)
- 過去の方針や実験経緯を調べる: [履歴資料](docs/履歴/README.md)

現行文書と履歴資料は混在させません。履歴資料は当時の判断を再現するために残しますが、現在の仕様や優先順位の根拠には使いません。

## ライセンスと報告

ToolUseProxyは[Apache License 2.0](LICENSE)で提供します。脆弱性報告にsecret、protected source、local pathが含まれる場合は、public Issueではなく[非公開の報告手順](SECURITY.md)を使用してください。

進捗は[GitHub Issues](https://github.com/mani1261790/ToolUseProxy/issues)、[GitHub Project](https://github.com/users/mani1261790/projects/1)、[`weekly-report` Issue](https://github.com/mani1261790/ToolUseProxy/issues?q=label%3Aweekly-report)で管理します。
