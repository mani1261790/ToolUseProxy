# Literature Review

このページは、ToolUseProxy の研究テーマに関連する文献を、開発の3段階に対応づけて整理したものです。

- 第1段階: 情報流を追跡可能にする
- 第2段階: 情報流から流出を検知する
- 第3段階: 情報流出を Stop する

同じ文献が複数段階に関係することはありますが、ここでは「どの段階で特に効くか」を基準に置いています。

## まず読む文献

最初に読む順番としては、次の4本が自然です。

1. [W3C PROV](https://www.w3.org/TR/prov-overview/)
2. [Provenance Traces](https://arxiv.org/abs/0812.0564)
3. [Practical Whole-System Provenance Capture (CamFlow)](https://arxiv.org/abs/1711.05296)
4. [RTBAS](https://arxiv.org/abs/2502.08966)

この4本で、

- provenance をどう表現するか
- trace をどう残すか
- 実運用でどう記録するか
- LLM agent にどう持ち込むか

が一通りつながります。

## 第1段階: 情報流を追跡可能にする

この段階では、「まず event と artifact を記録し、あとから情報の経路をたどれるようにする」ことが重要です。  
漏えい判定や遮断より前に、追跡可能なログ構造と provenance 表現を固めるための文献です。

### 1. W3C PROV

- URL: [https://www.w3.org/TR/prov-overview/](https://www.w3.org/TR/prov-overview/)
- 役割:
  - provenance を `entity / activity / agent` で表す標準モデル
  - ToolUseProxy の event ログや情報流グラフのデータモデル設計に直接使える
- この研究との対応:
  - `artifact` = entity
  - `PreToolUse` / `PostToolUse` = activity
  - Codex / user / tool = agent

### 2. Provenance Traces

- URL: [https://arxiv.org/abs/0812.0564](https://arxiv.org/abs/0812.0564)
- 役割:
  - 結果だけでなく、「どう導出されたか」を trace として残す考え方を与える
  - provenance に意味論的な基礎を与える文献
- この研究との対応:
  - `tool_input` や `tool_output` を単なる文字列ログではなく、導出経路付きで扱う発想に近い

### 3. Practical Whole-System Provenance Capture (CamFlow)

- URL: [https://arxiv.org/abs/1711.05296](https://arxiv.org/abs/1711.05296)
- 役割:
  - 実システムで provenance を継続記録し、後から監査・分析に使う実装例
  - provenance ログが大きくなりやすいことや、用途に応じた capture の絞り方も参考になる
- この研究との対応:
  - OS 全体ではなく Codex Hooks ベースだが、「まず記録し、後で auditor が見る」という構造が近い

### 4. OpenLineage

- URL: [https://openlineage.io/docs/](https://openlineage.io/docs/)
- 役割:
  - lineage を `job / run / dataset` で整理する実務寄りの標準
  - provenance 理論より軽く、イベントログ設計の参考にしやすい
- この研究との対応:
  - `tool call` を job/run 的に見る発想
  - `artifact` や source/sink を dataset 的に見る発想

## 第2段階: 情報流から流出を検知する

この段階では、「記録できた情報流から、どれが危険な流れかを見分ける」ことが中心になります。  
特に、LLM agent における confidentiality leakage、prompt injection、dependency screening の観点が重要です。

### 1. RTBAS: Defending LLM Agents Against Prompt Injection and Privacy Leakage

- URL: [https://arxiv.org/abs/2502.08966](https://arxiv.org/abs/2502.08966)
- 役割:
  - tool-based agent に Information Flow Control を適用しようとする近い研究
  - confidentiality と integrity を両方扱っている
- この研究との対応:
  - 「全部を taint すると広がりすぎる」という問題意識が近い
  - dependency screening や selective propagation は、artifact 間の類似度比較や依存推定に近い

### 2. AgentSecBench

- URL: [https://arxiv.org/abs/2605.26269](https://arxiv.org/abs/2605.26269)
- 役割:
  - privacy leakage と tool-use integrity を agent ベンチマークとして測る
  - 評価設計の観点で有用
- この研究との対応:
  - 正常タスク / 攻撃タスクの作り方
  - 検知性能だけでなく utility をどう見るか

### 3. Credential Leakage in LLM Agent Skills

- URL: [https://arxiv.org/abs/2604.03070](https://arxiv.org/abs/2604.03070)
- 役割:
  - skill / tool 実装がどのように credential leakage を起こすかを大規模に調べた研究
  - debug logging や stdout exposure が主要経路として出てくる
- この研究との対応:
  - tool output やログ保存が sink になることの裏付けになる
  - secret だけでなく、実装の流れ全体を見る必要性を説明しやすい

### 4. Not what you've signed up for: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection

- URL: [https://arxiv.org/abs/2302.12173](https://arxiv.org/abs/2302.12173)
- 役割:
  - 外部データに埋め込まれた指示が、後続の tool call や model output に影響する問題を整理した代表的な文献
- この研究との対応:
  - 「tool response は単なる data ではなく、次の行動に影響する」という問題の背景として重要

### 5. Your LLM Agent Can Leak Your Data: Data Exfiltration via Backdoored Tool Use

- URL: [https://arxiv.org/abs/2604.05432](https://arxiv.org/abs/2604.05432)
- 役割:
  - tool use 自体が外部送信の経路になり得ることを示す
  - multi-turn で leakage が増幅する点も重要
- この研究との対応:
  - 攻撃シナリオ設計の参考になる
  - `tool_input` と `tool_output` の両方を追うべき理由になる

## 第3段階: 情報流出を Stop する

この段階では、「危険な情報流が外部 sink に到達する前に止める」ことが中心になります。  
この段階に入って初めて、警告、遮断、ユーザー確認、マスクなどの介入設計が必要になります。

### 1. ClawGuard: A Runtime Security Framework for Tool-Augmented LLM Agents Against Indirect Prompt Injection

- URL: [https://arxiv.org/abs/2604.11790](https://arxiv.org/abs/2604.11790)
- 役割:
  - tool-call boundary で実行時に介入する runtime security framework
  - deterministic な boundary enforcement を強く打ち出している
- この研究との対応:
  - ToolUseProxy の第3段階である `warn / confirm / redact / block` の比較対象として使いやすい

### 2. RTBAS

- URL: [https://arxiv.org/abs/2502.08966](https://arxiv.org/abs/2502.08966)
- 役割:
  - 第2段階だけでなく、第3段階にもまたがる
  - confidentiality / integrity が保てない場合だけ user confirmation を要求する設計
- この研究との対応:
  - 「常に止める」のではなく、「危険な場合だけ確認させる」という設計判断の比較対象になる

### 3. Design Patterns for Securing LLM Agents against Prompt Injections

- URL: [https://arxiv.org/abs/2506.08837](https://arxiv.org/abs/2506.08837)
- 役割:
  - LLM agent を prompt injection に強くする設計パターンをまとめている
  - policy, tool restriction, confirmation, isolation といった設計選択の整理に向いている
- この研究との対応:
  - 実装そのものより、第3段階の policy engine 設計や stop 条件の言語化に使いやすい

## sandbox との関係

この研究をセキュリティの文脈で説明するとき、sandbox の話がよく出ます。  
これは重要ですが、この研究の主題そのものではありません。

- sandbox
  - そもそも読める source や到達できる sink を減らす
  - 予防策
- ToolUseProxy の情報流追跡
  - 読めてしまった情報が、どこからどこへ流れたかを追う
  - 観測・監査・検知策

つまり、sandbox は前段で attack surface を減らし、ToolUseProxy は許可された権限の中で起きる private 情報の流れを監視する役割です。

## 今の段階で特に読む価値が高いもの

現在の実装はまだ第1段階なので、特に重要なのは次の文献です。

1. [W3C PROV](https://www.w3.org/TR/prov-overview/)
2. [Provenance Traces](https://arxiv.org/abs/0812.0564)
3. [CamFlow](https://arxiv.org/abs/1711.05296)
4. [RTBAS](https://arxiv.org/abs/2502.08966)

この4本を読むと、

- event / artifact の表現
- flow graph の表現
- 監査ログの設計
- selective propagation の必要性

がかなり整理しやすくなります。
