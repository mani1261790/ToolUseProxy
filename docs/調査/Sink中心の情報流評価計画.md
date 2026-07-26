# Sink中心の情報流評価計画

## 結論

ToolUseProxyの第一目的は、protected sourceの情報が外部sinkへ送られる直前に検知・制御することです。情報流graphは目的そのものではなく、sinkの実payloadを見つけ、判定の確信度を上げ、人間へ根拠を説明するための補助手段と位置付けます。

今後の研究方針を次のように固定します。

```text
Sink-first, provenance-assisted

外部sinkを特定する
  -> 実際に送信されるpayloadを解決する
  -> protected sourceと型別に比較する
  -> 必要な場合だけlineageを補助証拠として使う
  -> allow / warn / ask / blockを判断する
```

現行実装が扱うのは、Codexから観測できるtool I/O、file operation、resource、sinkの範囲です。LLM内部の表現、推論、要約、判断への因果的な影響を直接観測するものではありません。したがって、字句または意味上の近さを「情報が流れた証明」とは呼びません。

## なぜsink-time検査を中心にするか

外部流出を止める最終境界は、HTTP request、Web search、MCP call、file upload、Git publish、final answerなどのsinkです。途中の経路を完全に再構成できなくても、送信payloadにprotected valueが完全一致すれば実行前に止められます。

一方、tool inputの表面だけではpayloadが見えないsinkがあります。

```text
curl --data @generated-summary.txt ...
git push origin main
upload_file(path="report.zip")
```

この場合、送信されるfile、archive、Git objectを解決して検査する必要があります。lineageは有力な手掛かりですが、可能な限りsink固有adapterで実payloadを構造的に解決する方を優先します。

## 比較する4方式

同じcorpusとpolicy条件で、次を段階的に比較します。

| 方式 | 内容 | 明らかにしたいこと |
| --- | --- | --- |
| A. direct lexical | sink tool inputをexact / canonical / substring / lexicalで比較 | 現在の直接検査だけで止められる範囲 |
| B. resolved payload | sink固有adapterでfile、body、Git objectなどを解決して型別比較 | tool inputに本文がないsinkの改善量 |
| C. semantic | Bへlocal semantic comparisonをobserve-onlyで追加 | paraphrase、翻訳、要約、コード変換の改善量と誤検知 |
| D. lineage-assisted | B・Cへ構造edgeとlineage evidenceを追加 | 多段変換、境界跨ぎ、説明可能性への追加効果 |

DがB・Cをほとんど改善しない場合、lineageのruntime優先度を下げます。改善するcaseが限定的なら、そのsinkやboundaryだけに適用します。情報流graphを維持すること自体を成功条件にはしません。

## protected sourceの型別比較

すべてのsourceへ同じ「意味類似度」を適用しません。

| Source | 主な比較 |
| --- | --- |
| API key、token、password | raw / canonical exact、encoding、selector |
| メール、住所、ID、設定値 | structured field、canonical、部分一致 |
| 非公開prose、研究ノート | chunk lexical、local semantic |
| source code、Git diff | token、identifier、AST / code feature、local semantic |
| 数値、分析結果、判断材料 | structured dependency、周辺context、介入実験 |
| file、archive、Git publish | 実payload / object解決、hash、content comparison |

credentialに対するsemantic similarityは主経路にしません。一般的な文章やコードのsemantic similarityは因果関係を証明しないため、最初は監査・評価だけに使います。

## 「観測」と「推定」の言葉を分ける

結果と説明では、少なくとも次の4区分を混ぜません。

- `observed_transfer`
  - file read / write、pipe、tool use ID、sink argumentなどの構造で確認した移動
- `content_correspondence`
  - exact、canonical、substring、lexical similarityで確認した内容対応
- `inferred_influence`
  - semantic similarityや複数証拠から推定した影響
- `unobserved_internal_transformation`
  - LLM内部で行われ、現在のHook境界から確認できない変換

類似度だけで因果的な情報流を断定しません。因果依存に近づく評価では、protected sourceだけを置き換えてsink出力の変化を測る介入実験を行います。ただしLLMの非決定性があるため、同一条件を複数回実行し、単発差分を証明として扱いません。

## 評価tensor

評価caseは次の積で整理します。

```text
Source × Transformation × Boundary × Sink
```

### Source

- credential
- structured secret / PII
- private prose
- source code / Git diff
- numeric result / decision material

### Transformation

- exact copy、substring
- canonicalization、URL / JSON / Base64 encoding
- file copy、rename、archive
- paraphrase、translation、summary
- prose-to-code、code-to-prose
- aggregation、複数sourceの混合
- split transmission
- calculation、control dependence

### Boundary

- same turn / same task
- resumed task / new task
- context compaction
- subagent handoff
- branch switch / worktree
- another clone / another contributor
- Plugin update / DB restart

### Sink

- HTTP request
- Web search
- MCP external call
- final answer
- file upload
- Git push / tag publish

## 指標

- sink payload extraction recall
- leak detection precision / recall / F1
- policy action accuracy
- false block件数
- lineage追加による差分改善量
- earliest detection point
- boundary後のrecovery distance
- raw protected value exposure
- Hook p50 / p95 latency
- offline rebuild時間
- DB保存量とretention
- 説明を人間が正しく理解できる割合

合成corpusはdevelopment / validationを分離し、必要に応じてrepository外holdoutをaggregate-onlyで評価します。実secret、remote embedding、telemetryは使用しません。

## Policyへの接続

初期評価では証拠別に扱います。

| 証拠 | 初期action |
| --- | --- |
| exact / canonicalかつ実payloadへのstructured connection | block候補 |
| encoding / typed structured match | block候補 |
| semantic match + independent structured / lineage evidence | askまたはobserve |
| semantic matchのみ | observe / warn候補 |
| unsupported / payload未解決 | 保護済みと表示せず、理由付きunknown |

semantic-onlyの自動blockは、独立validationと人間評価で十分なprecisionを得るまで有効にしません。

## Gitが示すlineageの必要性

`git push origin main`というtool inputには、送信されるcommitやblobの本文がありません。そのため、command文字列とprotected sourceの比較だけでは漏えいを検知できません。

Gitでは次を別々に評価します。

1. refspecからoutgoing commit rangeを求める
2. reachable objectとblobをboundedに列挙する
3. protected source、resource version、blob内容を型別に比較する
4. branch、worktree、manifest revisionの境界を記録する
5. 他者commitの取り込みとlocal DB非共有の限界を説明する

これはlineageが価値を持ち得る代表例ですが、最終判断は[#36](https://github.com/mani1261790/ToolUseProxy/issues/36)の比較評価で行います。

## 実装判断の順序

1. [#36](https://github.com/mani1261790/ToolUseProxy/issues/36)でsink-only / semantic / lineage-assistedの評価契約を固定する
2. [#37](https://github.com/mani1261790/ToolUseProxy/issues/37)でsession / compaction / subagent境界を測る
3. [#38](https://github.com/mani1261790/ToolUseProxy/issues/38)でGit payloadと複数人開発を測る
4. 結果に基づき[#39](https://github.com/mani1261790/ToolUseProxy/issues/39)のbounded reconcileを実装するか判断する
5. local semantic backendはobserve-onlyのprivacy / latency / precision gateを通った場合だけproduction候補にする

## 2026-07-26時点の実装

Issue #36の最初のsliceとして、production policyを変更しない独立benchmark foundationを実装しました。

- `tests/fixtures/sink_benchmark/v1`にdevelopment / validation各6件を固定
- 各splitでBash、MCP、final answerの正例・負例を必須化
- direct lexical、resolved lexical、任意のlocal semantic、現行runtime lineageを同じcaseで比較
- source-ingestion v3の実runtime harnessを再利用し、full / incremental parityを同時確認
- reportへsource本文、protected value、raw target payloadを含めないprivacy gate
- semanticはobserve-onlyで、backend未設定時は精度0として扱わず`unavailable`と明示
- v1では`curl @file`を推測解決せず`unsupported`と明示
- v1.1では評価専用のbounded `--data-binary @file` resolverを追加
- evaluated-onlyと、unsupportedをfail-openとして含むend-to-end指標を分離
- resolver v2ではPOSIX component-wise directory FD traversal、1 command 8 file reference、200 ms budgetを固定
- 値を返さずworkspace / snapshot semantics / source chunk ID / exact match / aggregate costだけを持つpayload evidence契約を追加

v1.1の全12ケースでは、direct end-to-end recallは`0.333`、resolved lexicalは`0.667`、現行runtime lineageは`0.333`でした。resolved precisionは`1.0`、file-backed payload resolutionは4 / 4、raw fixture exposureは0です。component-wise openはresolver内部の親path差し替えを防ぎますが、resolverが取得するのは実行前snapshotであり、Hook後にtarget toolが再読込するTOCTOUと実送信bytesの同一性は解消しません。そのためproduction Hookには未接続です。再現方法は[Sink-first比較評価](../運用/Sink-first比較評価.md)、evidence境界は[Sink payload evidence](../設計/SinkPayloadEvidence.md)に記載します。

## 今は保証しないこと

- LLM内部の完全なtaint tracking
- semantic similarityによる因果関係の証明
- Codex外のterminal、IDE、Git GUI操作の遮断
- remote machine間・複数人間のlineage自動統合
- 任意shell program、暗号化・圧縮payload、未知binaryの完全解決
- 全session・全workspaceを毎Hookで再解析すること
