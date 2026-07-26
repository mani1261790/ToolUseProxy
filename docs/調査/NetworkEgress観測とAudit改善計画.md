# Network egress観測とAudit改善計画

## 結論

ToolUseProxyのBash adapterは、`curl`や`git push`など既知のcommandを外部sinkとして分類します。しかし、これは実network接続そのものの観測ではありません。未知binary、Python / Node.js、raw socket、DNS、wrapper経由では、通信が起きてもadapterが見逃す可能性があります。

この不足は、低レイヤーの観測へ全面的に置き換えるのではなく、二つの証拠を分けて補います。

```text
tool adapter
  -> 何を送ろうとしているか、payloadをどう解決するか

network observation
  -> local processが実際にどこへ接続を試みたか

差分評価
  -> adapterが見逃した接続、誤ってexternal扱いしたcallを見つける
```

network observationは外部性のground truth候補です。TLSで暗号化されたpayloadやhosted tool内部の通信までは見えないため、protected内容の漏えい判定にはadapter、payload resolver、source comparison、必要に応じたlineageが引き続き必要です。

## 分けて測る二つのrecall

| 指標 | 問い | 主な証拠 |
| --- | --- | --- |
| externality recall | 実際のnetwork attemptをexternal sinkと分類できたか | OS / sandbox / local proxyのvalue-free観測 |
| leakage recall | protected内容を含む送信を検知できたか | resolved payload、exact / typed / semantic comparison、lineage |

実network attemptの総数が分からない状態では、「adapterの偽陰性はない」とは言いません。最初にobserve-onlyの分母を作り、block policyは変えません。

## Phase 1: value-freeなegress observation

synthetic workspaceと専用runnerで、次の情報だけを記録します。

- event / process / tool callと結合するためのID
- executable familyとargv structure
- protocol
- destination class: loopback / private / public / reserved / unknown
- port class
- connection attempt / success / failure
- adapterが付けたsink type
- join statusと観測時刻

raw payload、protected value、認証情報、DNS label、URL queryは保存しません。HTTPSを復号するMITM、root権限を必要とするsystem-wide interception、利用者全体の通信収集は初期scopeに含めません。

評価corpusには、既知command、`env curl`などのwrapper、Python `requests`、Node `fetch`、`nc`、custom executable、DNS / UDP、失敗する接続、loopback / private destination、public / protected payloadを含めます。Web Search、MCP、Browser / Computer Useはlocal process観測と一致しない可能性を別bucketで報告します。

## Phase 2: adapter differential benchmark

同じcaseについて、adapter分類とnetwork observationを突き合わせます。

- adapter externality recall
- unknown egress rate
- external分類のprecision
- tool eventとのjoin成功率 / 誤結合率
- program / protocol / destination class別のcoverage gap
- Hookと観測器のp50 / p95 latency
- raw protected value exposure

観測器が見えないhosted tool、TLSで見えないpayload、OS差を`unknown`として残します。見えないものをallowやsafeへ丸めません。

## Phase 3: Auditログからの改善

Audit modeは強化学習ではありません。初期段階では、教師あり学習、active learning、クラスタリング、rule mining、人間のlabelを組み合わせます。

人間が全件を順番に読む代わりに、次を優先してreviewします。

- 実egressあり・adapter分類なし
- policy threshold付近
- 未知のexecutable / destination / argument構造
- semanticとlineageの判定不一致
- severityが高いcase
- 既存clusterから遠いnovel case
- allowされたcallの無作為sample

最後の無作為sampleは、既知のblock候補だけを見るselection biasを避け、偽陰性の分母を維持するために必要です。

MLへ渡すfeatureは、executable、argv構造、protocol、destination class、sink type、source sensitivity、match method、lineage hop、size bucket、outcome、policy actionなど、値を含まない構造情報を基本にします。

MLの初期用途は次に限定します。

1. review順序を付ける
2. 類似eventをcluster化する
3. 新しいadapter rule候補を提案する
4. offline replayで既存policyとの差分を予測する

model出力だけでallow例外やblock規則を自動配信しません。poisoning、concept drift、誤labelを避けるため、候補はversion付きdatasetでoffline validationし、shadow modeと人間reviewを通してから昇格します。network接続の有無、exact secret match、Git object解析のように決定的に判定できる箇所はMLへ置き換えません。

## 実装順

1. workspace単位のruntime設定を永続化し、Desktop / CLIで同じobserve-only flagを使えるようにする
2. value-freeな`egress_observations`契約とsynthetic corpusを固定する
3. adapter differential reportを作り、externality recallのbaselineを出す
4. 人間label schema、無作為sample、active-learning queueを追加する
5. rule candidateをoffline replayし、shadow modeで改善量と副作用を測る
6. 十分なprecisionを得た決定的ruleだけをadapterへ昇格する

## 非目標

- 全OS・全processの完全な通信傍受
- TLS payloadの復号
- hosted Web Search / MCP内部通信の完全観測
- modelによるオンライン自己更新
- semantic score単独の自動block
- 実secretを学習datasetやGitHub artifactへ保存すること
