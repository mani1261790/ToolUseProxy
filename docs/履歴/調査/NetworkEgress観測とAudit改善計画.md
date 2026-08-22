# Network egress観測とAudit改善計画（履歴）

> この文書は2026-08-11までの調査過程とnegative resultを保存する履歴資料です。現行方針の正本ではありません。現在の研究方針は[現行研究方針](../../研究/現行研究方針.md)、外部通信可能性の実装ロードマップは[Externality Protectionロードマップ](../../運用/ExternalityProtectionRoadmap.md)を参照してください。

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

## Codex network境界の現在の契約

2026-08-11時点の公式仕様では、ローカルCodexのnetwork accessは既定で無効です。command networkを有効にした場合、`network_proxy`のdestination ruleはscript、program、subprocessへ適用されます。`network_proxy`自体はnetwork accessを許可せず、allowlist-firstで`deny`が優先します。

- [Agent approvals & security](https://learn.chatgpt.com/docs/agent-approvals-security)
- [Hooks](https://learn.chatgpt.com/docs/hooks)

ToolUseProxyは、この境界を「漏えい判定器そのもの」にはしません。役割は次のとおり分離します。

```text
Codex network sandbox / proxy
  -> local commandがnetworkへ出る事実を広く制御・観測する候補

ToolUseProxy DLP / lineage
  -> protected source由来の情報が送信対象へ到達したかを判定する

policy
  -> externalityとleakageの両証拠を使い、allow / deny / unknownを決める
```

公開Hook契約の`PermissionRequest`はmanaged-network approval時にも実行され、allow、deny、通常のapproval継続を選べます。ただし公開されている入力は`turn_id`、`tool_name`、`tool_input`、任意の説明であり、network host / protocolの構造化fieldや`tool_use_id`は記載されていません。したがって、公開Hookだけからnetwork factを安定joinできるとは扱いません。

一方、ローカルCodex 0.145.0のexperimental app-server schemaには、`item/commandExecution/requestApproval`、`itemId` / `threadId` / `turnId`、`networkApprovalContext.host` / `protocol`が存在します。これは有力なcandidateですがexperimentalです。`scripts/probe_codex_network_boundary.py`は実network接続を行わず、network policyや設定ファイル本文を保存せずに、このschema capabilityだけをfail-closedに確認します。production Hookとの同一性は推定しません。

probeの実行例:

```console
python3 scripts/probe_codex_network_boundary.py --require-candidate
```

この結果が`AVAILABLE`でもproduction integrationを有効にしません。Codex version更新ごとに再probeし、実機のevent correlation、欠落、重複、latencyを別sliceで測ります。

### 2026-08-11実機probeと観測境界

`networkApprovalContext`のschema存在だけでは、通常のローカル`network_proxy`による遮断をapp-server approvalとして観測できません。Codex 0.145.0の実装も確認した結果、network policy deciderとapp-server approval callbackが接続されるのは、管理者が`requirements.toml`の`experimental_network`を構成したmanaged environmentだけでした。一般利用者向けPluginのためにsystem-wideなmanaged設定を導入することは、権限と影響範囲が広すぎるため行いません。

外部modelや課金を使わないlocalhost固定mock providerとephemeral app-server turnを作り、固定public hostへのsynthetic `exec_command`をempty allowlistで3回実行しました。内部proxy stderrは公式protocolではないため、引き続きobserverへ採用していません。

その代わり、Codexが公式に出力できるOTLP/HTTP JSON logをlocalhost collectorへ送り、`codex.network_proxy.policy_decision`だけを値非保持snapshotへ変換しました。

```console
PYTHONPATH=. python3 scripts/run_codex_network_live_probe.py \
  --execute \
  --repeats 3 \
  --require-live-contract
```

結果:

- network policy decision event: 3 / 3
- conversation単位のjoin: 3 / 3
- event latency: p50 `107.714 ms`、p95 `109.363 ms`
- app-server network approval: 0 / 3
- `execution.id`によるTool Use単位の厳密join: 0 / 3
- 同じOTel endpointへ届いた非network event: 54件
- 値を含み得る`codex.tool_result` event: 3件
- ToolUseProxyのreportへ保持されたraw value: 0件

この結果は二つに分けて扱います。

1. OTel transport contract: `PASS`。通常のlocal network proxy decisionをshadow評価で数える用途には使える
2. production observer: `INELIGIBLE`。decision後の非同期logであり、Tool Use単位の厳密joinがなく、endpointには値を含み得る他eventも届く

したがってOTel collectorは合成fixtureとisolated evaluationだけに限定し、production Hook、deny policy、一般Plugin設定、学習用Auditへは接続しません。productionで普遍的な実行前制御を行うには、次のいずれかが必要です。

1. 通常のlocal sessionでも使える、安定したCodex network-decision callback
2. ToolUseProxy自身が全commandを実行するcross-platform executor / sandbox
3. enterprise管理下に限定したmanaged `requirements.toml` integration

一般利用者へ最も小さい権限と負担で提供できるのは1です。2は互換性と保守負担が大きく、3は一般Pluginの解決策にはなりません。この境界が解消するまでproduction blockへ昇格しません。

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

### 実装済み: contract / corpus slice

最初のsliceではproduction runtimeを変更せず、次を実装しました。

- version付きvalue-free schemaと21件のsynthetic corpus
- development / validation分離
- adapter externality、observer attempt、unknown egress、exact join、Hook visibilityのreport
- hosted / unobservableをlocal observerの偽陰性分母から分離
- command、argv、host、URL、DNS label、payload、protected valueをcase schemaで受理しないstrict loader
- raw value exposure 0とcoverageだけを確認するCI foundation gate

実行例:

```console
python3 -m hook_monitor.evaluation.network_egress_cli \
  --dataset tests/fixtures/network_egress/v1 \
  --split all \
  --format text \
  --check
```

v1 baselineはadapter externality recall `0.308`、unknown egress rate `0.692`です。これはsynthetic labelに基づく現状仮説であり、実network ground truthではありません。精度をCI合否へ使わず、次sliceの実測で置き換えます。

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

1. 完了: workspace単位のruntime設定を永続化し、Desktop / CLIで同じobserve-only flagを使えるようにする
2. 完了: value-freeな観測契約、synthetic corpus、adapter differential baselineを固定する
3. 完了: isolated synthetic runnerでapp-server approvalとOTel policy-decisionを分けて測定した
4. 完了: OTel eventの欠落、conversation join、Tool Use join、p50 / p95 latency、raw exposureを測定した
5. 停止: OTelは実行前制御・厳密join・入力eventの値非保持を満たさないため、production shadow observationへ昇格しない
6. 人間label schema、無作為sample、active-learning queueを追加する
7. rule candidateをoffline replayし、shadow modeで改善量と副作用を測る
8. 十分なrecall / precisionを得た決定的ruleだけをadapterへ昇格する

次sliceでも広い再利用可能permissionやglobal `*` allow ruleは要求しません。合成値と明示destinationだけを使い、observerが欠落・曖昧・version不一致なら`unknown`として安全停止します。

## 非目標

- 全OS・全processの完全な通信傍受
- TLS payloadの復号
- hosted Web Search / MCP内部通信の完全観測
- modelによるオンライン自己更新
- semantic score単独の自動block
- 実secretを学習datasetやGitHub artifactへ保存すること
