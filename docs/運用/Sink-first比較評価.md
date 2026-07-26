# Sink-first比較評価

## 目的

外部sinkの入力を直接見るだけで検知できる範囲と、payload解決、semantic comparison、lineageを加えたときの改善量を、同じ合成corpusで比較します。情報流graphの存在自体を成功条件にはしません。

このrunnerは評価専用です。Hookのproduction policy、block条件、network設定を変更せず、target toolも実行しません。

## 実行方法

Python 3.11または3.12の開発環境で実行します。

```bash
python -m hook_monitor.evaluation.sink_benchmark_cli \
  --dataset tests/fixtures/sink_benchmark/v1 \
  --split all \
  --format text \
  --check
```

machine-readableな結果も同時に保存できます。

```bash
python -m hook_monitor.evaluation.sink_benchmark_cli \
  --split all \
  --format json \
  --output-json /tmp/tooluseproxy-sink-benchmark.json \
  --check
```

`--check`が現在検査するのは、dataset契約、評価coverage、runtime full / incremental parity、reportのprivacyです。精度値は改善前baselineを含むため、まだpass条件にはしていません。

## 4つのprofile

| Profile | 現在の入力 |
| --- | --- |
| `direct_lexical` | Bash command全体、MCP arguments、final answer本文 |
| `resolved_lexical` | 静的に抽出できるcurl body、MCP arguments、final answer本文 |
| `resolved_semantic` | resolved payloadへ任意のlocal embedding backendを追加。既定CLIでは未設定 |
| `lineage_assisted` | source-ingestion v3のproduction runtime graphによる到達判定 |

semantic profileはrunner APIへbackendを渡せる設計ですが、CLIとHookでは有効にしていません。semantic-onlyの自動blockも行いません。

## Dataset v1

`tests/fixtures/sink_benchmark/v1`には12件あります。

- development 6件、validation 6件
- 各splitでBash、MCP、final answerの正例・負例を1件ずつ含む
- credential、structured secret、private prose、decision materialを含む
- exact copy、paraphrase、file referenceを含む
- source、payload、値はすべて合成

case metadataとraw Hook lifecycle fixtureは分離しています。raw lifecycleは既存のsource-ingestion v3 loaderで検証し、caseの正解label、sink、action、observe-only指定が一致しなければ読み込みを拒否します。

## 初期baseline

全12ケース、local semantic backendなしの結果です。

| Profile | 評価可能 | Precision | Recall | F1 |
| --- | ---: | ---: | ---: | ---: |
| direct lexical | 12 / 12 | 1.00 | 0.50 | 0.667 |
| resolved lexical | 11 / 12 | 1.00 | 0.60 | 0.750 |
| resolved semantic | 0 / 12 | - | - | - |
| current runtime lineage | 12 / 12 | 1.00 | 0.50 | 0.667 |

ここから分かるのは次の3点です。

1. exactなinline credential / MCP argumentは現行方式で検出できます。
2. paraphraseはlexicalと現行lineageのどちらでもまだ検出できません。
3. `curl --data-binary @file`はstatic body extractorがfileを読まないため、resolved profileでも`unsupported`です。

semanticが0件なのは「全件不一致」ではなく、backend未設定なので`unavailable`です。file referenceも推測でnegativeにせず、coverageから外して理由を残します。

## Privacyと再現性

reportへ含めるのはcase ID、分類、判定、score、集約値だけです。source本文、protected value、raw command、raw MCP arguments、final answer本文は出力しません。評価中のsource materializationは一時directory内だけで行い、target tool、shell、networkを実行しません。

lineage profileは既存のsource-ingestion評価entrypointを使い、同じraw Hook eventsに対するfull rebuildとincremental updateの一致を確認します。

## 次の実装

1. file-backed HTTP bodyをboundedに解決するresolverを評価側で追加する
2. development splitだけでlocal semantic backend候補を比較する
3. validation splitを最後に開き、precision、recall、action、latencyを確認する
4. [#37](https://github.com/mani1261790/ToolUseProxy/issues/37)でsession / compaction / subagent境界を追加する
5. [#38](https://github.com/mani1261790/ToolUseProxy/issues/38)でGit outgoing object resolverを別surfaceとして追加する

resolved / semanticだけで十分なcaseと、lineageが追加価値を持つcaseを分離してから、production runtimeへ接続するか判断します。
