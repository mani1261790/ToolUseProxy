# Sink-first比較評価

## 目的

外部sinkの入力を直接見るだけで検知できる範囲と、payload解決、semantic comparison、lineageを加えたときの改善量を、同じ合成corpusで比較します。情報流graphの存在自体を成功条件にはしません。

このrunnerは評価専用です。Hookのproduction policy、block条件、network設定を変更せず、target toolも実行しません。

## 実行方法

Python 3.11または3.12の開発環境で実行します。

```bash
python -m hook_monitor.evaluation.sink_benchmark_cli \
  --dataset tests/fixtures/sink_benchmark/v1_1 \
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
| `resolved_lexical` | 静的curl body、評価専用のbounded `--data-binary @file` snapshot、MCP arguments、final answer本文 |
| `resolved_semantic` | resolved payloadへ任意のlocal embedding backendを追加。既定CLIでは未設定 |
| `lineage_assisted` | source-ingestion v3のproduction runtime graphによる到達判定 |

semantic profileはrunner APIへbackendを渡せる設計ですが、CLIとHookでは有効にしていません。semantic-onlyの自動blockも行いません。

## Dataset

`tests/fixtures/sink_benchmark/v1`には12件あります。

- development 6件、validation 6件
- 各splitでBash、MCP、final answerの正例・負例を1件ずつ含む
- credential、structured secret、private prose、decision materialを含む
- exact copy、paraphrase、file referenceを含む
- source、payload、値はすべて合成

case metadataとraw Hook lifecycle fixtureは分離しています。raw lifecycleは既存のsource-ingestion v3 loaderで検証し、caseの正解label、sink、action、observe-only指定が一致しなければ読み込みを拒否します。

v1.1も12件で、各splitのBash正例・負例をfile-backed payloadへ置き換えています。public fileは`workspace_files`で明示的にmaterializeし、protected sourceを上書きするpath、workspace外path、重複path、上限超過をloaderが拒否します。

v1.1 dataset digestは`62747858a46e59be2c67ec8a02387448f6192d85e361c58e5c9eec8c427f8fe0`です。

## 指標

各profileは次の2種類を分けて報告します。

- `evaluated_only`: payloadを解決できたcase内での比較器精度
- `end_to_end`: unsupported / unavailableをfail-openのallowとして含めた製品全体の精度

これにより、payload coverageが増えた結果と、比較器自体のprecision / recallを混同しません。`payload_resolution`にはresolvable case数、解決数、resolution recall、値なしのunsupported reason件数を保存します。

## v1.1結果

全12ケース、local semantic backendなしのend-to-end結果です。

| Profile | 評価可能 | Precision | Recall | F1 |
| --- | ---: | ---: | ---: | ---: |
| direct lexical | 12 / 12 | 1.00 | 0.333 | 0.500 |
| resolved lexical | 12 / 12 | 1.00 | 0.667 | 0.800 |
| resolved semantic | 0 / 12 | - | - | - |
| current runtime lineage | 12 / 12 | 1.00 | 0.333 | 0.500 |

payload resolutionは4 / 4、unsupportedは0、raw fixture exposureは0です。resolved profileはdevelopment / validationのfile-backed正例2件をdirect profileから回収し、file-backed負例2件をallowのまま維持しました。

ここから分かるのは次の3点です。

1. `--data-binary @relative-file`の現在snapshotを読むと、inline command比較では見えない正例を回収できます。
2. 現行runtime lineageはfile本文を解決しないため、このcorpusではdirect profileを改善しません。
3. paraphraseはresolved lexicalと現行lineageのどちらでも検出できません。

semanticが0件なのは「全件不一致」ではなく、backend未設定なので`unavailable`です。

## File resolverとpayload evidenceの境界

resolver v2はstaticな`--data-binary @relative-file`だけを対象にし、workspace内のregular UTF-8 fileをfile reference 8件、1値32 KiB、32値、合計128 KiB、200 ms以内で読みます。POSIXではworkspaceからcomponentごとにdirectory FDを開き、`O_DIRECTORY` / `O_NOFOLLOW`で親path差し替えによるworkspace escapeを防ぎます。workspace外、`..`、symlink、`@-`、dynamic operand、非regular file、非UTF-8、NUL、上限超過は値なしreason付きでunsupportedにします。component-safe openを利用できないplatformでも推測fallbackせずunsupportedにします。shell、subprocess、curl、networkは実行しません。

取得するのは`pre_execution_file_snapshot`です。解決値は比較中だけ保持し、payload evidenceへはworkspace、sink、segment、resolution / comparison status、snapshot semantics、件数、byte数、source chunk ID、exact / exact substring match method、処理時間、値なしreasonだけを返します。payload本文とpayload由来hashは返しません。comparisonは512 source chunk、1件32 KiB、合計512 KiBを上限にし、token equivalent、shingle、semanticはこのcontractへ含めません。

component-wise openはresolver内部のpath raceを防ぎますが、Hook確認後にfileが変わるTOCTOUは残るため、curlが同じbytesを送った証明ではありません。production Hookへは未接続で、既存static extractorは引き続きfile-backed operandを`coarse_fallback`として扱います。詳細は[Sink payload evidenceの設計](../設計/SinkPayloadEvidence.md)を参照してください。

## Privacyと再現性

reportへ含めるのはcase ID、分類、判定、score、集約値だけです。source本文、protected value、workspace file、raw command、raw MCP arguments、final answer本文は出力しません。評価中のmaterializationは一時directory内だけで行い、target tool、shell、networkを実行しません。

lineage profileは既存のsource-ingestion評価entrypointを使い、同じraw Hook eventsに対するfull rebuildとincremental updateの一致を確認します。

## 次の実装

1. [#44](https://github.com/mani1261790/ToolUseProxy/issues/44)でpayload evidence契約とcomponent-safe readerを固定する
2. [#45](https://github.com/mani1261790/ToolUseProxy/issues/45)でproduction shadow metricsを測り、exact-only opt-in enforcementを判断する
3. [#46](https://github.com/mani1261790/ToolUseProxy/issues/46)でdevelopment splitのlocal semantic backend候補とhard negativeをobserve-only比較する
4. [#38](https://github.com/mani1261790/ToolUseProxy/issues/38)でGit outgoing object resolverを別surfaceとして追加する
5. [#37](https://github.com/mani1261790/ToolUseProxy/issues/37)でsession / compaction / subagent境界を追加する

resolved / semanticだけで十分なcaseと、lineageが追加価値を持つcaseを分離してから、production runtimeへ接続するか判断します。
