# repository外holdout評価

Similarity v2.1のdevelopment / validationはrepository内のsynthetic corpusです。規則をfreezeした後のblind評価には、本文をGitへ置かないrepository外holdoutを使います。

このrunnerはrepository checkout専用のlocal evaluation toolです。release wheel / Plugin ZIPには`hook_monitor.evaluation`を同梱しないため、ToolUseProxy checkoutのdevelopment環境から実行します。networkやremote serviceを使用せず、private入力を完全reportへ変換する機能も持ちません。stdout、`--output-json`、errorにはaggregateだけを出します。

## 安全境界

- holdout directoryはToolUseProxy repositoryの外に置く
- symlinkの`manifest.json` / `cases.jsonl`は使用しない
- live credentialを使わず、失効済み・合成済み・匿名化済みの値だけを使う
- `public_categories`は公開してよい集約labelだけにする
- case ID、本文、本文SHA-256、input path、dataset digest、mismatch IDはpublic reportへ出さない
- schema errorはrecord番号付きの固定codeとして扱い、入力値をechoしない

repository配下またはsymlink経由でrepository配下になるholdoutは`holdout_must_be_outside_repository`で拒否されます。

## directory形式

```text
/absolute/path/outside/ToolUseProxy/private-holdout/
├── manifest.json
└── cases.jsonl
```

`manifest.json`は次のexact schemaです。未知fieldは拒否します。

```json
{
  "schema_version": 1,
  "contract": "tooluseproxy-similarity-external-holdout",
  "contract_version": "1.0.0",
  "public_categories": [
    "public_compound_negative",
    "selected_alpha_positive"
  ],
  "expected_counts": {
    "pairs": 4,
    "scenarios": 4
  },
  "attestation": {
    "contains_live_credentials": false,
    "categories_are_public": true
  }
}
```

公開categoryは2〜16個です。各categoryに最低2 pairと2 scenarioが必要で、全体としてpositive / negative、reach / no-reach、allow / blockの両側を含めます。pair / scenarioはそれぞれ最大1,000件、入力fileは最大16 MiB、各本文はUTF-8で最大64 KiB、scenarioのartifactは最大8件です。同一recordの複製は拒否します。latency benchmarkはpairを1 operation、scenarioをfull / incrementalの2 operationsとして、repeat込み最大10,000 operationsに制限します。

## case形式

`cases.jsonl`は1行1 JSON objectです。blank lineと未知fieldは拒否します。

pair:

```json
{"schema_version":1,"kind":"pair","public_category":"public_compound_negative","source_binding_signal":"registered_source","left_text":"PRIVATE LEFT TEXT","right_text":"PRIVATE RIGHT TEXT","should_link":false}
```

scenario:

```json
{"schema_version":1,"kind":"scenario","public_category":"selected_alpha_positive","source_binding_signal":"selected_security_field","source_text":"PRIVATE SOURCE TEXT","artifact_texts":["PRIVATE OUTBOUND TEXT"],"sink_type":"external_http_request","should_reach_sink":true,"expected_action":"block"}
```

`source_binding_signal`は`registered_source`、`selected_field`、`selected_security_field`のいずれかです。`not_applicable`はsource-binding holdoutでは使用できません。pairはproductionのsource-binding comparator、scenarioはfull graphとSQLite incremental graph、lineage、finding、policyを実行します。

## 実行

```bash
python -m hook_monitor.evaluation.external_holdout_cli \
  --dataset /absolute/path/outside/ToolUseProxy/private-holdout \
  --benchmark-repeats 5 \
  --format text \
  --output-json ./external-holdout-public-report.json \
  --require-go
```

`--require-go`は次を全て要求します。

- overall pair precision / recallが1.0
- categoryごとのpair accuracyが1.0
- overall E2E reachability F1 / action accuracyが1.0
- categoryごとのreach / action accuracyが1.0
- false block / missed blockが0
- full / incremental parity mismatchが0
- aggregate report privacy auditがPASS

latencyはhardware依存なのでp50 / p95 / maxを集約表示しますが、固定GO thresholdには使いません。

## public report

公開可能なJSONは次の情報だけを持ちます。

- contract / runner version
- pair / scenario / public category件数
- overallとpublic category別の混同行列・accuracy
- similarity method件数
- parity件数とmismatch件数
- aggregate latency
- privacy / quality check

case単位の診断surfaceは意図的に提供しません。NO-GO時は公開category単位の集約まで戻り、private環境内でcorpus管理者が原因を調べます。private入力や個別hashをIssue、PR、CI artifactへ添付してはいけません。
