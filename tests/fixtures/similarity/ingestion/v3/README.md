# Source-ingestion corpus v3

schema v2のsource selectorを維持したまま、Bashのcurl送信operand抽出をproduction経路全体で評価するsynthetic corpusです。実source file、`protected_sources.json`、raw Codex Hook eventから、chunking、Bash parser、送信値抽出、adapter、full / incremental lineage、finding、policyまでをnetworkやtarget commandの実行なしで測ります。

## v2との不変性

- `similarity/ingestion/v2`のfixtureとdigestは変更しません
- v3先頭12ケースは、v2のcase ID、source本文、selector、raw event、split、到達label、期待actionをそのまま継承します
- v3ではdataset schemaを2、dataset versionを`3.0.0`へ上げ、全scenarioへ`expected_bash_submissions`だけを追加します
- 追加8ケースは各split 4件で、全20ケースをpositive 10件、negative 10件に保ちます

## `expected_bash_submissions`

非Bash scenarioは空配列です。Bash scenarioはtarget event内のcurl segmentごとに次を宣言します。

```json
{
  "segment_index": 0,
  "extraction": "static_values",
  "submitted_values": ["C.EXAMPLE0001"]
}
```

- `segment_index`はstrict Bash plan上の0始まりのindexです
- `static_values`は、shellを実行・展開せずに確定できるcurl body operandです
- `submitted_values`は送信順を保持し、重複も別のoperandとして数えます
- public siblingも実際に送られるstatic operandなら列挙しますが、protected lineageは与えません
- shell展開を伴う`$TOKEN`、backtick command substitution、file-backedな`@file` / `@-`など、値を静的に確定できない入力は`coarse_fallback`とし、`submitted_values`を空にします。single quoteやescapeでliteralになった`$`と、`--data-raw @literal` / `--form-string name=@literal`はstaticです
- fallbackはsinkを消すという意味ではありません。既存のcoarseなsegment-to-sink evidenceを残し、runtime値を推測しないという契約です
- staticとfallbackのどちらでもshell、subprocess、networkを実行しません

## 追加ケース

Developmentには`-dVALUE`、`--data VALUE`、`--data=PUBLIC`、`$TOKEN` fallbackを追加します。Validationには同一segment内の複数data option、2つのcurl segmentの分離、`--data-binary @file` fallback、backtick fallbackを追加します。

## Labelと期待metric

`should_reach_sink`はselected protected valueからtarget sinkへのsource-chunk evidenceがあるかを表します。external Bash sinkのpositiveは`block`、negativeは`allow`です。fallback caseでは未知のruntime値を秘密値と仮定せず、明示された静的・構造的evidenceだけを評価します。

実装完了時の全20ケースの期待値:

- source-chunk TP / FP / TN / FN: `10 / 0 / 10 / 0`
- reachability precision / recall / F1: `1.0 / 1.0 / 1.0`
- policy action accuracy: `1.0`
- false block / missed block: `0 / 0`
- exact protected-value chunk recall: `1.0`、source chunk: `20`
- adapter sink coverage: `20 / 20`
- full / incremental parity: `20 / 20`
- Bash extraction: 12 cases、13 segments
- static extraction: 10 segments、11 ordered values、precision / recall / F1 `1.0`
- coarse fallback: 3 segments、accuracy `1.0`

metricとscenario reportにはcase ID、segment/count、match結果だけを出し、source本文、raw command、submitted value、value hashは出しません。

## Safety and versioning

- 全値はneutralな手作業synthetic canaryで、実credentialを含みません
- sourceとeventの文字列にはlabelやcase IDを埋め込みません
- target commandは解析するだけで実行せず、networkとremote embeddingを使いません
- v1とv2は過去baselineとしてimmutableに保ち、v3のcase追加はminor、説明だけの変更はpatch、schema・label・scored text・split変更は次のmajor directoryで行います
