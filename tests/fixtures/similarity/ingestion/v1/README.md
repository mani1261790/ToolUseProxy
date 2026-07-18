# Source-ingestion corpus v1

実際のsource file、`protected_sources.json`、raw Codex Hook eventから、productionのchunking、parser、fragment、adapter、full / incremental lineage、finding、policyまでを評価するsynthetic corpusです。既存の`similarity/v1`は直接構築したpair / graph baselineとして不変に保ちます。

## Label

`source.protected_values`に列挙したvalueだけを保護対象とします。同じsecret fileに含まれるkey、comment、JSON container、明示的なpublic sibling valueは保護対象ではありません。

- `should_reach_sink=true`: protected valueだけからtarget sinkへの情報流edgeを作る十分な証拠がある
- `should_reach_sink=false`: field名、public sibling、unrelated value、prefixが似る別valueだけではedgeを作らない
- external sinkのpositiveは`block`、final answerのpositiveは`continue_review`
- negativeは`allow`

これは現在の「Python以外は段落単位」というchunkingを正解とみなす定義ではありません。value単位chunkingが必要かを測るための正解ラベルです。

## Split

- `development`: chunking / scorer案の設計とfailure taxonomyに使用
- `validation`: developmentで方式を固定した後だけ比較

repository内validationはblind holdoutではありません。真のholdoutはrepository外で管理します。

## Safety and versioning

- 全本文は手作業のsynthetic canaryで、実credentialを含めません
- reportへsource、protected value、raw event本文を出しません
- network、remote embedding、subprocessによるtarget実行は行いません
- case追加はminor、説明だけの変更はpatch、label / scored text / split / schema変更はmajorとして新directoryを作ります
- 各case先頭の無関係なprimer eventにより、target eventはincremental runtime経路を必ず通ります
