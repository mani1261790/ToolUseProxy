# Source-ingestion corpus v2

実際のsource file、schema v2の`protected_sources.json`、raw Codex Hook eventから、productionのselector-aware chunking、parser、fragment、adapter、full / incremental lineage、finding、policyまでを評価するsynthetic corpusです。`similarity/ingestion/v1`はselector導入前の不変baselineとして残し、v2は同じcase ID、source本文、event、split、正解label、期待actionへsource selectorだけを追加します。

## v1との差

- dotenv sourceは、`source.selector.dotenv_keys`で秘密値を持つkeyだけを選択します
- JSON sourceは、`source.selector.json_pointers`で秘密値を持つstring leafだけをRFC 6901 pointerとして選択します
- 同じfile内のpublic sibling、key名、comment、JSON containerはcontent-derived taintの対象にしません
- labelと期待actionはv1から変更せず、selector導入による精度差を直接比較します

## Label

`source.protected_values`に列挙し、selectorで指定したvalueだけを保護対象とします。同じsecret fileに含まれるkey、comment、JSON container、明示的なpublic sibling valueは保護対象ではありません。

- `should_reach_sink=true`: selected protected valueだけからtarget sinkへの情報流edgeを作る十分な証拠がある
- `should_reach_sink=false`: field名、public sibling、unrelated value、prefixが似る別valueだけではedgeを作らない
- external sinkのpositiveは`block`、final answerのpositiveは`continue_review`
- negativeは`allow`

selectorはcontent由来のchunkを狭めますが、登録されたsource path自体を読んだというpath-based taintは保守的に残します。したがって、selectorがあるsourceでも保護対象fileへのReadなどを「公開fileの読取り」とは扱いません。

## Split

- `development`: selector / chunking / scorer案の設計とfailure taxonomyに使用
- `validation`: developmentで方式を固定した後だけ比較

repository内validationはblind holdoutではありません。真のholdoutはrepository外で管理します。

## Safety and versioning

- 全本文は手作業のsynthetic canaryで、実credentialを含めません
- reportへsource、protected value、raw event本文を出しません
- network、remote embedding、subprocessによるtarget実行は行いません
- case追加はminor、説明だけの変更はpatch、label / scored text / split / schema変更はmajorとして新directoryを作ります
- 各case先頭の無関係なprimer eventにより、target eventはincremental runtime経路を必ず通ります
