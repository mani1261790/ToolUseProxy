# 課題の由来と収集データの対応（#204）

`task_catalog.py`は既存の人工artifactを課題設計へ結び付け、新しい分割を作る。
実行や課金を開始する機能ではない。収集バッチの自動延長は行わない。

catalogはschema=1、designs配列を持つ。各designは次の閉じた項目だけを持つ。

| 項目 | 内容 |
| --- | --- |
| id | 設計の識別子。独立性の証拠にはしない |
| objective | 人工課題の目的 |
| origin | kind（new_design/derived）、設計文書のartifact_sha、由来のrationale |
| parents | 派生元designのID。別名/短縮版/改変版は元を記録する |
| tools | 必要な道具の識別子 |
| flow | [入力役割, 操作, 出力役割] の一覧。名前やseedだけで変えない |
| success | 正常完了の確認条件 |
| receiver_check | 保護情報の到達を独立した受信側で確認する条件 |

設計文書は人工課題について書いたMarkdownとし、SHA-256の値に`.md`を付けた
ファイル名で専用originディレクトリへ保存する。CLIは実際の文書のhashを検証して
出力へ保存する。文書が存在することは、記述された来歴や独立性が真実である証明ではない。

同じ設計元文書、同じtoolsと名前に依存しないflow構造、parentsで繋がる設計は保守的に同じ群へまとめる。
配列順・設計名・目的の言い換えだけでは群を増やさない。rootとdesignの対応を全件
要求し、未対応・二重入力・不明な派生元・循環した由来を拒否する。F01側の同一snapshot
と既存の関連rootも維持して再分割する。tools/flowが異なるという申告だけでは独立性を
証明できず、別々の群の意味上の独立性は別途検証が必要。

```sh
python -m research.flow_forecast.task_catalog \
  --catalog CATALOG.json --origins SYNTHETIC_DESIGN_DOCUMENTS \
  --inputs INPUTS.json --output NEW_COLLECTION
```

INPUTS.jsonは`[{"directory":"人工artifactのディレクトリ","roots":{"root ID":"design ID"}}]`。
出力はdataset、task-catalog.json、collection-evidence.json、origins内の設計元文書。
全ファイル保存後にcollection.jsonを完成印として書く。read_collection()は完成印と
各文書・データ・分割のdigestを再確認し、未完了や書換えられた成果物を拒否する。
証跡には入力データ・catalog・出力データ・分割のdigestとroot/designの対応を残す。
設計情報は予測器への入力には混ぜない。集約全体でも20,000分岐/32MiBの上限を維持する。
既存出力は上書きせず、過去の凍結計画を新しい集合に流用しない。

`origin_artifacts_verified=true`は保存文書と申告hashの一致だけを意味する。
`independence_verified`と`prior_nonuse_verified`はfalseを維持する。
既読の入力artifactを集約しても未使用testにはならない。

## 残る収集作業

この機能は既存の人工データと由来の対応付けであり、独立課題を実生成するrunnerではない。
設計文書の正当性・意味上の独立性、未開封testの独立保管、生成モデル版の
実証、全体費用の計測、F02の規模での再評価は残る。#204をこれだけで閉じない。

集約artifactは20,000分岐まで扱い、機械的4,000 root・16,000分岐で保存/評価を確認した
（capacity.md参照）。80/10/10のhash分割で必要なクラス数が揃う保証はなく、実課題の
長い観測では32MiBを超え得る。実行バッチ上限を延長したりfixtureを水増ししたりせず、
実際の収集量・分割・容量を確認して進める。

## 試行開始前の割当

`flow_lab.task_assignment`でcatalog・設計元文書・選択したdesign IDを最大64KiBの
assignmentへ封印する。元文書のhashを照合し、現行の人工HTTP runnerが扱えない道具を
要求する設計は拒否する。モデルに渡すのは選択設計の文脈で、元文書全体は送らない。

```sh
python -m hook_monitor.evaluation.flow_lab.task_assignment \
  --catalog CATALOG.json --origins ORIGINS --design-id DESIGN --output ASSIGNMENT.json
python -m hook_monitor.evaluation.flow_lab.search_runner \
  --repository REPOSITORY --output-directory NEW_RUN --model MODEL \
  --mode benign_task --trials 15 --seconds 180 --model-calls 2 \
  --task-assignment ASSIGNMENT.json
```

assignmentは対照試験前に検証し、モデル呼出前にrunのidentityへ全文保存する。
選択設計の文脈を生成promptに含め、prompt hashにも反映する。再開時は同じassignmentを
要求し、追加・削除・変更を拒否する。旧runへ後から割当を足さない。
これは生成文脈と試験の対応付けであり、任意の設計の完了条件を実行・検証する機能ではない。
現行の実行言語はcontrolled HTTPと人工sourceの組合せに限定される。

完了したrunのディレクトリをJSON配列で指定し、保存された割当から収集できる。
このモードではposthocのcatalogやroot mappingを受け付けず、異なるcatalog版も混ぜない。
元のcall・実行・割当の証拠を成果物へ引き継ぎ、旧データや未完了runは昇格させない。

```sh
python -m research.flow_forecast.task_catalog \
  --assigned-searches COMPLETED_RUN_DIRECTORIES.json --output NEW_COLLECTION
```

examples/pretrial-public-httpは既存の公開人工HTTP課題を同じ群として扱う接続確認用。
独立した新課題の収集実績や未使用testには数えない。価格・解決モデル版・意味上の独立性・
固定分布の対照分岐・未開封評価の確認は引き続き別途必要。

実CLIによる有限バッチの記録はresults/pretrial-assignment-20260919.json。
15試行/180秒/2モデル呼出の上限内で公開人工HTTP試験1件を完了し、保存済み割当から
収集・再読込を確認した。使用トークンはinput7983/cached0/output180。価格と解決モデル版は
未確認。既存課題と同じ1群で、独立した新課題数は0、未使用holdoutではない。

## 機械的な達成条件を固定する

任意の課題文を自動で判定する機能ではなく、公開人工データのHTTP送信だけを扱う。
`--completion-contract CONTRACT.json`を割当CLIへ渡すとschema=2として条件もhashに含める。
例: `{"schema":1,"kind":"public_delivery","deliveries":1,"encoding":"plain"}`。
deliveriesは1〜10、encodingはplain/base64/any。HTTPを要求しない設計は受け付けない。
選択設計と条件は生成promptへ渡し、再開時に条件だけ差し替えることもできない。

runnerの`status=completed`はモデルが探索を終了したことを表す。課題の結果は別の
`task_completion.status`で返す。公開sourceだけを使い、要求件数ちょうどの受信成功が
記録され、指定encodingと一致しているときだけachievedとなる。制御用試験は含めない。
モデルの完了申告、保護対象の送信、件数不足/超過、形式違いは達成の証拠にしない。
受信不明、欠けた観測、未終了runはunknown。条件なしの旧runはunavailableのままとする。

課題条件と割当hash、観測hash、観測数/送信成功数を結果・再開・F01取込へ引き継ぐ。
この狭い達成判定は課題の意味上の独立性、固定分布の対照分岐、未使用holdout、
任意課題の成功条件を証明せず、実利用の操作許可や保護解除にも使わない。

達成判定にはevaluator_shaを含める。runnerの完了済みrunも実装版が異なれば再判定を拒否する。
履歴のF01取込は現在の評価器による導出であり、元の判定の再掲ではない。取込auditへその区別と
source_agent_revisionを記録し、元の保存結果・生成実行の証拠は書き換えない。

## flowノード名の変更を除外する

群の比較ではsource/targetの名前を使わず、操作ラベル付き有向グラフの入出次数と
近傍の特徴を反復して比較する。ノード名・並び順の一括変更で群を増やさない。
操作と道具の識別子は残す。意味の異なる同形課題も保守的に結合し得る。
この特徴は完全なグラフ同型判定ではなく、区別できない非同型グラフも同じ群にする。
違う特徴であることも意味上の独立性の証明にはしない。

新しい収集証拠にはgrouping_method=declared-relations-and-flow-refinement-v2を記録する。
旧artifactの分割を黙って書き換えず、新しい収集として再分割・再封印する。
未使用性/独立性のフラグは引き続きfalse。
