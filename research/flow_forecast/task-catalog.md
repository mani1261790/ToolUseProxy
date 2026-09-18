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

同じ設計元文書、同じtools/flow、parentsで繋がる設計は保守的に同じ群へまとめる。
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
設計情報は予測器への入力には混ぜない。集約全体でも2,000分岐/32MiBの上限を維持する。
既存出力は上書きせず、過去の凍結計画を新しい集合に流用しない。

`origin_artifacts_verified=true`は保存文書と申告hashの一致だけを意味する。
`independence_verified`と`prior_nonuse_verified`はfalseを維持する。
既読の入力artifactを集約しても未使用testにはならない。

## 残る収集作業

この機能は既存の人工データと由来の対応付けであり、独立課題を実生成するrunnerではない。
設計文書の正当性・意味上の独立性、試験前の割当固定、未開封testの独立保管、生成モデル版の
実証、全体費用の計測、F02の規模での再評価は残る。#204をこれだけで閉じない。

F02の最小520群に各4分岐があるだけでも2,080分岐となるため、現在の単一Dataset上限を
越える。80/10/10のhash分割に任せると必要な収集総数はさらに大きくなる。収集数を減らしたり
fixtureを水増ししたりせず、分割保存/集計を評価器に接続してから本規模の収集に進む。
