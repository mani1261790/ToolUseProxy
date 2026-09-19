# モデル生成前からのcohort binding

`generated_mbpp prepare --cohort-plan PLAN`は、参照課題の由来と封印済みcatalogの設計が一致することを検証し、モデル呼出し前のrequestへcohort bindingを保存する。生成計画schema2は同じbindingとrequest SHAを保持する。旧schema1は変更しない。

collectは生成時のbindingを継承する。別計画の指定、計画なしの旧生成応答への事後追加を拒否する。importは生成証跡と試行intentのbindingが同一であることを検証し、欠落・付け替えを拒否する。計画区分をモデルへのタスク内容へ加えず、controllerの実行証跡として保持する。

## 実測

source051f2e1で封印済み全train計画dfdfbe3d…を使い1回生成。gpt-5.5指定、input3724/cached0/output91、controller7261ms。固定モデル版・単価は未確認。1明示バッチ12試行、15.720205583秒、report前114633bytes、上限20/180秒/1GiB。既存介入を再利用した。

新collectionは1関連群/1root/3prefix/6枝、全train。生成receipt1件が通常/checked経路とモデル別集計まで届くことを検証。train比較はinconclusive_do_not_adopt、採用独立群0。結果は [results/generated-cohort-20260919.json](results/generated-cohort-20260919.json)。

関連975テスト/Ruff成功。計画をモデル呼出し前に保存する順序、collectの継承/差替え拒否、importでのbinding欠落拒否を含む。履歴の完全性・独立性・第三者による事前封印の証明ではない。既知履歴の照合はまだ生成前の同じ経路へ統合していないため次の残件。#204継続。
