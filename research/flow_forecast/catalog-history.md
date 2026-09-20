# collectionを跨ぐ既知課題の照合

現在のF01 splitは実行rootから区分を決めるため、別collectionの関連課題が異なる区分を持ち得る。区分名だけで未使用データと認定しない。旧collectionやsplitを書き換えず、既知の由来を先に照合する。

`catalog_history --candidate NEW_COLLECTION --prior USED_COLLECTION --output NEW_REPORT`はsealとtask-catalogだけを読み、origin hash・処理構造・親子関係から、collectionを跨いだ関連成分を作る。課題IDは内部でnamespaceを分け、名前の一致だけでは関連性と扱わない。既存の保守的な同形処理の判定を使い、違う名前・文言でも同じ処理なら結合する。宣言catalogの全課題を対象にするので、まだ実試行に現れていない設計も保守的に対象になる。

`compare_holdout prepare/evaluate`の`--prior-collection`へ過去のcollectionを渡すと、既知の関連由来を、bundle・targetを読む前に拒否する。一致がなければ監査結果を計画hashへ結び付け、evaluateでも同じ履歴を再照合する。履歴を省略したり変更したりすると計画が一致しない。既存の履歴未指定経路を未使用性の証明へ昇格しない。

この機能は指定された履歴だけを照合する。履歴の完全性、独立性、未使用性は確認済みとしない。ローカルhashは外部保管証明ではない。収集前の全体catalogと固定割当ての機能は別途必要。

## 実結果

source782bfdaでgenerated-mbpp-collection-v1と既存checked-mbpp-collection-v1を照合し、宣言3設計すべてをknown_related_originsと判定した。実holdout prepareもholdout_known_related_originsで拒否された。metadata以外の読込を先に行わないことは、dataset/targetの存在しないfixtureとbundle readerの拒否回帰で確認した。

結果は [results/catalog-history-20260919.json](results/catalog-history-20260919.json)。関連964テスト/Ruff成功。新model/trial/採用独立群0。#204継続。次は収集前の由来・関連群・用途を固定し、各バッチをその割当てへ結び付ける。
