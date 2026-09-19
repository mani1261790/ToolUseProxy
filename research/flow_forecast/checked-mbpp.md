# 閉じたMBPP実行の値依存契約

`task_catalog --checked-mbpp-captures pairs.json --mbpp-source source.jsonl --output new-directory`で、capture/interventionsの組を取り込む。通常のMBPP importは引き続きunknownを維持する。

固定レコードと参照関数の入力能力検査、固定wrapperの実装、実測state/返答、有限介入とのbindingを組み合わせる。成功したplain JSON経路では参照関数は公開引数だけを読み、wrapperがprivateを別フィールドに保存する。compute ackは公開task IDとcomputedだけ、公有照会はresultだけ、全体照会はprivateもコピーする。この限定した値依存をjson_projectionとして評価へ渡す。

hashだけで意味を証明せず、有限例だけで一般化しない。field単位の因果、タイミング、例外、不正controller、別の参照関数・wrapperは対象外。image IDが異なるという介入bindingの記録をそのまま保持する。可視prefixを変えず、辺の過不足を拒否し、未dispatchの未来は検閲されたunknownとして残す。

source3bd1e69で既存6captureを再検証し、新しいcollection-v1へ封印した。3design/1関連群/6roots/18prefix/36枝、全train。horizon4では公有18枝がno、private observe9枝がyes、private enforce9枝がunknown。モデル呼出・新試行・採用独立群はいずれも0。

collectionに結び付けて計画を作成し、train診断を実行した結果はinconclusive_do_not_adopt。旧collection/plan/観測は変更していない。関連946テスト成功、通常importとのprefix一致・private辺欠落拒否・改変・検閲維持を確認した。結果は [results/checked-mbpp-20260919.json](results/checked-mbpp-20260919.json)。

#204の独立群数・実生成モデル証跡・未使用holdoutの条件は未達。次は生成計画の実receiptとMBPP試行を結び付ける。
