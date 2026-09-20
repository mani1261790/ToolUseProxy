# 閉じた予定APIのJSON値依存契約

```sh
python -m research.flow_forecast.task_catalog --checked-agenda-captures pairs.json --output NEW_COLLECTION
```

pairs.jsonはcapture/interventionsのディレクトリ対の配列。新たなtrialやモデル呼出はしない。
通常のagenda-capturesは今後もselection/unknownを維持する。checked経路だけで以下を検証し、
この固定プログラムのJSON値の投影をchecked_json_projectionとして扱う。

## 契約の範囲と根拠

1. strict capture readerが、固定された有効なJSON call、guard、API前後状態、応答、送信body、
   receiver、source、全予約を照合する。可視I/O境界はclosed-agenda-io-v2に限定する。
2. APIとtransportの実装hashを、確認したコード形に固定する。hash自体を証明とはしない。
   このAPIのaddはtitle/timeを引数から保存し、privateを所有者Aのshared recordからコピーする。
   返答はid/createdだけ。publicはtitle/timeを列挙して返し、getは所有レコードをコピーする。
   transportはJSONでstateを復元するため、任意のPython objectや独自deepcopyは入力にならない。
3. add前にnewがなく、Aにsharedだけが存在すること、新レコードの各フィールド、既存AとBの
   不変、id/createdだけの返答を検証する。照会ではstate不変と、指定フィールドの完全一致を確認する。
4. 固定ソースで実行した5case/15呼出の介入記録を照合し、実captureの照会結果へ結び付ける。
   有限介入は追加の実測根拠であり、これだけから一般的な非干渉性を推定しない。
5. 公開入力→ack、公開入力→照会結果、実際に返った場合だけ保護元→照会結果という辺が
   過不足なく存在することを確認する。欠損した保護元の辺を正常扱いに変換しない。
   送信は既存の独立receiver hashによる辺を維持する。予測prefix自体は変更しない。

対象はこの実装と検証済みの呼出・plain JSON状態の値依存性だけ。信頼できるPython標準
ライブラリとDocker/controllerを前提とする。任意API、異なる入力domain、タイミング・
例外による伝播、侵害されたcontroller、一般の意味的依存には適用しない。API/transportが
変われば拒否し、契約の再確認が必要。実測image IDsの相違は証拠に残し、layer同一性を
検証したとはしない。

## 実測資料の再評価

source f3b1a0fで既存captureと介入資料を再検証し、checked collectionを別に封印した。
1関連群/2roots/6prefix/12枝、全train。horizon4では公有のobserve/enforceがno、保護の
observeがyes、保護のenforceは停止後未観測なのでunknown。停止を正常例へ転用しない。

compare prepare/evaluate（train）まで実行し、inconclusive_do_not_adopt。新trial0/model0、
採用独立群追加0。結果はresults/checked-agenda-20260919.json。元のunknown collectionや
実行資料を書き換えていない。独立holdout、生成モデル版、未使用の道具/課題/モデルでの
有効性は未達で、#204を閉じない。
