# 予定APIの可視I/O境界の修正

初期のagenda_importは、agenda.addの結果を内部のagenda-recordとして表し、保護元をその
操作の入力へ含めていた。実際の返答は{id, created}だけで、内部レコードのprivate値は
この時点では返らない。検証observerのsnapshotと予測時に見える返答を混同していた。

今回、addの出力をagenda-ackへ変更し、その入力を公開のagenda-inputだけに限定した。
内部snapshotは監査資料に保持し、予測入力のオブジェクトにはしない。照会後は、実際に
戻り値のprivateへ人工保護値が含まれた場合に限って保護元を観測入力へ反映する。
公開照会には含めない。どちらの照会もselectionの真値はunknownを維持するので、返答の
文字列一致だけで一般的な因果関係・非干渉性が証明されたとは扱わない。

同じ環境を指定した回帰試験では、公有/保護variantの予測入力は照会前の境界0/1で完全に同じ。
実captureはimage IDが異なるため、環境ID以外の可視入力が同じことを確認した。環境IDを
成果物から削除したり、同一環境と偽ってはいない。
新しいsource_versionはclosed-agenda-io-v2。内部状態を可視扱いした旧collection-v1は
予測器の有効性の根拠に使わない。保存済みの実行記録と旧封印資料は変更せず、同じcapture
からcollection-v2を別に封印した。再実行を新しい独立課題として数えない。

collection-v2も1関連群/2roots/6prefix/12枝、全train、経路真値unknown。既存compareの
prepare/evaluate（train）まで通し、inconclusive_do_not_adoptを確認した。新モデル呼出0・
新trial0・採用独立追加0。結果はresults/agenda-visible-prefix-20260919.json。

この修正は予測入力と検証用状態の境界を正すもので、API内部のフィールド依存関係の検証は
別途必要。#204の凍結条件・独立holdout・実生成モデル版の未達は変わらない。
