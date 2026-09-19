# 予定APIの記録をF01へ取り込む

```sh
python -m research.flow_forecast.task_catalog --agenda-captures inputs.json --output NEW_COLLECTION
```

inputs.jsonは完了済みagenda_collectionディレクトリの配列。取込はモデルやtrialを実行しない。
intent/execution/implementation/report、予約、個別step、guard receipt、所有resourceを照合し、
API状態・戻り値・receiver body hash/サイズを固定された期待値と比較する。API/transportの
ソースhashも照合し、保存されたreceiver_addressとJSON入力から実行scriptを再構成する。
途中失敗や余分な予約/step/guard、独立して改変された記録、宛先がない旧形式は拒否する。
これはローカル成果物の整合性であり、第三者の実行証明・独立保管を保証するものではない。

F01では状態更新と照会をtool_output、送信をhttp能力として表す。個々のMCP tool名の
未知ツール評価ではない。状態更新・選択の因果関係はselection/unknown、送信のみ実受信の
hashに基づくreceiver証拠とする。マーカーの到着や期待出力との一致だけで全経路を既知に
しない。deny後に実行されなかった処理・将来のI/Oは作らない。予測入力へ判定や受信証拠を
入れず、共通prefixの各境界でobserve/enforceを対応させる。

同じAgenda課題の公有/保護variant・再実行を1つの関連designへ結び付ける。独立性・
過去未使用は未確認。モデル生成なしの資料に生成モデルを補わない。

## 実測の取込と比較

PR #236の統合main 9a6b133を基に、source 7663b8cで新しい有限バッチを2本実行した。
各最大20試行/180秒/1GiB、各12試行、合計24試行、モデル0。公有15.4442秒/105162bytes、
保護12.2705秒/109677bytes（report前）。旧24試行を消さず、guard接続後の累積は48試行。
公有は両モードで到着。保護はobserveで到着、enforceでsendが拒否・未dispatch・未到着。

新しい24試行をread_captureで検証し、1関連群・2roots・6prefix・12枝のcollectionへ封印。
すべてtrainで、正解経路labelはunknown。既存compareのprepare/evaluate（partition=train）
まで実行し、inconclusive_do_not_adoptを確認した。比較は開発診断で、未使用holdoutではない。
生成モデル証跡0、採用独立課題追加0。F02条件のhashは変更していない。

結果とhashはresults/agenda-import-20260919.json。次は閉じたAPIの状態更新・フィールド選択の
依存関係を検証する契約を接続し、未知を安易に既知へ変えずに真値の被覆を改善する。
#204の独立holdoutと実モデル版の証明は引き続き未達。
