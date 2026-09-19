# 人工課題を F01 と比較処理へ接続する

```sh
python -m research.flow_forecast.task_catalog --task-worlds inputs.json --output NEW_COLLECTION
```

inputs.json は task_world_collection が完了したディレクトリの配列。新しい試行やモデル呼出は行わない。

## 検証と変換

実行前 intent に保存された課題定義を閉じた v1 定義と照合し、implementation / execution の hash、各条件の対照試行、試行予約、Hook receipt、操作ごとの bytes 証跡、受信記録、正常完了条件、有限バッチの時間・容量・試行数を検証する。保存済みの個別操作ファイルとレポートの不一致も拒否する。これはローカル整合性の確認であり、第三者の実行証明ではない。

F01 に compute 操作と inventory_allocation / calendar_intersection / ledger_reconciliation の課題種別を追加する。既存資料の意味・凍結済み F02 条件は変更しない。実行していない遮断後の操作・I/O は記録しない。

- load と public の save は固定された実測 bytes のコピー。
- compute は semantic / unknown。正解と一致しても依存関係の証明にはしない。
- private の save は結果と保護元からの selection / unknown。マーカー受信だけで経路全体を既知にしない。
- send は独立受信側の hash と長さに基づく receiver 証跡。
- 固定されたこの人工シナリオ内の継続確率は1。自然なエージェントの行動確率ではない。

catalog の由来文書は、実行前 intent と一致した固定課題定義から作る。同じ課題の public / include_private / 再実行は同じ design に結び付ける。異なる名前や root ID を独立性の証明には使わない。モデル実行を伴わない資料なので generator evidence は欠損として集計する。

## 実測資料の再評価

実装 62d2cd55fa9516fb5ea05cc5e0c7fc5db3da83b3 で既存3バッチから collection-v2 を再構成し、封印済み資料との一致を確認した。結果は results/task-world-import-20260919.json。3群6枝、全群train。observe/4 の正解はすべて unknown、モデル実行証跡0件。

既存 compare の prepare / evaluate（partition=train）まで実行し、inconclusive_do_not_adopt を確認した。学習用の開発診断であり、未使用holdoutの成績ではない。追加モデル呼出0・追加trial0、独立課題受入0。F02の正常・正例数、未使用課題での有効性、生成モデル一般化は未達。

収集時の古い report の f01_import 欄はその実装時点の未接続状態を表す。元資料を書き換えず、今回の取込は別の封印済み collection として保存する。意味的変換の真値検証と、実生成エージェントの課題実行への接続を引き続き実装する。
