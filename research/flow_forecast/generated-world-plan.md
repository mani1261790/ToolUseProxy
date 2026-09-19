# 生成エージェントの人工課題計画と実行

`world_plan_provider` は用意済みの load / compute / save / send と出力範囲の計画をモデルへ求める。compute のアルゴリズムはcontrollerが提供する。モデルが業務計算コードを実装した、任意ツールを使った、対話的に実行中の計画を修正した、とは扱わない。

CodexProvider の既存の監査済みCLI版・host tool無効化・tool event拒否・入出力容量・timeout・停止処理を再利用する。通常のHTTP proposal形式は従来のまま。人工課題用は別のschema/parser/instructions/promptを持ち、モデルからコード・パス・任意ツール・送信先を受け取らない。

```sh
python -m research.flow_forecast.generated_world_plan prepare \
  --world inventory --model gpt-5.5 --output NEW_PREPARED
python -m research.flow_forecast.generated_world_plan collect \
  --prepared NEW_PREPARED --repository CHECKOUT --output NEW_CAPTURE
```

prepare は1回・最大60秒・返信16384bytesで終了する。課題定義、要求モデル、実装hash、prompt hash、予約を呼出前に保存し、構造化応答・実行receipt・全呼出費用を保存する。不完全な手順や拒否も1回の呼出として記録し、自動再試行しない。有効な計画だけを最後に封印する。

collect は封印と保存済み成果物を再検証し、課題/出力方針を試行前intentへ埋め込む。最大20試行・180秒・1GiBの既存隔離バッチ。実行中に追加モデル呼出はない。importerとgenerator_strataは課題・実行枝・元のreceiptを結び付け、同一call_idの再利用は拒否する。要求モデル名を実提供モデル版の証明にはしない。

## 実測

source 22fb119で在庫引当の1回の提案を取得し、同じsourceで実行した。

- 要求モデルgpt-5.5。load → compute → save → send、export=public。
- 入力3765/cached0/出力78 tokens、記録時間6250ms。単価・提供元費用は不明でnull。
- 11試行、14.05秒、report前110035bytes。observeは正常完了・保護受信なし。enforceは最初の操作で停止。
- 既存inventory介入と結び付け、checked collectionへ取込。train 1群・実生成receipt1件。要求モデル名の層別比較まで確認した。
- 総合inconclusive_do_not_adopt。独立課題受入0、calibration/testなし、実提供モデル版は未確認。

結果、hash、実行元と派生比較元の版は results/generated-world-plan-20260919.json。データは /private/tmp/tooluseproxy-204-generated-world-{prepare,capture,collection}-v1。比較もtrainの開発診断であり、未使用モデル/課題での一般化を示さない。#204は継続する。
