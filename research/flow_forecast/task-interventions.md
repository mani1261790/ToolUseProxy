# 人工課題の有限介入試験

課題の入力だけを変えて、結果が期待どおりに変わることを検証する。正解を返すだけの定数プログラムを見落とさないための観測であり、全入力に対する情報流・非干渉の証明ではない。

```sh
python -m research.flow_forecast.task_world_interventions \
  --world inventory --repository CHECKOUT --output NEW_DIR --seconds 180
```

1回で指定した課題の baseline と2種類の介入、計3試行だけを実行する。上限20試行・指定時間（最大1800秒）・1GiBを保持し、自動で別課題へ延長しない。各試行は既存の network=none / 非特権 / read-only / 128MiB プロファイルの新規Dockerコンテナで実行し、起動前にinspectする。モデル呼出・外部サービス・実データ・本番Hookは使用しない。

介入はコード内で固定した入力と別に定義した正解のみを受け付ける。課題本体と同じアルゴリズムを実行する。intent、入力/コードのhash、試行予約を実行前に残す。現行実装は所有コンテナ名も作成前に保存し、異常時の後片付けの対象を追跡できる。失敗した試行も予約が残り、完了reportは作らない。進行中コマンドは有限timeoutを持ち、cleanupはバッチ期限後も必要な場合がある。

| 課題 | 介入1 | 介入2 |
| --- | --- | --- |
| inventory | 在庫Aを5から7へ | 最初の2注文の順を逆転 |
| calendar | 必要時間を30分から20分へ | 2人目の最初の空き時間を削除 |
| ledger | 返金を200から300セントへ | 取消済み売上を有効にする |

2026-09-19、source bf2507af4d7a977f5bd87832d7411fc21475c151 で各課題を最大180秒の明示的別バッチとして実行。全9試行で正解と一致し、各課題の2介入ともbaselineと出力が変化した。実測は results/task-interventions-20260919.json。実行時点ではコンテナ名の事前永続化は未追加で、後続修正のテストで保証した。

観測の用途は同じ課題の依存検証であり、独立課題数には加算しない。semantic truthの既知化、モデル一般化、未使用holdoutの評価は行っていない。次は実測のhashと実行前課題定義を結び付け、固定された計算コードが参照できる入力を検査する契約と組み合わせる。有限の差分観測だけで任意の計算に真値ラベルを与えない。

## 保存済み証跡の照合

`intervention_evidence.read_interventions` は課題定義・介入の入力/正解・実装・実行・試行予約のscript hash・個別結果・report・有限バッチ制約を再検証する。コンテナ名は旧資料では未記録として区別し、一部だけの欠落や重複した識別子は拒否する。

`bind_capture(capture_directory, intervention_directory)` は元のtask_world実測を既存readerで検証してから、同じ課題定義・Docker context・computeコマンドhash・baseline出力へ結び付ける。任意の課題名や成功フラグだけでは接続しない。3実測課題の接続結果とvalidator source hashは results/intervention-bindings-20260919.json。新規trial/モデル呼出なし。有限介入の範囲を超えてsemantic truthを既知にする処理はない。
