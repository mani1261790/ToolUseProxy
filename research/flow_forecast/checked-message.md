# MessageAPI集計の限定された値フロー契約

公開MessageAPIの固定実装を読み、ログインの定型応答、受信箱の件数/受信先数の集計、
本文一覧の返却を確認した。`get_message_stats`は受信箱の各entryを数え、受信先keyの集合を作る。
本文valueと保存済みmessage_countは集計に使わない。`view_messages_sent`は本文を受信先ごとにまとめる。

`checked_message`は固定sourceとadapter、capture readerで検証したJSON状態・成功経路に限定する。
保護範囲は本文中の人工マーカーであり、受信箱の形と受信先IDは人工課題の公開入力。
これらの形やIDも保護すべき一般環境へ、そのまま適用する契約ではない。
hashは確認対象を結び付ける識別情報であって、hashだけで非干渉を証明するものではない。

## 有限介入と既存captureへの結合

```sh
python -m research.flow_forecast.bfcl_message_interventions \
  --repository REPOSITORY --source PINNED_MESSAGE_API --output NEW_INTERVENTION_DIRECTORY
python -m research.flow_forecast.task_catalog \
  --checked-message-captures PAIRS_JSON --message-source PINNED_MESSAGE_API --output NEW_COLLECTION_DIRECTORY
```

PAIRS_JSONは `[{"capture":"CAPTURE_DIRECTORY","interventions":"INTERVENTION_DIRECTORY"}]`。
介入は以下の5ケースを新しいネットワークなしcontainerで実行する。
各ケースに状態設定・ログイン・集計・本文取得の4試行を予約し、計20試行で終了する。
既定180秒、許容最大1800秒、1GiBの上限を段階ごとに確認し、自動延長しない。

| 変更対象 | 期待する集計の変化 | 本文一覧 |
|---|---|---|
| 基準 | 3件・受信先2件 | 基準の本文 |
| 本文だけ | 変わらない | 該当本文だけ変わる |
| 受信先を既存の相手へ変更 | 件数3のまま・受信先1件 | 同じ受信先の一覧へまとまる |
| 受信箱へ1entry追加 | 件数4・受信先3件 | 新しい本文が追加される |
| 保存カウンターだけ999へ変更 | 変わらない | 変わらない |

readerは全予約・スクリプト・応答/状態・実装hashを再検証する。既存captureとの結合には
Docker context、介入基準ケースの状態と実queryの前後状態、取得結果の一致を要求する。
実測では両captureのquery各2件が結合できた。image IDは異なり、同一image確認済みとは扱わない。

## ラベルへ反映する範囲

実call、前後状態、出力、source/adapterの一致に加え、必要な転送edgeが揃っていることを検査する。
ログインackと本文一覧は限定JSON projection、公開集計は限定computationとして記録する。
元の可視prefixは変更しない。送達は既存のreceiver本文照合を維持し、
enforceで実行されなかった送信の将来結果はunknown/censoredのまま残す。

Python標準ライブラリとDocker controllerを信頼する限定試験であり、異なる入力、
例外・時間経路、一般的な意味解析、独立課題性、実機Hook受信を証明しない。

## 2026-09-20 JSTの実測

実装commit `6282a2615280fee06c677b6cdb01678beb5f1a03`。
`/private/tmp/tooluseproxy-204-message-interventions-v1` の20試行・15API呼出しは全期待値と一致した。
経過5.512秒、report前46,866bytes。記録された5containerが残っていないことも確認した。
この確認と既存captureの再読込では、新しい生成モデル呼出しや送達試行は行っていない。

`/private/tmp/tooluseproxy-204-checked-message-collection-v1` に1関連群・6prefix・12branchを再封印。
collection identityは `5c20e65e7d9281b3d04a364203cf96342fa8ebdc8fddec718e26bc4f1f38e8f1`。
horizon 4はno=6、yes=3、unknown=3。全てtrainで、開発使用済み・独立性未検証のまま。

比較CLIのprepareとtrain評価も実行し、結果は `inconclusive_do_not_adopt`。
これは学習用データによる接続確認であり、未使用testは0群。
比較report内のtest_*という従来の指標名も、このtrain実行では未使用testの件数を意味しない。
学習1群、調整用正常0群、未知課題・道具・生成モデル別の評価不足を理由に、採用しない。

関連80テスト、予測関連全881テスト、Ruff成功。
[機械可読記録](results/checked-message-20260920.json)に介入、結合、ラベル、train比較の範囲を記載した。
採用独立群は0。F02の520群、生成モデルとの実対応、未使用holdout、費用・有効性は未達。
