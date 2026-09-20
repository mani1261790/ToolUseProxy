# Hook外の予測記録（#137、実装中）

通常のPluginからは起動しない、人工データ用の単発workerです。予測専用DBへ
結果を記録し、既存のpolicy decisionやHook設定は変更しません。
F04の有効性は未確認で、実際のToolCallにモデルを適用する機能は無効です。

## 人工データで使う

repo rootから `python3 -m research.flow_forecast.recording.cli` を実行します。
F01で作成したsealed datasetとF03のJSONモデルを使います。
以下のPATHは各自の人工成果物に置き換えてください。

```sh
python3 -m research.flow_forecast.recording.cli init --journal PATH/forecast.db
python3 -m research.flow_forecast.recording.cli enable --journal PATH/forecast.db --synthetic-dataset PATH/dataset
python3 -m research.flow_forecast.recording.cli candidates --journal PATH/forecast.db --synthetic-dataset PATH/dataset
python3 -m research.flow_forecast.recording.cli enqueue --journal PATH/forecast.db --synthetic-dataset PATH/dataset --model PATH/model.json --candidate PREFIX_ID
python3 -m research.flow_forecast.recording.cli run --journal PATH/forecast.db --synthetic-dataset PATH/dataset --model PATH/model.json
python3 -m research.flow_forecast.recording.cli history --journal PATH/forecast.db --synthetic-dataset PATH/dataset --format text
python3 -m research.flow_forecast.recording.cli disable --journal PATH/forecast.db --synthetic-dataset PATH/dataset
```

- initは新規ファイルだけを作り、予測はまだ無効です。enable/disableは人工実験用の
  journalだけを変更します。実projectの保護解除・管理者登録・再有効化ではありません。
- 予約期限は30秒。runは1件だけ処理し終了します。常駐・自動再試行はありません。
- 入力・モデルを処理前後で再読込し、版が変われば結果を破棄します。
  元のデータが読めない場合も、予約済みの内容を最新の入力として代用しません。
- 無効化すると待機中/実行中の結果を無効にし、既存履歴を残します。
  再有効化後も過去の結果は履歴であり、現在の操作への許可には使いません。
- 強制終了後は `recover` に同じjournal/datasetを指定すると、lease期限が切れた
  実行中の記録だけを中断扱いにします。期限内の別workerは取り消しません。
- journalは最大1,000件。自動削除せず満杯を返します。必要なら新しい専用DBで再開します。
- JSON出力はローカル用です。Issueや外部送信用の集計へそのまま流さないでください。

## 実イベントDBの入力版確認

`inspect-input --events-db PATH/events.db --workspace ID --session ID` は、登録済みprojectの
管理者lease内で読取専用snapshotを取得します。管理者停止中は入力を読みません。
管理者状態が未導入ならlegacy扱いであり、人間による承認を証明したことにはなりません。
モデル用Prefixへの変換は行わず、`out_of_domain` と版のhashだけを返します。
このコマンドは予測予約・推論・イベントDBの変更を行いません。

## 残る受入

CLI/人工DBでの検証と、Mac/Codexの同じ実行での追加負荷・既存保護の受入は別です。
管理者のOS権限分離、実行中Unsetupとの実機競合、F04/#204の独立評価、
実入力の構造変換とモデル適用可否が未確認です。#137はまだcloseしません。
