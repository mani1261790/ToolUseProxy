# 評価データの使用履歴（#204）

`holdout.py`は人工評価専用のSQLite台帳。新規台帳は排他的に作成し、既存の
実利用DBの初期化・移行には使わない。dataset・manifest・splitのdigestを封印し、
評価開始前にrun・plan・model・評価器のdigestを結び付けて最初の使用を予約する。
同時実行でも1件しか予約できず、予約後に落ちた場合も未使用へ戻さない。
結果digestは同じrunに一度だけ記録できる。調整後や汚染が判明した場合は退役する。

台帳にはリセット/再封印APIを設けない。ただし、同じ権限を持つプロセスによる
ファイル差替え・削除・別台帳作成や、この経路外で過去にデータを読んだことまで
防ぐ仕組みではない。`prior_external_use_verified`と
`independent_custody_verified`は常にfalse。hashや記録があるだけで独立性・未使用性を
合格にしてはいけない。生成元証跡と独立した保管・開封履歴を併せて確認する。

## 分割保存と評価経路

`partition_bundle.py`はtrain/calibration/testを個別のF01 artifactとして保存する。
トップのbundle.jsonは各artifactのdigestと分割の同一性を持ち、正解や集計は持たない。
`compare_holdout prepare`はtrain/calibrationだけを読み、testディレクトリが
アクセスできない場合も計画を凍結できる。`evaluate`も最初は同じ経路でモデルと
計画を照合し、台帳の予約をcommitしてからtestを開く。再結合時に関連群と
同じsnapshotが分割を跨いでいないこと、元のsplitと一致することを再検証する。
読み込み・評価・出力に失敗しても開封済みの記録を戻さない。

```sh
python -m research.flow_forecast.compare_holdout export --dataset ARTIFACT --bundle BUNDLE
python -m research.flow_forecast.compare_holdout create-ledger --ledger HOLDOUT.sqlite
python -m research.flow_forecast.compare_holdout seal --bundle BUNDLE --ledger HOLDOUT.sqlite
python -m research.flow_forecast.compare_holdout prepare --bundle BUNDLE --output PLAN.json
python -m research.flow_forecast.compare_holdout evaluate --bundle BUNDLE --ledger HOLDOUT.sqlite --plan PLAN.json --output REPORT.json
python -m research.flow_forecast.compare_holdout retire --bundle BUNDLE --ledger HOLDOUT.sqlite --reason tuning_after_open
```

出力は上書きしない。時間/メモリは既存のBudget、データ量はF01の制限に従う。
コードまたはPython実行環境が変われば計画の作り直しが必要。旧compare.pyは従来の
一体型artifact向けのままで、未使用性は証明しない。

exportは既にアクセス可能なDatasetを変換する操作であり、未使用データを作る操作
ではない。`prior_access=conversion_from_accessible_dataset`を記録し、受入条件の
unused_test_partition、independent_root_groupsを合格へ変更しない。
独立課題の収集、実生成モデルの証跡、独立した保管・過去の開封履歴は未完了。
この機能だけで#204や後続Issueは閉じない。
