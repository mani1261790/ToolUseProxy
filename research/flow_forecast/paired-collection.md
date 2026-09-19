# 保存済み計画の観測・停止条件を揃えた収集

生成前の課題割当を持つ完了済み人工searchから、指定したattemptの計画を固定する。
同じaction列をobserve/enforceの順に再実行し、生成モデルへ再提案を求めない。
元のrun/attempt/step、割当、生成元の証拠を保存し、同じ課題群として扱う。

```sh
python -m research.flow_forecast.paired_collection \
  --repository SYNTHETIC_SOURCE_CHECKOUT \
  --search-directory COMPLETED_ASSIGNED_SEARCH \
  --attempt 1 --seconds 600 --output NEW_DIRECTORY
```

両条件で新しい受信環境を用意し、公開到達・保護対象到達・保護対象拒否の3対照を
各条件で確認する。課題の各操作前に時間・容量・回数を確認する。
1計画は最大7操作とし、対照込み最大20操作、8試行（6対照+2計画）に制限する。
1バッチ最大1800秒・1GiBを維持し、次のバッチを自動で始めない。
時間期限は各操作の開始前に確認し、実行中のDockerコマンドは各コマンドのtimeoutで停止する。

生成前の割当とは別に、今回選んだ計画・条件・上限をintent.jsonへ実行前に保存する。
source-evidence.jsonは元の人工runの閉じた取込証拠。各条件の終了後にobserve.json /
enforce.jsonを保存する。中断時の予約と観測を保持し、既存出力での再実行は拒否する。
成功時だけdatasetとreport.jsonを完成させる。実利用DB・外部宛先・任意コマンドは使わない。

datasetは既存F01形式で、両policy_modeは同じprefix・branch ID・control groupへ対応する。
各操作は元のrunnerと同様に独立したguard呼出なので、長い状態付き軌跡とは見なさない。
中間変換の独立観測は追加しておらずtruth relationはunknownを保つ。元の計画は適応探索で
選ばれたためsampling=adaptive_search、probability=nullのままで、自然な発生確率にしない。
これは条件を揃えた再試験であり、独立新課題数0、unused_holdout=falseを維持する。
#204の独立課題・未使用道具/生成モデル別の再評価を代替せず、採用や保護解除を許可しない。
