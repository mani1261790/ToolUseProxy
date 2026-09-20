# 人工予定APIの状態とI/O

API-Bankの予定追加/照会を参考に、実データや第三者コードを使わない独自の小さなAPIを
実装した。上流準拠の評価ではない。呼出はagenda.add / agenda.get / agenda.publicに限定し、
controllerが選んだ人工所有者A/Bの状態だけを操作する。所有者をtool引数で変更できない。
同じIDは所有者ごとの名前空間へ格納し、戻り値とobserverのsnapshotはcopyで返す。
無効な入力・重複ID・容量超過は状態を変えない。

所有者をA/Bに変える試験、別所有者指定の拒否、日付の不正、上書き拒否、未知ID、
追加→照会→公有フィールド抽出を7つの固定ケース/10呼び出しで観測する。
実際にservice.callへJSON引数を渡し、controller側で前後の全状態と戻り値を採取する。
期待値をAPIの返答から生成せず、別に宣言した出力・状態と比較する。

```sh
python -m research.flow_forecast.agenda_batch \
  --repository REPOSITORY --output NEW_DIRECTORY --seconds 180
```

各caseは既存の非特権・network none・read-onlyのDocker profileで実行し、実行前に
profileを確認する。1バッチ最大20呼び出し/1800秒/1GiB。今回の指定は180秒。
case内の呼び出し枠を実行前に予約し、失敗しても予約を消さない。個別containerは実行の
終了時に削除する。研究コードを含めない既存image構成は変更せず、固定した自作API本体を
実行scriptへ含め、case・call・scriptのhashを予約に結び付ける。任意コードや外部caseは
受け付けない。途中失敗の時間/容量/予約数をfailure.jsonに記録する。

## 実測

- 最初のsource d46774d / agenda-api-v1は、imageに研究モジュールが含まれないため
  import段階で失敗。3枠を予約し、API結果は確認できなかった。旧実装にはfailure.jsonが
  なく経過時間は不明。削除・再利用せず、不明を0時間として扱わない。
- 修正source dcc3123 / agenda-api-v2は、7case・10呼び出しが事前の正解と一致。
  2.5878秒、report前49283bytes。失敗を含む合計予約13枠、モデル呼出0。
- 保存後に全observationとcase/call/script予約hashを再照合した。
  report/hash/sourceはresults/agenda-api-20260919.jsonに記録。

この段階は状態を持つ人工APIの部品検証であり、ToolUseProxyの判定や受信先の観測は
接続していない。native Hook確認、F01変換、未使用評価、独立課題の追加とは扱わない。
全caseは同じ派生課題familyである。次はこの実dispatchをguard・隔離receiverへ結び、
I/Oとstate observationを保ったまま収集する。shell実行のtool名を変えただけの新ツール
一般化とは主張しない。#204は未完了。
