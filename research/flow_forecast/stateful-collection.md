# 中間の入出力を観測する人工収集器（#204）

従来の探索・対照収集は毎回新しいsenderを起動するため、複数操作の途中にある
ファイルや変換の関係を観測できず、中間truthをunknownとしていた。
この収集器は、既存の隔離プロファイルを保つ単一sender内で、事前に固定した
読取・コピー・Base64変換・保存・送信を順に実行する。検出器の判断をtruthに使わない。

```json
{"schema":1,"source":"public","operations":["read","encode","save","send"]}
```

sourceはpublic/protectedという内蔵の人工値だけ。操作は2〜7個で、最初はread、最後はsend。
中間はcopy/encode/save、encodeは最大1回。道具側がPythonを組み立て、呼出元はコード・
パス・送信先・ペイロードを指定できない。ホストのファイルや資格情報をコンテナへ渡さず、
読取専用イメージ・非特権ユーザー・16MiB tmpfs・内部限定ネットワークを検証する。

```sh
python -m research.flow_forecast.stateful_collection \
  --repository SOURCE_CHECKOUT --plan PLAN.json --output NEW_DIRECTORY --seconds 180
```

plan/実装の識別情報は開始前、各操作の予約は判断・実行前に排他的に保存する。
予約にはstep IDとcommand hashを対応付け、Hook受領・判断もdispatch前に別保存する。
dispatchや観測が失敗してもその対応を失わない。完了reportは実測経過秒と、report自身を
書き込む前のartifact容量を記録する。過去の未計測値は後から推定して埋めない。
途中失敗・時間切れでも記録を残し、既存ディレクトリへ再実行しない。observe/enforceを
別のreceiver/senderで実行し、それぞれ公開到達・保護到達・保護停止の3対照を確認する。
対照と各道具操作を1試行ずつ保守的に数え、最大20試行、1800秒、保存量1GiB以下。
指定時間を各処理の前後で確認し、進行中のDocker処理には既存の個別timeoutを適用する。
終了・失敗時の所有コンテナ削除は予算終了後も実行する。次バッチへ自動延長しない。

## 観測とF01への接続

各操作が終了してから別の観測プロセスが、実際の入力・出力ファイルを読み直す。
copy/saveはバイト一致、encodeは復号して入力と一致することを確認する。
独立したreceiverは実際に受信したbodyのhash・長さ・人工保護値の到達を記録する。
送信ファイルとreceiverのhash/長さが一致しなければ収集失敗とする。
F01への取込時にも、閉じた人工値と操作から求まる全hash鎖、操作順、拒否条件、
最後までの観測を再検証する。結果不明・欠測・途中失敗を正常完了に変換しない。

両条件で実際に共通して観測できた位置のprefixだけを固定する。予測入力には
過去の操作・objectだけを渡し、hash証拠・将来の経路・検出判断は渡さない。
拒否された操作自体は実行済みの観測に加えず、監査記録に保持する。以後の未実行部分は
censoredのまま。観測済みcopy/base64/save/sendの経路だけをtruthとして扱う。

この分布は「生成・実行前に宣言した単一の決定的人工pipeline」に限り確率1。
自然なエージェントの行動分布ではなく、過去のadaptive探索を固定分布へ変換する機能でもない。
現行は生成モデルを使わず、generator_evidence=null/model_verified=false。
既存の人工HTTP課題に観測を追加した実装確認であり、独立新課題数は0、unused_holdout=false。
操作や名前を変えただけで独立課題に数えない。TaskBenchのAPI課題を実行したものでもない。

observerとsenderは別プロセス、receiverは別コンテナだが、Docker/ホストの管理権限に
対する独立した証明ではない。native CodexからのHook配送、実環境での保護、有効性や
#204の独立評価条件をこの試験だけで合格にしない。Pluginの有効化は行わない。
