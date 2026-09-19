# MBPPの入力・private値の有限介入

固定MBPP 602/603/604について、baseline、private値だけ変更、入力だけ第2例へ変更の3条件を実行する。各条件はcompute/public/getの3呼出で、各課題9試行。参照コード・レコード・dispatcherのhashを固定する。

`mbpp_projection`は既存dispatcherから入力と人工private値の取得式だけを明示的に置換する。元のcaptureをそのまま再実行した観測ではない。private値はMBPP関数の引数に渡さず、wrapperのメタデータとして扱う。ホストでは参照関数を実行しない。

`mbpp_projection_batch`は課題単位で最大20試行・180秒（指定可能範囲は1800秒まで）・1GiBの明示的バッチを予約し、ネットワークなし・非特権・read-only Dockerで実行する。条件ごとの3呼出を実行前に予約するため、失敗時には未実行呼出も予約数に含まれ得る。全体時間は段階の前後で確認し、各実行には既存10秒timeoutを使う。全体を厳密に指定秒で中断する保証ではない。

`read_interventions`は意図、実装manifest、9予約、3container、script、実出力、結果、reportと容量を再検証する。重複JSONキー・余分な観測・失敗記録・改変を拒否する。`bind_capture`はstrict capture readerを通し、同じ由来・build contextとbaseline照会値を照合する。

## 実測

実行source `9a8de05`、reader `db7624d`。保存先は各 `/private/tmp/tooluseproxy-204-mbpp-{602,603,604}-projection-v1`。集計は [results/mbpp-projection-20260919.json](results/mbpp-projection-20260919.json)。

3明示バッチで27試行、合計7.093977958秒、report作成前128844bytes。全条件で宣言した結果に一致した。private値だけの変更は公有照会値を変えず、入力の変更は公有結果を変えた。モデル呼出0、採用独立群0。

既存6captureへのbindingは成功した。ただし全6件で実測image IDは異なり、`identical_image_verified=false`。build contextの一致をimage同一性と扱わない。有限例だけから普遍的非干渉性を証明せず、F01のunknownを変更しない。native Hookやreceiverの新しい観測もない。次に固定wrapper・plain JSON domainの投影契約へ接続する。
