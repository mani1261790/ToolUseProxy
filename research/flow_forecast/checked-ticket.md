# 固定Ticket APIの値選択契約

公開TicketAPIの固定SHA版について、_find_ticketのID選択、resolveのstatus/resolution更新と定型応答、get_user_ticketsのowner/status filter、get_ticketのrecord返却を読んで確認した。
`checked_ticket`はこの実装と固定transport、検証済みのJSON初期状態・成功経路に範囲を限定する。hashだけを証明とは扱わない。

`read_checked_capture`はcaptureと人工介入の証跡照合に加え、実call・前後状態・選択結果を検査する。
resolveの応答は公開IDの確認だけで、保護本文を含まない。公開一覧はticket 1のみ、ID取得は保護本文を含むticket 2を選ぶ。
期待する情報オブジェクトの対応が欠けたり増えたりしていれば拒否し、検証されたselectionだけをchecked_json_projectionへ変換する。
受信側の観測は既存の実本文照合を維持し、enforceの未実行区間は未観測として残す。

CLIは `--checked-ticket-captures PAIRS.json --ticket-source PINNED_SOURCE.py --output NEW_DIRECTORY`。
pairsの各要素はcapture/interventionsの2つのdirectoryを指定する。

実測2captureを再読込して封印した結果は、1関連群・6prefix・12branch。
horizon 4はno=6、yes=3、unknown=3。新規trial/model呼出し0。
[記録](results/checked-ticket-20260919.json)にはcollection.jsonから計算したcollection_identityを保存する。
旧読込記録でcatalog digestをseal_shaと記した項目もcatalog_shaへ訂正し、実際のcollection_identityを追加した。

関連43テストとRuff成功。可視prefixを変えないこと、保護経路のedge欠落・状態変更・transport変更を拒否することを検証した。
Python標準ライブラリとDocker controllerを信頼し、異なる入力・例外・時間経路・一般的非干渉は対象外。
ハッシュ分割名はcalibrationでも、開発使用済み・独立性未検証のまま。採用独立群0、未使用holdoutの達成ではない。
