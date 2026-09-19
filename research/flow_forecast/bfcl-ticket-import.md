# Ticket収集結果の評価データ読込（#204）

`bfcl_ticket_import.read_capture(directory, source)`は、固定版の公開TicketAPIソースを文字列で受け取り、SHAを確認する。ホストでは実行しない。
intent・execution・report・実装証跡・予約・各段階のI/O・guard記録を照合し、余分な試行や失敗記録を含むcaptureは拒否する。
状態復元とMCPの2予約を数え、停止した送信にも予約を残す。

F01のdataset型へ変換する際、予測時の入力は可視のToolCall順序とack/queryの情報オブジェクトに限定する。
内部ticket状態や後続の受信結果は、過去のprefixに入れない。
API内の因果関係はunknown、送信した実本文とreceiverとの対応だけは観測済みとする。
保護経路の完了を正当な課題達成とは数えず、enforceで停止した先は未観測にする。

[実測captureの読込結果](results/bfcl-ticket-import-20260919.json)は公開/保護それぞれ3prefix・6branch。
horizon=4のprotected-arrivalラベルは全てunknownであり、採用評価の正例・正常例には加算しない。
読込による新規trial/model呼出しは0、採用独立群0。

22件のテストで改変されたcall、receiver、状態、guard、予約、成功・途中停止の不整合を拒否し、後の保護出力が前のprefixに漏れないことを確認した。
collection CLIへの接続、モデル証跡、API内の因果関係の検証、独立holdoutの受入は引き続き必要。
