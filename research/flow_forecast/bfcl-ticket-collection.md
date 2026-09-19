# BFCL Ticketの実I/O収集（#204）

固定版TicketAPIのresolve → query → sendを、人工状態と隔離receiverに接続した。
APIの返り値と保存した更新後状態を照合し、queryで保存した実際のJSON本文を送る。
公開経路は所有者Aの解決済みticketのみ、保護経路は人工保護文字列を含む所有者Bのticketを取得する。
ToolUseProxyのMCP事前判定へ同じcallを渡す。記録のみではdenyでも実行し、停止ありではdispatchしない。
native Codex HookやPostToolUseの受信を証明するものではない。

1バッチは両モードのcontrol6試行と、各3段階の状態復元・MCP予約12試行の計18試行。
上限20試行・180秒・1GiB。失敗時も予約済み試行を残し、出力先を再利用・自動延長しない。
時間・容量は工程間で検査するため、全工程の厳密なOS強制deadlineではない。

公開経路は18試行・17.285秒、両モードで公開本文が到達した。
保護経路は18試行・19.265秒、記録のみで人工保護文字列が到達し、停止ありでは送信前にdenyとなった。
後者は途中停止なのでpipeline完了や正当なtask達成には数えない。
停止理由にはexternal_payload_verification_unavailableが記録されており、意味的な所有権判定の成功とは扱わない。

初回公開バッチはcontrol3試行後、変数名の衝突でsource照合に失敗した。
原因を修正して別出力先で実行し、失敗記録も保持した。
[実測記録](results/bfcl-ticket-collection-20260919.json)は実行時commitとreport hashを保存する。
予約数・call/script hash・各stepとreportの対応を別途再計算した。
その後のレビュー修正で、実装とビルド元のPython証跡一致、予約保存後の加算も追加した。
この修正後は単体試験で検証しており、上記実測の実行時commitとは区別する。

新規モデル呼出し0、採用独立群0。F01へのimport、生成モデル証跡、未使用holdoutへの採用は未完了。
同じAPIの2経路を独立課題として水増ししない。
