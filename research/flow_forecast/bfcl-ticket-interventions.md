# Ticket APIの有限な人工介入

固定公開ソースを変更せず、5つの人工初期状態でresolve・所有者別Resolved一覧・他所有者ID取得を実行する。
基準値に対し、他所有者の本文、自分のtitle、他所有者のcreated_by、他所有者のstatusを一つずつ変更する。
期待する返り値と最終状態は実行前に定義し、各ケースを新しい隔離containerで実行する。

各ケースは状態設定1＋API3の4試行、合計20試行。明示1バッチの上限は20試行・180秒・1GiB。
記録前の予約保存、実装/ビルド元一致、工程間予算検査、失敗記録保持は参照実行と同じ。
時間上限は工程間検査であり、全工程の厳密なOS強制deadlineではない。

実測は20試行・7.221秒・report前49,394 bytes、全5ケースの期待値が一致。
[記録](results/bfcl-ticket-interventions-20260919.json)に実行commitを保存した。
予約とscript/観測/reportのhash対応を再計算し、記録した全containerが撤去済みと確認した。
照合処理を含む20テストとRuff成功。新規モデル呼出し0、採用独立群0。

他所有者本文は所有者別一覧に影響せず、ID取得には反映された。自分のtitleは一覧に反映され、他所有者ID取得には影響しなかった。
他所有者のownerだけをAに変えてもOpenのため一覧から除外され、statusだけをResolvedに変えてもBのため除外された。
この有限集合の観測を一般的な非干渉の証明にはしない。receiver、native Hook、生成モデルの試験ではない。
`bfcl_ticket_evidence.bind_capture`で予約・実装・script・出力・状態の証跡を再検査し、公開/保護の各query 2件を基準ケースへ照合した。
ビルドcontextは一致するがimage IDは異なり、identical_image_verified=falseを記録する。
この照合に追加trialは不要。F01の因果ラベル昇格はまだ行わず、unknownを維持する。
