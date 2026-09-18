# 人工試験のIssue連携

Issue #132。#131の保存記録から共有案を作り、専用outboxへ保存し、明示コマンドで
GitHub Issueへ接続する。Hook・Plugin・定期処理から自動起動しない。

## 共有内容

共有するのは閉じた人工操作の種類、固定の観測分類、検出器ソースの指紋、試験参照、
判定根拠の指紋だけ。コマンド本文・送受信本文・判定理由の自由文・ローカルパスは
共有案へコピーしない。生成時と送信時の両方で形式を検査する。

未特定・観測不足も提案対象。途中の試験予約は操作の成否不明と明記する。
同じ操作について後の版で問題が観測されなかった結果も、同じ問題へ追記する。
未観測だけでは修正完了と表現しない。

問題キーは人工操作と問題種別から作り、検出器版を含めない。
送信キーには版・試験参照・観測内容を含め、同じ記録を二重にキューへ入れない。
受信対照の成功と、実利用環境でのHook到達や本番の修正完了は区別する。

## コマンド

まずローカルの共有案を確認する。この操作は通信せず、元の試験DBも変更しない。

```sh
python3 -m hook_monitor.evaluation.flow_lab.issue_runner preview \
  --campaign /absolute/path/to/comparison
```

専用の新規outboxへ登録する。repositoryを指定しただけでは送信しない。

```sh
python3 -m hook_monitor.evaluation.flow_lab.issue_runner enqueue \
  --campaign /absolute/path/to/comparison \
  --outbox /absolute/path/to/lab-outbox --repository owner/repository
python3 -m hook_monitor.evaluation.flow_lab.issue_runner status \
  --outbox /absolute/path/to/lab-outbox --repository owner/repository
```

既存Issueへ接続する場合は、previewのproblem_keyを使って対応を登録する。
登録はローカルだけで、実在・競合は送信前に照会する。登録済みの対応先は変更しない。

```sh
python3 -m hook_monitor.evaluation.flow_lab.issue_runner bind \
  --outbox /absolute/path/to/lab-outbox --repository owner/repository \
  --problem-key <64桁のproblem_key> --issue 140
```

次のコマンドで初めて通信する。既存pilot workerのGitHubクライアントを共用するが、
pilotの実利用DB・設定・worker起動処理は使用しない。認証はホストのghを使用する。

```sh
python3 -m hook_monitor.evaluation.flow_lab.issue_runner sync \
  --outbox /absolute/path/to/lab-outbox --repository owner/repository --limit 20
```

未対応の問題は新規Issueを作る。対応済みなら同じIssueへ観測をコメントする。
既存Issueの再open・close、コード・PR・Project状態の変更はしない。
共有先はoutbox作成時に固定し、同じ保存先の別repositoryへの切替を拒否する。
1 repositoryの送信には1つの永続outboxを使う。複数ホスト・複数outboxからの
同時投稿をGitHub側で原子的に排除する仕組みではない。

## 送信状態と再実行

- pending: 未送信。認証・読み取りの失敗は再試行可能。
- in_flight: 書き込み開始を保存済み。プロセス中断や応答喪失を含め、結果未確定。
- sent: 成功応答、またはIssue/コメントの送信マーカーで投稿を確認済み。
- rejected: 共有案の検査に失敗。外部へ送信しない。

同じコマンドを再実行すると投稿済みマーカーを照合する。
結果不明の書き込みは、一覧に見つからなくても自動再送しない。
同じ問題の後続投稿も待たせる。別の問題は巡回して処理し、一部の不明記録だけで
キュー全体を止めない。Issue一覧が途中で切れた場合も、不在とはみなさない。
同じoutboxを複数プロセスから同時に送信することはロックで拒否する。

statusには件数と直近100件の参照・対応Issue・状態・エラーコードを表示する。
syncは未処理・不明・拒否が残れば終了コード1、全件確認済みなら0。
外部でマーカーが削除された、結果不明の要求がまだ確定していない等の場合は
記録を保持して照会を続け、推測で再投稿しない。

## 検証の区別

疑似GitHub試験では新規作成、同じ問題への版違いコメント、書き込み後の応答喪失、
未到達か不明な要求、再実行、重複マーカー、認証失敗、同時送信、内容改変、
送信先変更、未知の投稿による他の問題の停滞を確認する。

実GitHubでは、#131で実行した旧新版の人工HTTP試験を既存#140へ各1件投稿した。
再実行は追加0件で、リモートのマーカーも2件のまま。

- [旧版の観測](https://github.com/mani1261790/ToolUseProxy/issues/140#issuecomment-5725393913)
- [新版の観測](https://github.com/mani1261790/ToolUseProxy/issues/140#issuecomment-5725394067)

この実投稿確認は既存Issueへのコメント経路であり、新規Issue作成の実GitHub試験ではない。
公開Python送信の保守的停止は#140として残る。#130〜#132の接続だけで検出器の改善が
完了したとは扱わず、次に#140を修正し、正常操作と保護停止を再比較する。
ToolUseProxyは無効のまま。実利用DBやrootの利用者管理manifestは変更しない。
