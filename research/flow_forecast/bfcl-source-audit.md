# BFCLの取り込み可否（#204）

[公開元の固定commit](https://github.com/ShishirPatil/gorilla/tree/6ea57973c7a6097fd7c5915698c54c17c5b1b6c8)
から、LICENSE、データ説明、multi-turn評価器と実行補助、Message/Ticket/FileSystemの
実装、Message/Ticketの関数定義の計9ファイルを静的に確認した。Git blob SHAとSHA-256を
照合済み。第三者コードはimport・実行していない。対話データも取得していない。
取得範囲・hash・関数名はresults/bfcl-source-audit-20260919.jsonへ保存した。

root LICENSEはApache-2.0、データREADMEもapache-2.0を宣言する。今回repoへ追加するのは
監査結果だけで、上流コードや対話の複製ではない。Git trees APIが返したshaと、
git commitオブジェクトの実際のtree shaは別欄に記録した。

## 利用できる部分と不足する証拠

MessageAPIは10操作、TicketAPIは9操作で、取得した関数定義には全操作のresponse定義がある。
FileSystemの18操作も状態を持つ。実装を参照して具体的な操作の契約を設計できる点は、
道具の説明と実行順だけのデータより有用。ただし、これを37独立課題とは数えない。

multi_turn_checkerはモデル側と正解側の実行後状態、および必要な応答の包含を確認する。
private属性を状態比較から除き、呼出順検査は呼ばれていない。これはタスク結果の判定であり、
保護情報の依存関係やreceiverへの到着の証明ではない。

- MessageAPI.send_messageはメモリ上のinboxへ内容を追加する。外部receiverを観測して
  いないため、sent_statusをToolUseProxyの送達ラベルに使わない。
- TicketAPI.ticket_loginはusername/passwordが空でないことを確認する模擬認証。
  get_ticket/close_ticket/edit_ticketは所有者による限定を行わない。これを管理者承認や
  実際のアクセス制御の保証へ流用しない。
- 実行補助はクラスを動的importし、呼出文字列をevalする。限られた関数名の除外もあるが、
  固定JSON dispatchと同等の境界ではない。上流runnerをホストへ直接接続しない。
- FileSystemはメモリ内のFile/Directoryを中心に実装し、long_contextをimportする。
  今回、その依存ファイルは未監査。subprocessのimportはあるが、確認したファイル内では
  呼出を見つけていない。importだけを根拠に外部実行が起きるとは判断しない。

## 独立性と次の収集判断

READMEのV3 base 200 / augmented 800は件数の説明であり、独立群数の保証ではない。
特にMissing FunctionsはCoreと基本的に同じ操作列であると明記される。派生関係を保持せず
別partitionへ分けると漏れが起きる。V2 Liveは実世界データと説明されるため、今回の人工
評価用コーパスへ取り込まない。V3各行の由来・派生関係は今回未確認であり、公開済みという
理由だけで未使用holdoutにもできない。

現時点では直接F02へ取り込まない。次の実装では、上流の動的runnerを採用する前に、
選んだ操作群の依存コード・入力domain・状態遷移・独立した成功条件を監査し、人工初期状態と
固定JSON dispatchに限定する必要がある。送信は隔離receiverの観測と結び付ける。
同じAPIを使う派生シナリオや関数名の置換は、独立群の増加として扱わない。

今回のモデル呼出0、実試行0、採用独立群0。BFCLを使えば520独立群を確保できる、という
結論ではない。#204の独立holdout・実モデル版・有効性評価の不足は継続している。
