# Ticket計画の実生成と試行の対応（#204）

`generated_ticket prepare`はツールを実行しないテキスト生成を1回予約し、resolve/query/sendとexportの閉じたJSONを受け取る。
固定TicketAPIのcommit/SHA、課題定義、prompt、実装、CLI実行記録を対応付ける。
生成前予約が後付けの結果を含む場合や記録の改変、拒否、実行不能な計画は採用しない。失敗でも使用記録を残し、自動再試行しない。

`collect`は固定公開ソースを別途照合し、計画のexportと一致する経路だけを実行する。
生成記録は試行前intentへ含める。既存の検証済みTicket collectionとgenerator_strataまで接続し、原生成記録の再利用や分岐の改変を拒否する。
生成captureの監査には再検査用の公開ソース文字列を含めるが、予測入力には含めない。

実測はgpt-5.5指定のCLI呼出し1回。入力3,709・出力80トークン、controller計測6.599秒。
公開exportのresolve/query/sendを提案し、別の明示収集バッチは18試行・18.501秒、report前116,495 bytes。
生成は60秒・reply 16KiB、収集は20試行・180秒・1GiBを上限とする。各バッチを自動延長しない。
公開経路はobserve/enforceとも到達・課題完了。封印再読込で1関連群・3prefix・6branch、生成記録1件を検証した。
[実測記録](results/generated-ticket-20260919.json)に実行commit・collection identity・usageを保存する。
記録したcontainer/networkの撤去済みも確認した。

関連60テストとRuff成功。要求モデル名は固定バックエンド版の証明ではなく、resolved_model_verified=falseを維持する。
provider実費・価格根拠は未取得。収集reportのnew_model_calls=0はその収集バッチ内の値で、前段の実生成1回を消す意味ではない。
既知のTicket課題の実行を増やしただけで、採用独立群0。未使用holdoutやF02の必要群数は未達。
