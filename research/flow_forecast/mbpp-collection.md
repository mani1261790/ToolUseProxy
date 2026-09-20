# MBPP処理のtool I/O・受信確認（#204）

固定されたMBPP 602/603/604の参照関数を、実際のJSON tool dispatchへ接続した。
各課題の第1例を用い、compute→public/get→sendの3呼び出しを行う。元の関数名を
tool名へ置き換えただけではなく、computeは元のコードをその引数で実行する。
返答・永続状態を別observerで照合し、送信先の別receiverでもbody hash/サイズを確認する。

[固定したGoogle Research / MBPP](https://github.com/google-research/google-research/tree/4700efb9afa54286b0e04473ba80a13e8461e25f/mbpp)
（Austin et al., 2021、データCC BY 4.0）が出典。原版データのSHAと選定レコードのhashを
照合し、試行前intentへ出典・候補・使用caseを保存する。元データはrepoへ複製しない。

## 人工サービスの意味

参照関数は結果だけを計算する。wrapperが結果と人工のprivateメタデータを保存し、
computeのtool返答はcomputed/task_idのackだけとする。privateは計算引数へ渡さない。
publicはresultだけ、getはresult/privateを返す。sendは実際の照会返答を読むため、
期待値をcontrollerからreceiverへ直接送ったものではない。

privateは隔離image内の人工ソースに由来する。元のMBPP課題に秘密情報や脆弱性があると
主張するものではなく、計算と保護メタデータの投影を組み合わせた開発用シナリオ。
内部state/observerは監査情報であり、将来の予測prefixへそのまま渡してはいけない。

guardは実際のMCP形式名/JSON引数を受け、準備した同じcallだけをdispatchできる。
変更されたcall、未知の課題、変更された参照コード、外部receiverは拒否する。
これは実PreToolUse runtimeへの直接入力であり、native Codex/MCP hostの配送試験ではない。

```sh
python -m research.flow_forecast.mbpp_collection \
  --repository /path/to/isolated/checkout --source /path/to/mbpp.jsonl \
  --task-id 602 --variant public --output /path/to/new/output
```

variantはpublic/include_private。1回で1課題・1variant、observe/enforceと各3受信対照を
含む最大12予約。各20試行/180秒/1GiBの上限で、次バッチへ自動延長しない。
モデル呼出はない。失敗・中断でも既存記録と費用を残す。

## 実測と限界

source1858dd4で602/603/604×public/privateの6バッチを個別に実行した。
72試行、合計76.4875秒、report出力前のartifact小計630,673bytes。
各課題のpublicは両modeでallow・公有結果到着。privateはobserveで最後のdeny後も
人工的に送信して保護到着を確認し、enforceでは最後の送信前deny・未dispatch・到着なし。
観測modeのguard文面を未実行の証明にせず、実際のdispatch/receiverで判断する。

保存済み36呼び出し予約のscript/call hash、33実dispatchとobserver、送信が実行された
9件のreceiver bodyを再照合した。結果はresults/mbpp-collection-20260919.json。
各課題の残り2例は前の参照実装バッチでのみ実行しており、この経路で全9例を検証したとは
主張しない。各private条件のtask_achievedは閉じた処理手順の完了を表す。

拒否は保守的なexternal payload判定で、計算の意味的な情報追跡や早期予測の改善証明ではない。
F01へのstrict reader/取込、生成モデル、独立性の検証は未接続・未完了。採用独立群0。
次はこの保存記録を由来・実I/O・受信の対応を崩さずに評価collectionへ接続する。
