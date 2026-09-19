# 人工課題のResponses API生成経路

`generated_world_plan prepare --provider openai-api`は、既存の閉じた人工課題計画を
公式Responses APIで1回だけ生成する。既定のcodex経路は維持する。
APIキーはOPENAI_API_KEYから受け取り、artifact・引数・エラー本文に保存しない。
Codexのログイン情報をAPIキーとして流用しない。

```sh
python -m research.flow_forecast.generated_world_plan prepare \
  --provider openai-api --world inventory --model MODEL_ID --output NEW_DIRECTORY
python -m research.flow_forecast.generated_world_plan collect \
  --prepared NEW_DIRECTORY --repository REPOSITORY --output NEW_CAPTURE_DIRECTORY
```

親が最大60秒で子プロセスを終了させる。子は公式host/pathへのHTTPSを1回だけ実行し、
redirect・proxy・retry・任意endpointを受け付けない。要求は人工課題の定義、固定指示、
閉じたJSON schemaだけ。tools空、tool_choice none、store false、最大出力1024 tokens。
レスポンス本文は256KiB、計画本文は16KiBまで。不完全応答・refusal・tool call・複数計画を
採用しない。HTTPエラー本文やライブラリの診断を返さない。

API receiptはschema 2。要求モデル名とは別に、提供側response.modelのreported_model、
response IDのhash、正確な要求/応答のhash、usageを記録する。CLI receiptを偽造せず、
cli_versionはnull。実行receiptと採用計画のreceiptでAPIメタデータが一致することを確認する。
提供側のモデルIDがaliasである可能性や、保存後のローカルartifactの書換え可能性は残る。
resolved_model_verifiedはfalseを維持し、固定snapshot版・provider署名・研究上の独立性の
証明には昇格させない。

応答が課金usageを返していても計画が不正なら、実行費用だけを残し封印しない。
認証なし/通信失敗/時間切れはusage unknownで、無料や0tokensと扱わない。
charged_callsは予約枠の消費を表し、提供側へ要求が到着したことの証明ではない。

取得したreported_modelはtask_world_importを通り、generator_strataの
provider_reported_models_by_partitionへ接続する。群の分割・予測器の層別ラベル・F02の
モデル一般化合格条件は変えない。モデルIDを返すことと固定版の保証を分ける。

検証は人工HTTP応答によるもの。2026-09-19の環境にOPENAI_API_KEYはなく、実API呼出0。
既存CLIの実測証拠はschema 1のまま検証できる。実APIのモデルID、固定版の可否、費用、
人工trialへの実接続は、API利用環境で別途確認する必要がある。#204は未完了。

仕様確認: [Responses create](https://developers.openai.com/api/reference/python/resources/responses/methods/create)
のmodel、output、usage、text.formatを参照（2026-09-19）。
