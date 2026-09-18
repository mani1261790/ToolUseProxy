# ToolUseProxy 展示画面

このdirectoryの4ファイル（index.html / screen.css / screen.js / replay-data.js）を
同じfolderへコピーし、index.htmlをChrome等で開く。サーバー・インストール・ネット接続は不要。
ToolUseProxyのPluginは無効のままでよい。実利用DBや保護リストには接続しない。

## 1分の展示

1. 「保護情報の送信」で「再生する」。情報の出所→Shellへの入力→送信前の停止をたどる。
2. 時系列の「送信前に停止」を選ぶと、固定試験で確認した停止理由の説明を読める。
3. 「公開情報の送信」を選んで再生し、通常の操作を許可する例を見る。
4. 判定の横の「実際の外部受信」は未観測。許可と配信完了、停止と未受信の観測は別だと説明する。
5. 「証拠が足りないとき」は説明用の人工例。試験結果の再生とは明確に区別して表示する。
6. 「リセット」で工程を初期状態へ戻す。一時停止・1工程ずつ進む・速度変更も使える。

試験の実行や外部送信は再生中に行わない。固定試験に受信側の証拠がないため、
「受信0件」などの結果を推測して作らない。経路と工程は説明用の再構成であり、
生の操作ログや実測timestampではない。本文・認証情報・実利用ログは含まない。

## 固定データの再生成

保護リストを含まないclean checkoutで実行する。人工試験は専用の一時directoryを使う。

```sh
python scripts/demo_plugin.py --json > /tmp/tooluseproxy-demo-evidence.json
python scripts/build_exhibition_replay.py \
  --evidence /tmp/tooluseproxy-demo-evidence.json \
  --output docs/exhibition/replay-data.js
```

exporterは合格した人工試験の固定項目だけを抽出する。任意の本文・診断・pathを
転載せず、version/hashも形式を検証する。不合格・不完全な試験を成功例にしない。
画面のCSPで外部接続を禁止し、fetch、外部font/CDN、解析サービスを使わない。

## 自動確認と実ブラウザの確認

- exporterの本文非転載、不合格の拒否、受信未観測の保持：tests/test_exhibition_replay.py
- Chromeで1440pxと390pxの表示、再生完了、リセット、停止/許可/不明の切替を確認済み。
- Browser offline状態での切替再生、file://からのoffline起動・再生を確認済み。
- screenshotは作業checkoutのoutput/playwrightへ保存。会場機材の確認は別途行う。

将来のライブ連携は、この静的画面へ実利用ログを直接流し込まず、本文を持たない
検証済みの表示データへ変換して追加する。現時点のライブ観測は未接続。
