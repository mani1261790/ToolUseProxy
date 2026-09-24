# 導入と初期設定

[紹介](README.md) · [対応範囲](SUPPORT.md) · [データの扱い](PRIVACY.md) · [文書一覧](docs/索引.md)

macOS / Linux、Python 3.11–3.12、認証済みのCodex CLIを用意します。Windowsの新判定経路は実機受入が未完了です。公開版は [v0.2.0-alpha.16](https://github.com/mani1261790/ToolUseProxy/releases/tag/v0.2.0-alpha.16) です。

## 1. プラグインを導入する

```sh
codex plugin marketplace add mani1261790/ToolUseProxy --ref public-alpha
codex plugin add tooluseproxy@tooluseproxy
```

Codex環境へのインストールは一度行えば、複数のプロジェクトで利用できます。保護登録や設定はプロジェクトごとに行います。インストール元と5種類のHook定義を確認して信頼し、Codexを再起動して新しいタスクで使用します。

このプラグインはユーザーの権限で動き、判定用モデルへ通信します。インストール済み・有効という表示だけで、実際の保護動作を確認したとは扱いません。

## 2. 対象プロジェクトで初期設定する

> このプロジェクトでToolUseProxyを使いたい

Codexが付属のセットアップSkillを使います。初回は、記録したToolCallの入力・出力と検査に必要なローカルの証拠を判定モデルへ渡すこと、バックグラウンド解析もモデルを利用することを確認します。[データの扱い](PRIVACY.md)を読んでから進めてください。

初期設定の時点から記録を始め、過去の作業は取り込みません。保護対象の自動登録は行いません。初期設定済みなら設定を作り直さず、ログ画面を開きます。

プラグインの保存先への書込みや、ログ画面のローカル接続に権限が必要な場合は、Codexの通常の申請を確認してください。権限不足は流出検出やモデルの時間切れとは別の問題です。権限を得ずに保存先を変えたり、別タスクに代行させたりしません。

## 3. 保護するファイルを指定する

> research_notes.mdを保護して

プロジェクト内に存在する指定ファイル全体を登録します。登録のために本文を読んだり、モデルへ問い合わせたり、送信テストをしたりはしません。登録済みなら重ねて作り直しません。

> 何を登録してた？

登録一覧を確認できます。初期設定・登録完了と、実際に送信を止められることの検証は別です。検証が必要なら、架空のデータと確認済みの送信先を使う作業として別途依頼してください。

## 4. ログを確認する

初期設定時にログ画面が起動します。あとから開く場合は、次のように依頼できます。

> ログを見せて

Codexのブラウザサイドパネルで開きます。呼び出し一覧とグラフを切り替え、プロジェクト・セッション・遮断の有無で確認できます。画面が切れた場合は再度開いてください。ログ画面の接続切れと、保護機能の停止は別です。

## 更新・解除する

更新は明示的に行います。

```sh
codex plugin marketplace upgrade tooluseproxy
codex plugin list --json
```

Hook定義が変わった場合は再確認し、Codexを再起動します。再現用に版を固定する場合は、導入時の `--ref` に公開タグを指定します。固定タグは更新チャンネルの変更に追従しません。

プロジェクトからの解除は、[Setup／Unsetup](docs/運用/Setup-Unsetup.md)の管理者承認経路を使います。エージェント向けコマンドだけで保護を解除する設計にはしていません。管理者用部品は別途導入が必要で、未導入なら解除は完了しません。プラグインを削除しても保存済みのログは消えません。

## 手動操作・開発用のコマンド

通常の利用では、上記の短い依頼で構いません。手動操作では、実際にインストールされた版の起動スクリプトを使います。次の `<...>` は環境に合わせて置き換えます。

```sh
sh "<PLUGIN_ROOT>/hooks/run_cli.sh" --version
sh "<PLUGIN_ROOT>/hooks/run_cli.sh" setup --workspace "<WORKSPACE>" --data-dir "<PLUGIN_DATA>" --accept-judge-data --json
sh "<PLUGIN_ROOT>/hooks/run_cli.sh" protect add --path research_notes.md --workspace "<WORKSPACE>" --data-dir "<PLUGIN_DATA>" --json
sh "<PLUGIN_ROOT>/hooks/run_cli.sh" logs --workspace "<WORKSPACE>" --data-dir "<PLUGIN_DATA>" --json
```

`--model <MODEL>` で判定用モデルを指定できます。省略時は独立したCLIの既定モデルであり、親タスクと同じとは限りません。起動スクリプトの場所、設定、解除の詳細は[プラグイン導入](docs/設定/Plugin導入.md)を参照してください。
