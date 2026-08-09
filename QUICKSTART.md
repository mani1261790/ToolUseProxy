# ToolUseProxy 5分クイックスタート

この手順では、検証済みの公開alphaを保護branch `public-alpha`からインストールします。開発中の変更を含む`main`は、通常利用のインストール元にしないでください。

## 1. 必要なもの

- macOSまたはLinux
- Python 3.11または3.12
- Plugin対応のCodex CLIまたはCodex Desktop

利用前に[対応環境と既知の制限](SUPPORT.md)と[プライバシーとデータ保持](PRIVACY.md)を確認してください。ToolUseProxyのlocal監査DBには、コード、command、response、protected sourceの断片が平文で保存される場合があります。

## 2. Pluginをインストールする

次の2コマンドを実行します。

```bash
codex plugin marketplace add mani1261790/ToolUseProxy --ref public-alpha
codex plugin add tooluseproxy@tooluseproxy
```

MarketplaceとPluginのインストールは、Codex環境ごとに1回だけです。projectごとに再インストールする必要はなく、同じPluginを複数projectで利用できます。

特定versionへ固定する場合は、1つ目のコマンドで`public-alpha`の代わりにimmutable tagを指定します。

```bash
codex plugin marketplace add mani1261790/ToolUseProxy --ref v0.1.0-alpha.5
```

## 3. 3つのHookを確認してTrustする

Codexが表示するHookを、次の条件と照合してください。

- sourceが`Plugin - tooluseproxy@tooluseproxy`
- `PreToolUse`、`PostToolUse`、`Stop`の3件
- commandがインストール済みToolUseProxy Plugin内の`hooks/run_hook.sh`を指す

役割は次のとおりです。

- `PreToolUse`: tool実行前にpayloadを確認し、protected contentの外部送信を止める
- `PostToolUse`: tool実行後に入力と結果をlocal DBへ記録する
- `Stop`: 最終回答にprotected contentが残っていないか確認する

HookはCodex sandbox外でユーザー権限により実行されます。ToolUseProxyのHook自身はlocal dataへ書き込み、network通信は行いません。source、件数、command pathが異なる場合はTrustしないでください。無関係なHookも表示されている場合は`Trust all`を使わず、ToolUseProxyの3件を個別に確認します。

## 4. 利用するprojectを初期設定する

ToolUseProxyを使いたいprojectをCodexで開き、新しいtaskで自然な言葉で依頼します。例えば次のように短く頼めますが、この通りの言い方でなくても構いません。

> ToolUseProxyをこのプロジェクトで使えるようにして

Pluginのインストールは1回ですが、次の情報はworkspaceごとに分離されます。

- workspaceの初期化
- protected sourceの登録
- runtime保護設定
- local監査data

ToolUseProxyが必要な初期設定と安全確認を案内します。通常は確認画面が2回出ます。どちらも外部通信は行わず、このprojectの外にあるToolUseProxy専用保存領域を設定・確認するためのものです。

完了時に「このプロジェクトではToolUseProxyが動作しています」と表示されれば準備完了です。すべての機密ファイルが自動登録されるわけではありません。

## 5. protected sourceを1件確認する

続けて、自然な言葉で保護候補を探すよう依頼します。次は入力例であり、固定フレーズではありません。

> 守った方がよいファイルを探して

候補が見つかると、次の内容が日本語で表示されます。

- ファイル：project内の相対pathだけ
- 守る内容：値を表示せず、どの設定項目を守るか
- できること：選んだ内容の外部送信を実行前に止められること
- 「守る」を選ぶと：保護対象リストに1件追加され、元ファイルは変わらないこと
- 選択肢：「守る」「今回は見送る」「今後は候補に出さない」

候補の値、file preview、source hash、ユーザーのabsolute pathは表示しません。初期設定や候補探しだけでは保護対象に登録されません。

PreToolUse blockは既定で無効です。このクイックスタートだけで強制blockを自動的に有効化することはありません。保護設定を有効にする場合は、[Plugin導入ガイド](docs/設定/Plugin導入.md)の説明と承認境界を確認してください。

## 6. 実projectで安全に試す

最初は、production credential、顧客data、署名鍵を含まない低riskなprojectを選びます。次の順で確認してください。

1. 有効なToolUseProxy Pluginが1つだけである
2. 3つのHookを確認してTrustした
3. 「このプロジェクトではToolUseProxyが動作しています」と表示された
4. harmlessなpublic操作が通常どおり完了した
5. syntheticなprotected valueが外部操作の実行前にblockされた
6. 通常作業で予期しないblockが発生しない
7. PluginをRemoveしても、別途data削除を承認しない限りlocal dataが保持される

setup失敗、Hookの`modified`または`untrusted`、2つ目のToolUseProxy Plugin、public操作の誤block、protected valueの外部副作用が発生した場合は検証を停止してください。広い再利用可能permissionで回避しないでください。

詳細な記録項目は[実projectでのドッグフード手順](docs/運用/Pluginドッグフード.md#実projectでのself-dogfood)と[dogfood report template](.github/ISSUE_TEMPLATE/dogfood-report.md)を利用できます。reportへsource値、raw Hook payload、SQLite DB、access token、ユーザーのabsolute pathを含めないでください。

## 7. 更新する

更新は自動ではありません。新しい公開alphaへ進む場合だけ、明示的に実行します。

```bash
codex plugin marketplace upgrade tooluseproxy
codex plugin list --json
```

更新後は変更されたHook定義を再確認し、新しいCodex taskを開始して、bundled setup skillが求めるverificationを実行します。

## 8. Pluginを外す

PluginコードとMarketplace登録を外す場合は次を実行します。

```bash
codex plugin remove tooluseproxy@tooluseproxy
codex plugin marketplace remove tooluseproxy
```

この操作ではlocal監査dataを削除しません。data削除は[Plugin導入ガイド](docs/設定/Plugin導入.md#disable--uninstall)に記載した、別の`uninstall plan`と明示承認が必要です。

## 30秒のsynthetic preview

repositoryをcheckoutしている場合は、実network通信を行わない自動previewも実行できます。

```bash
python3.11 scripts/demo_plugin.py
# Python 3.12を使う場合
python3.12 scripts/demo_plugin.py
```

これはHookの目視確認・Trustや、実際のCodex taskでの検証を置き換えるものではありません。
