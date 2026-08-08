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
codex plugin marketplace add mani1261790/ToolUseProxy --ref v0.1.0-alpha.4
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

ToolUseProxyを使いたいprojectをCodexで開き、新しいtaskで次のように依頼します。

> ToolUseProxy setup skillを使って、このworkspaceを初期設定し、doctorとstatusで確認してください。protected valueは表示せず、失敗した場合はそこで停止して理由を説明してください。

Pluginのインストールは1回ですが、次の情報はworkspaceごとに分離されます。

- workspaceの初期化
- protected sourceの登録
- runtime保護設定
- local監査data

`doctor: ok`と`status: active`を確認します。これはruntimeが利用可能という意味であり、すべての機密ファイルが自動的に保護されたという意味ではありません。

## 5. protected sourceを1件確認する

続けて、次のように依頼します。

> protected source候補を1件だけscanしてください。相対path、理由、confidence、値を含まないselectorだけを説明し、approve、reject、ignoreの判断を待ってください。

ToolUseProxyは候補の値、file preview、source hash、absolute pathを表示しません。protected sourceは、内容と変更点を理解したうえで1件ずつ明示承認します。初期設定やscanの実行だけでは登録されません。

PreToolUse blockは既定で無効です。このクイックスタートだけで強制blockを自動的に有効化することはありません。保護設定を有効にする場合は、[Plugin導入ガイド](docs/設定/Plugin導入.md)の説明と承認境界を確認してください。

## 6. 実projectで安全に試す

最初は、production credential、顧客data、署名鍵を含まない低riskなprojectを選びます。次の順で確認してください。

1. 有効なToolUseProxy Pluginが1つだけである
2. 3つのHookを確認してTrustした
3. setup、doctor、statusが成功した
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
