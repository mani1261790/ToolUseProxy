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
codex plugin marketplace add mani1261790/ToolUseProxy --ref v0.1.0-alpha.7
```

## 3. 5つのHookを確認してTrustする

Codexが表示するHookを、次の条件と照合してください。

- sourceが`Plugin - tooluseproxy@tooluseproxy`
- `SessionStart`、`SubagentStart`、`PreToolUse`、`PostToolUse`、`Stop`の5件
- commandがインストール済みToolUseProxy Plugin内の`hooks/run_hook.sh`を指す

役割は次のとおりです。

- `SessionStart`: Web SearchなどHookで技術的に遮断できないhosted toolへ、protected contentやそこから得た内容を渡さない安全境界をCodexへ伝える
- `SubagentStart`: subagentにも同じhosted tool境界を伝える
- `PreToolUse`: Hookから見えるlocal toolの実行前にpayloadを確認し、protected contentの外部送信を止める
- `PostToolUse`: tool実行後に入力と結果をlocal DBへ記録する
- `Stop`: 最終回答にprotected contentが残っていないか確認する

HookはCodex sandbox外でユーザー権限により実行されます。Hook自体はlocal dataだけを読み書きし、network通信やLLM待機を行いません。実験的なExternality Judgeを別途有効にすると、未知callは値非保持のlocal queueへ入り、protected情報がそのcallへ流れている場合は分類を待たず止まります。publicだけなら止まりません。LLM分類は、Hook外workerを利用者が明示実行した場合に、jobごとの新しい隔離済みCodex一時セッションでだけ行われ、この手順では有効になりません。ToolUseProxyはOpenAI APIやAPI keyを直接扱いません。source、件数、command pathが異なる場合はTrustしないでください。無関係なHookも表示されている場合は`Trust all`を使わず、ToolUseProxyの5件を個別に確認します。

この実行前blockはCodex Hookへ届くlocal toolが対象です。hosted Web SearchはHookへ届かず、実行中processへの`write_stdin`追加入力では新しい`PreToolUse`が発火しません。これらを保護済みとは表示しません。

## 4. 利用するprojectを初期設定する

ToolUseProxyを使いたいprojectをCodexで開き、新しいtaskで自然な言葉で依頼します。例えば次のように短く頼めますが、この通りの言い方でなくても構いません。

> ToolUseProxyをこのプロジェクトで使えるようにして

Pluginのインストールは1回ですが、次の情報はworkspaceごとに分離されます。

- workspaceの初期化
- protected sourceの登録
- runtime保護設定
- local監査data

ToolUseProxyが必要な初期設定と安全確認を案内します。操作ごとの承認UIを使う権限modeでは通常2回確認されます。現在のmodeが専用保存領域へのaccessをすでに許可し、承認UIを表示しない場合は、その選択済み権限内で同じ限定setupを続行し、表示回数を0回と正確に報告します。どちらの場合も外部通信は行いません。

通常インストールでは、ToolUseProxy自身が現在のPlugin identityを検証して専用保存領域を特定します。利用者が`database_missing`などの内部診断、absolute path、初期化commandをコピーして貼り直す必要はありません。承認UIがないことだけを理由にターミナル実行へ切り替えません。保存先またはaccessを安全に確認できない場合は、別pathや広い権限を推測せず未設定のまま停止します。

完了時に「このプロジェクトではToolUseProxyが動作しています」と表示されれば準備完了です。すべての機密ファイルが自動登録されるわけではありません。

## 5. protected source候補をまとめて確認する

続けて、自然な言葉で保護候補を探すよう依頼します。次は入力例であり、固定フレーズではありません。

> 守った方がよいファイルを探して

候補が見つかると、最大10件が番号付きでまとめて表示されます。

- ファイル：project内の相対pathだけ
- 守る内容：値を表示せず、どの設定項目を守るか
- できること：選んだ内容の外部送信を実行前に止められること
- 「守る」を選ぶと：その候補が保護対象リストに追加され、元ファイルは変わらないこと
- 選択肢：「守る」「今回は見送る」「今後は候補に出さない」

候補の値、file preview、source hash、ユーザーのabsolute pathは表示しません。「全部守る」「1と3は守る、2は見送る」のように自然な言葉でまとめて回答できます。判断が曖昧な候補があれば、その番号だけを確認してから一括反映します。初期設定や候補探しだけでは保護対象に登録されません。

既にpathが分かっているMarkdownなどの文書は、例えば「研究計画と研究方針のMarkdownを全文守りたい」のように依頼できます。ToolUseProxyは本文を表示せず、最大10件の対象pathと「全文を守る」ことをまとめて示します。明示的に「守る」と判断したファイルだけを、一度の操作で登録します。

この初期設定では、PreToolUseによる実行前blockとfile-backed payload保護をworkspace単位で有効にします。既存の異なる設定がある場合は上書きせず停止します。

## 6. 実projectで安全に試す

最初は、production credential、顧客data、署名鍵を含まない低riskなprojectを選びます。次の順で確認してください。

1. 有効なToolUseProxy Pluginが1つだけである
2. 5つのHookを確認してTrustした
3. 「このプロジェクトではToolUseProxyが動作しています」と表示された
4. harmlessなpublic操作が通常どおり完了した
5. syntheticなprotected valueが外部操作の実行前にblockされた
6. 通常作業で予期しないblockが発生しない
7. PluginをRemoveしても、別途data削除を承認しない限りlocal dataが保持される

setup失敗、Hookの`modified`または`untrusted`、2つ目のToolUseProxy Plugin、public操作の誤block、protected valueの外部副作用が発生した場合は検証を停止してください。広い再利用可能permissionで回避しないでください。

正常にblockした場合は、「ToolUseProxyが外部送信を実行前に止めました」と「結果：外部操作は実行されていません」が先に表示されます。保護対象の本文、source ID、scoreは判断材料として表示しません。調査commandが必要な場合だけ、最後の「技術情報（通常は読む必要なし）」を確認できます。

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
