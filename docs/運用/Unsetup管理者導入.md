# Unsetup管理者導入（#188、導入前の検証用）

現在は開発中。管理者用入口を通常CLIから分離したが、実機の権限境界と全workerを
含む受入確認は未完了。本文は導入物のレビュー用であり、現在のMacへ導入済みという
記録ではない。Pluginは無効のまま。利用者管理の保護リストを読み書きしない。

## 成り立つ権限境界

エージェント用アカウントは管理状態・管理コード・その親directory・Python実行系へ
書き込めず、管理者の認証情報・SSH agent・root shell・管理者側UI操作へ到達できない
ことが必要。特にエージェントから操作できるTerminalにroot shellを残した構成は
採用しない。NOPASSWDや包括的なsudo委任も承認経路にしない。

管理者用入口はrootの実行権限を要求する。この権限取得は、エージェントから
分離された管理者セッションで人間が行う。端末上の「確認して適用」は誤操作防止で
あり、OS認証の代わりではない。通常CLIの `unsetup apply` は引き続き拒否する。
同一ユーザーの任意shellに対して、可変のHook・Plugin設定自体まで改変不能にした
証拠にはならない。ADR 0005の導入条件を確認するまで完全耐性を宣言しない。

## レビュー可能な導入物を作る

開発側では通常権限で次を実行する。出力先は未存在のファイルを指定する。

```sh
python3 scripts/build_authority_admin.py --output /tmp/authority-admin-candidate.py
```

生成物は標準ライブラリだけで動く単一Pythonファイルで、検出DB・Pluginコードを
importしない。同じsourceから同じbyte列を作り、SHA-256を表示する。生成物の
`--help` と未承認操作の拒否はMac同梱Python 3.9.6でも試験する。製品本体の
Python 3.11/3.12要件を変更するものではない。

初回の信頼は管理者によるsource/配布物の確認に依存する。編集可能なcheckoutにある
hashを読むだけでは配布元の真正性は証明できない。管理者が独立に確認した配布物と
hashを使い、署名付き配布を行う場合はその署名も検証する。署名済みとは主張しない。

## 管理者による導入の契約

固定の導入先は次の2つ。通常CLIや環境変数で変更できない。

- コード: `/Library/Application Support/ToolUseProxy/Admin/authority-admin.py`
- 状態: `/Library/Application Support/ToolUseProxy/Authority/`

管理者が、OSの信頼できる導入手段でコードをowner root・mode `0555`、directoryを
owner root・mode `0755`として配置する。最終ファイルだけでなく全親directoryの
所有権、write権限、ACL、symlinkを確認する。既存directoryが別の所有者、リンク、
またはエージェントへwriteを許す状態なら、そのまま上書き導入しない。

配置後は管理者が保持したhashと配置済みファイルのhashを照合する。root-ownedでも
ACLでエージェントが変更できれば不合格。エージェント用アカウントから書込み・削除・
rename・別ファイルへの差替え・管理操作の呼出しが拒否されることを人工対象で試す。
本番の保護リストを拒否試験の対象にしない。

実行は信頼できるOSの `/usr/bin/python3 -I -S` を使う。環境をクリアし、
`PYTHONPATH`、user site、作業directoryからコードを読ませない。選択された
Command Line Tools/Python実体と全親directoryもエージェントから変更できないことを
確認する。管理者用入口はisolated/no-site、導入場所、root所有権、コードの書込禁止を
確認するが、初回導入の信頼や管理者セッションの分離を自動で作るものではない。

## 初期登録・停止・再初期化

以下は管理者セッション内の呼出し形式。`UID`、`PROJECT`、`DATA`は対象利用者の
数値UID、projectの絶対path、専用data directoryに置き換える。権限昇格を通常の
エージェント用CLIへ委任しない。

```sh
/usr/bin/env -i PATH=/usr/bin:/bin /usr/bin/python3 -I -S \
  '/Library/Application Support/ToolUseProxy/Admin/authority-admin.py' \
  enroll --uid UID --workspace PROJECT --data-dir DATA
```

1. 初期登録 `enroll` は旧Hook・workerの終了を確認し、Plugin無効状態で行う。
   新しいHookがleaseを取得できる導入版に揃える。旧Hookを自動的に追跡できたとは
   扱わない。確認画面に表示された利用者・canonical path・保持対象を確認する。
2. 停止は `enroll` を `deactivate` に替える。管理側は120秒の確認期限、対象directoryの
   inode、状態の世代を再検査してから停止を確定する。DB使用中・破損でもDBを開かない。
3. 既存leaseがあれば `deactivating` で返る。新規Hookは受け付けないが、実行中処理を
   取り消したとは表示しない。終了後に `finish` でdrainを確認して `inactive` にする。
4. エラーや中断後は `status` で実際の状態を確認する。commit後のI/Oエラーがあり得る
   ため、エラーだけを理由に「変更なし」とは扱わない。`finish` は既存操作だけを再開する。
5. 再初期化は `reactivate`。以前の設定・登録・履歴を残したまま新しい世代で再開する。
   設定が空になったとは扱わない。停止処理中の再初期化は拒否する。

どの操作も元ファイル・保護リストを変更せず、他projectを停止しない。履歴削除は
別の明示操作。これらの管理操作は正常な構文だけを理由にHookの無条件許可へ追加しない。

## 公開前の未完了ゲート

- 管理者セッションがエージェントから操作不能であることと、実機のowner/ACL境界
- 信頼できる配布物の導入・改変拒否・未承認呼出し拒否
- 人間の承認・取消・期限切れ、target差替え、再送、別project
- 全workerを含む同時実行、故障DB、中断後のstatus/finish、再初期化
- 新しい実行で5 Hookがinactive時に無表示・無記録であること
- 現在の利用者データを保持する公開・導入手順と、対応版への更新確認

現時点の単体試験は人工directoryと人工の管理者ownerで実施しており、これら実機ゲートの
合格の代わりにはならない。導入ができない環境では適用拒否を維持し、人間によるPlugin
管理画面の無効化を故障時の暫定復旧にする。全体Pluginの無効化はproject単位の完了ではない。

## 履歴整理の扱い

管理者状態が導入されている場合、停止projectの履歴は自動・手動整理の削除候補から
除外する。稼働中projectの期限切れ記録は従来どおり整理できる。削除が既に始まって
いれば、そのtransactionが終了するまで停止状態はdeactivatingに留まる。
停止前に表示した整理計画で停止後に対象履歴を削除しようとすると、計画変更として拒否する。

所属projectを確定できない記録と、過去のproject構成が不明なDB全体のmigration backupは
保持する。後者は整理計画でcleanup_blockedと表示される。これは容量削減の制約であり、
バックアップの検証成功だけでは停止projectの履歴を消してよい根拠にならない。
