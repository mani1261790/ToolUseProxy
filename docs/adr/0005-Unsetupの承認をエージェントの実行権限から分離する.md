# 0005: Unsetupの承認をエージェントの実行権限から分離する

日付: 2026-09-18。対象: Issue #188。状態: 設計決定、適用経路は未実装。

## 決定

エージェント向けCLIは変更の計画だけを作れる。人間の承認と設定更新は、
エージェントが変更できない管理側の処理にまとめる。信頼できる管理側がない
現行構成では `unsetup apply` は無条件に拒否する。確認番号を返すだけの
実装を、承認設計の完成や #188 の完了として扱わない。

故障時は利用者がCodexのPlugin管理画面から手動で無効化できる。
これは全プロジェクトに影響する暫定的な復旧であり、プロジェクト単位の
Unsetupの代わりに完了扱いしない。エージェントはその手操作を代行しない。

## 調査と信頼境界

- 本セッションは `danger-full-access` / approval `never`。任意shellとファイル
  更新が可能で、Codex承認を必須にする経路はこのタスクにはない。
- ローカル `codex-cli 0.153.4` の `--help` で `on-request` / `never`、自動レビュー、
  sandbox回避の選択肢を確認した。別インストールのCLIの存在を、Desktopの
  実行経路の検証と混同しない。新しいCodex実行や設定変更はしていない。
- [Codex permissions](https://learn.chatgpt.com/docs/permissions) はプロファイルに
  よる書込制限を提供し、danger-full-accessはその制限を除く。制限を採用する
  場合、設定自体もエージェントが変更できない管理対象にする必要がある。
- [Apple LAContext](https://developer.apple.com/documentation/localauthentication/lacontext)
  は利用者認証を提供する。しかしCLIへ成功の真偽値を返すだけでは、CLIの
  書換えや設定ファイルへの直接書込みを防げない。OS認証の実機試験は未実施。
- `activation.py` の有効化markerとDB設定は同一ユーザーが書き込める。
  モジュール呼出し、別Python、改造launcher、別プロセスからの変更まで防ぐには、
  CLI構文検査の外側に強制可能な権限境界が必要。

承認に使わないもの: `--yes`、チャット上の自己申告、質問ツールの回答、
環境変数、TTYの有無、親process名、同じユーザーが読めるtoken、確認hash、
自動レビューの通過、単なるOSダイアログのクリック。hashは変更検出にだけ使う。

## 管理側の契約

1. 管理側の実行コード・設定・承認状態と、Hookが信頼する有効状態の保管先を、
   エージェントの書込権限から外す。管理OSアカウント、保護されたservice等で
   強制する。読み取りだけの制限ではディレクトリ差替えを含めて検証する。
   Hook自体やPlugin設定を改変して回避できる構成には完全耐性を宣言しない。
2. 管理画面が対象のcanonical project、installation/data identity、操作種別、
   設定revision、保持するもの、停止の範囲を独立に表示し、人間が承認する。
   表示用文字列はエージェントの文章をそのまま信頼しない。
3. 承認と適用は同じ管理側で行う。CLIに再利用可能な秘密や成功booleanを渡さない。
   challengeは管理側発行・期限付き・一回限り。操作と対象とrevisionに結び付け、
   拒否・期限切れ・取消・別project・改変・再送では変更しない。
4. 管理側に対象単位の排他と世代番号を持ち、承認検証・状態遷移・challenge消費を
   一つの永続transactionとして確定する。crash後は確定結果を照会する。
   同じ要求の再送は結果照会だけにし、再初期化後の新しい世代を停止しない。
5. 人間による解除は重い検出DBに依存しない。DB使用中・破損・判定timeoutでも
   管理側が対象の停止状態を原子的に確定できる独立した保管先を使う。
   管理側故障時の復旧はOS管理者の手操作とし、未承認の自動解除へ降格しない。

この契約を実装・検証するまで、macOS認証を付けただけの適用commandや
人間専用と名付けただけのshell scriptを追加しない。

## 状態遷移とデータの扱い

計画は監視の有効状態を変えない。承認済み適用で対象だけをinactiveにし、
設定・保護対象登録・履歴・元ファイル・利用者の保護リストを保持する。
履歴削除は別操作。他projectと全体Pluginの有効状態を変更しない。

既存のactivation markerを削除するだけでは不十分。
`enabled_workspace_root` は旧DBへfallbackし、`save_workspace_activations` は
登録済みrootからmarkerを再作成する。独立した明示inactive状態を最優先し、
別projectのsetupや旧形式移行で再有効化しない契約が必要。

適用前から走っているHookは取り消したと主張しない。対象の新規Hook受付を止め、
既存Hookの終了とworkerの停止を確認するまでは `deactivating`、完了後に
`inactive` と表示する。初期化要求・新規記録・停止が起きないことを5 Hookで確認する。
再初期化では残っている登録・設定を人間が確認し、新しい世代でactiveへ遷移する。

## 迂回経路も検証対象

現行の正規管理操作分類は「外部通信しない命令」の判別であり、人間の承認ではない。
`protect remove apply`、保護設定のoff、登録を減らすreconcile/migrate、
`uninstall apply`、Plugin無効化、marker/DB/Hook/launcherの直接変更を棚卸しする。
Unsetupだけを保護してこれらを許した状態は、エージェントによる保護解除を
防げたとは扱わない。互換性に影響する既存commandの変更は別途試験付きで行う。

## 今回の実装と次の受入試験

今回追加するのは `unsetup plan` の読み取り専用プレビューと適用拒否。
計画は対象directoryの識別だけを行い、DB・保護リスト・activation内容を読まない。
現在の有効状態は `not_inspected`、承認経路は利用不可と表示する。
正規launcher・同project・同dataのplanだけを故障復旧の軽量経路へ追加する。
applyを管理操作の無条件許可へ追加しない。

今回の試験: DBなし・破損・排他lock中の計画、本文非読取、偽装flag/token/env、
再送・別projectのapply拒否、追加shell・別launcher・別dataの復旧経路拒否。
拒否試験の合格は承認成功経路や解除完了の証拠にはしない。

管理側実装後の必須試験: 実際の人間の承認・取消・期限切れ・nonce再送、revision
競合、symlink/対象差替え、同時Hook、workerと再初期化の競合、commit前後のcrash、
DB故障中の人間による解除、5 Hook無記録、他projectと全保持データの一致。

#188を完了にするには管理側の実装と実機証拠、公開・導入手順がまだ必要。
その次は #189 のオフライン展示画面を最優先とし、自動探索を先行させない。
