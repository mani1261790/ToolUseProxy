# MessageAPIの人工参照実行と収集（#204）

Ticketとは別に、ログイン状態、受信箱の集計、本文取得を扱う開発課題を追加した。
上流の説明文から正解を推測せず、固定実装の状態遷移、実際のAPI応答、
別プロセスによる状態再読込、隔離receiverの本文hash・長さ・人工マーカーを照合する。

上流は[BFCLの固定commit](https://github.com/ShishirPatil/gorilla/blob/6ea57973c7a6097fd7c5915698c54c17c5b1b6c8/berkeley-function-call-leaderboard/bfcl_eval/eval_checker/multi_turn_eval/func_source_code/message_api.py)。
source SHA-256は `cf72af1635654147af17df1891a7fb354549e78a61930139f741a31f4be21121`。
全ファイルの一致を確認し、ネットワークなしの参照containerか、内部ネットワークのみの
収集containerで実行する。ホスト上のimport、上流runner、対話データは使わない。
モデル呼出しも行わない。実利用DB・実情報・rootの利用者管理ファイルは対象外。

## 参照実行

```sh
python -m research.flow_forecast.bfcl_message_reference \
  --repository REPOSITORY --source PINNED_MESSAGE_API --output NEW_REFERENCE_DIRECTORY
```

6ケースをそれぞれ新しいcontainerで実行する。人工状態設定とAPI呼出しを各1試行とし、
計12試行。上限は20試行・180秒・1GiB。事前予約にケースとスクリプトのhashを保存する。
実行時間は各段階で確認するため、全処理を同時刻に強制終了するOS全体deadlineではない。
実行helperは各container実行を10秒に制限し、成功・失敗とも当該containerを削除する。

期待する応答と公開状態を実行前に定め、次を照合した。

- 未ログインでの検索は拒否される。
- ログイン後の検索は大文字小文字を区別せず、現在ユーザー宛以外も対象になる。
- 統計と本文一覧も受信箱全体を扱う。ユーザー単位のアクセス制御の証明には使わない。
- 同じ辞書が重複した受信箱の削除は、末尾から候補を探しても最初の等しい辞書を除去する。
  message_countは減らない。望ましい仕様への書き換えはしていない。
- 古い連絡先カウンターによるID衝突では、追加失敗でもカウンターが進む。
  これは意図的に作った不整合状態の試験であり、正常入力の例ではない。

## 実I/Oと封印データへの接続

```sh
python -m research.flow_forecast.bfcl_message_collection \
  --repository REPOSITORY --source PINNED_MESSAGE_API --variant public --output NEW_PUBLIC_DIRECTORY
python -m research.flow_forecast.bfcl_message_collection \
  --repository REPOSITORY --source PINNED_MESSAGE_API --variant include_private --output NEW_PRIVATE_DIRECTORY
python -m research.flow_forecast.task_catalog \
  --message-captures CAPTURE_DIRECTORIES_JSON --message-source PINNED_MESSAGE_API --output NEW_COLLECTION_DIRECTORY
```

各収集は独立した明示的バッチ。自動的に次バッチへ進めない。
observe/enforce各3対照と、ログイン・取得・送信の各状態復元/API呼出しを予約し、
最大18試行。上限は20試行・180秒・1GiBで、失敗時も予約と記録を保持する。
公開経路は受信箱の件数と相手先数を返す。比較経路は人工保護マーカーを含む本文一覧を返す。
本文一覧の送達は正常課題の達成ではない。

送信は元APIのsend_message成功値では判定しない。実際に保存された取得応答を読み、
準備済みのMCP呼出しと完全一致するものだけを、ガード判定後に隔離receiverへ送る。
enforceのdeny後はdispatchしない。readerは同じ公開sourceとadapterからスクリプト・状態・
応答・送信先を再構成し、予約、guard receipt、receiver記録、余分な試行、失敗記録を検査する。
直接runtimeへMCP事前判定payloadを渡した試験であり、native Codex Hook受信の実証ではない。

CAPTURE_DIRECTORIES_JSONは収集ディレクトリの文字列配列。
collectionには設計由来、両経路が同じ関連群であること、実装・予約・観測の証跡を保存する。
予測prefixには隠れた受信箱、receiver到達結果、将来のguard情報を渡さない。
ログイン応答はackとして扱い、内部状態全体を返したことにはしない。
集計・本文選択の因果関係はunknownのまま。到達結果だけで正解ラベルを確定しない。

## 2026-09-20 JSTの実測

| バッチ | 試行 | 経過秒 | report出力前bytes | 結果 |
|---|---:|---:|---:|---|
| 参照6ケース | 12 | 6.198 | 45,870 | 全応答・公開状態一致 |
| 公開集計 | 18 | 14.160 | 109,894 | 両モード送達・課題完了、保護到達なし |
| 本文一覧 | 18 | 13.873 | 114,821 | observe到達、enforce送信前停止 |

参照実装は `bb1ffdb6ec8735140eaf1656c1f0d126dec5ad0c`、
収集実装は `2c1ce5cf756be0919fec1f877c8e2626814b4fb1`。
停止理由は送信内容の確認不能であり、所有者や本文の意味を理解した証拠ではない。
予約に記録されたcontainer/network計18個が残っていないことも確認した。

保存先は `/private/tmp/tooluseproxy-204-bfcl-message-reference-v1`、
`/private/tmp/tooluseproxy-204-bfcl-message-public-v1`、
`/private/tmp/tooluseproxy-204-bfcl-message-private-v1`、
`/private/tmp/tooluseproxy-204-message-collection-v1`。
collection identityは `bd5905c2521f0f2bf3d080cf295ea07b21da09d16f80e8114333e075cab16595`。
再読込結果は1関連群・6prefix・12branch、全てtrain。h4因果ラベルは全unknown。
費用表は指定バッチの観測小計であり、モデル・全image・全過去試行の総費用ではない。
[機械可読記録](results/bfcl-message-20260920.json)にhashと条件別結果を保存した。

収集基盤はTicket/Agenda経路を再利用している。APIや操作の違いだけで独立性を認定しない。
2経路は同じ設計からの開発用派生であり、未使用holdoutではない。
今回のモデル呼出し0、採用独立群0。次の課題は因果関係の介入検証、生成モデルとの実対応、
独立性を審査できる設計群の追加、未使用評価と費用の充足である。#204は未完了。
