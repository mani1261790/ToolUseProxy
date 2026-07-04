# Tool Adapter

## Adapterとは何か

adapterは、toolごとに異なる入力・出力を、ToolUseProxy共通の情報流グラフへ翻訳する処理です。

Hookから届くJSONを保存するだけでは、その値が何を意味しているかまでは分かりません。

たとえば次の入力には、ファイルpathが含まれています。

```json
{
  "path": "private.py"
}
```

しかし、汎用の類似度計算だけでは、これがファイルのreadなのかwriteなのか、出力されたコードがどのファイル由来なのか判断できません。

Filesystem adapterはtool名とJSON構造を解釈し、次の共通表現へ変換します。

```text
Read:
resource_version(private.py)
  -> tool_output

Write:
tool_input.content
  -> resource_version(xx.md)
```

つまり、役割は次のように分かれます。

- adapter
  - toolの操作内容を理解する
  - path、content、outputなどの役割を抽出する
  - tool構造に基づく確定的なedgeを作る
- similarity
  - コピー、部分一致、少し崩れた再利用を推定する
- lineage
  - source bindingからedgeをたどり、各nodeのsourceを求める

## なぜadapterが必要か

類似度だけでは、無関係な文章が偶然似ている場合に誤ったedgeが作られる可能性があります。また、path文字列とファイル本文は似ていないため、ファイルreadの関係は内容比較だけでは説明できません。

adapterでは、次のようなtoolの構造を証拠にできます。

```text
tool_name = Read
tool_input.path = private.py
tool_response.content = 未公開コード
```

この場合、本文同士の類似度を使わず、

```text
private.pyのresource version
  -> 未公開コードを含むtool output
```

という`structured` edgeをscore `1.0`で作ります。

## Resource Version

同じpathのファイルでも、上書き前後では内容が異なります。そのため、pathそのものではなく`resource_version`をnodeとして扱います。

```text
notes.md version 1
  -> Writeで更新
notes.md version 2
  -> Readで取得
```

現在のresource versionは、主に次から識別します。

- session
- 絶対path
- content hash
- event sequence
- tool use ID

write後に同じpathをreadし、内容hashも一致した場合は、同じresource versionを経由させます。

## Protected Sourceとの接続

`protected_sources.json`に登録されたpathとresource versionのpathが一致した場合、次の確定edgeを作ります。

```text
protected_source(private.py)
  -> resource_version(private.py)
```

そのため、sourceファイルの現在の内容とtool outputが似ていなくても、指定pathをreadした事実からlineageを開始できます。

一方、未登録の`public.md`をreadしてもprotected sourceからのedgeは作られません。ほかの類似度edgeから接続されない限り、そのnodeはsource lineageの外に残ります。

## 現在実装しているAdapter

現在はFilesystem adapterだけを実装しています。

対象とするtool名は、正規化後に次のいずれかになるものです。

### Read

- `read`
- `read_file`
- `readfile`
- `read_text_file`
- `fs_read_file`
- `fs_readfile`
- `filesystem_read_file`
- `filesystem_read_text_file`

### Write

- `write`
- `write_file`
- `writefile`
- `write_text_file`
- `fs_write_file`
- `fs_writefile`
- `filesystem_write_file`
- `filesystem_write_text_file`

tool nameは小文字化し、`/`、`.`、`-`などを`_`へ正規化して照合します。Codex app-serverにも`fs/readFile`と`fs/writeFile`があるため、この命名も対象にしています。

入力ではsemantic roleが`path`と`content`のfragmentを使います。read出力では`content`、`stdout`、`tool_output`を使います。

## 現在の処理順

```text
Hook event
  -> event / artifact / artifact fragmentを保存
  -> adapterがtool call単位でfragmentを解釈
  -> resource versionとstructured edgeを生成
  -> similarity edgeと統合
  -> protected sourceをpathまたは内容でbinding
  -> lineageを伝播
```

`scripts/rebuild_lineage.py`を実行すると、adapter解析も同時に実行されます。

```bash
python3 scripts/rebuild_lineage.py --rebuild-graph
```

生成されたresourceは`resource_versions`、edgeは`information_flow_edges`へ保存されます。

## 未実装のAdapter

次はまだ実装していません。

- Search adapter
  - queryを外部送信候補として構造化する
- Bash adapter
  - `cat`、redirect、pipe、`curl`などを解析する
- MCP adapter
  - server名、tool名、arguments、resultをMCP callとして構造化する

Bashはshell構文、変数展開、pipe、redirectがあるため、Filesystem adapterとSearch adapterより後に実装します。

## 現在の制限

- tool名とJSON keyが許容形式に一致しない場合、Filesystem adapterは反応しない
- append、patch、rename、copy、deleteは未対応
- CodexがBash経由でファイルを読む場合はFilesystem adapterではなく、将来のBash adapterが必要
- 外部プロセスがファイルを書き換えた場合、Hookだけでは変更versionを確定できない
- read outputが省略・切り詰められた場合、content hashはファイル全体を表さない
- resource versionは現段階ではHook観測から再構成した仮想nodeであり、実ファイルsnapshotではない

## 公式仕様との関係

Codex Hooksは`PreToolUse`と`PostToolUse`を含むライフサイクルイベントを提供します。またCodex app-serverは、絶対pathを扱う`fs/readFile`と`fs/writeFile`を提供しています。

- [Codex configuration reference](https://developers.openai.com/codex/config-reference)
- [Codex app-server API overview](https://developers.openai.com/codex/app-server#api-overview)

ToolUseProxyは、これらのtool固有形式を直接グラフ全体へ持ち込まず、adapterで共通edgeへ変換します。
