# Release候補の作成と検証

public alphaのrelease候補は、wheel、sdist、Codex Plugin ZIP、管理者用単一Pythonファイルを個別に手作業で集めず、同じsource commitから一括生成します。

```bash
python3.11 -m pip install \
  --require-hashes \
  --only-binary=:all: \
  -r requirements/build.txt
python3.11 scripts/check_build_toolchain.py
python3.11 scripts/build_release_candidate.py \
  --outdir dist/release-candidate \
  --require-clean
```

release builderは`build`、`packaging`、`pyproject-hooks`、`setuptools`、`wheel`が`requirements/build.txt`のexact versionと一致しない環境を拒否します。lockはPython 3.11 / 3.12とmacOS / Linuxで共通のpure Python wheelだけをSHA-256付きで許可し、CIも`--require-hashes --only-binary=:all:`でinstallします。

出力directoryには次の8ファイルだけが入ります。

- Python wheel
- Python sdist
- clean Codex Plugin marketplace ZIP
- `tooluseproxy-authority-admin.py`（自動導入・権限昇格はしない）
- `release-manifest.json`
- CycloneDX 1.7 `*.cdx.json`
- release notes候補
- `SHA256SUMS`

wheel、sdist、Plugin ZIPは同じsource treeから再buildすると同じSHA-256になります。manifestはfull Git commit ID、commit timestamp、dirty状態、Python / Plugin version、artifact role / media type / size / SHA-256、外部確認が必要なgateを記録します。absolute checkout pathやGitの変更file一覧は含めません。

既存候補はnetworkを使わず検証できます。

```bash
python3.11 scripts/build_release_candidate.py \
  --verify dist/release-candidate
```

verifierは次を確認します。

- file setがmanifestで宣言した8ファイルと完全一致する
- symlink、subdirectory、追加fileがない
- `SHA256SUMS`がchecksum file以外をexactに覆う
- manifestのsize / hashと実artifactが一致する
- wheel / sdist / Plugin manifestのversionが一致する
- CycloneDX SBOMのcomponentとartifact hashがmanifestに一致する
- archive内部にunsafe path、重複entry、symlink等の非regular type、危険mode、想定外実行file、過大展開がない

`artifact_set_eligible`はclean sourceとLICENSEの両方が揃った場合だけtrueになります。green CI run、manual Hook trust、実Codex task dogfood、公開承認はlocal builderから推測せず`external_required`のまま残します。candidate生成はGit tag、GitHub Release、repository公開を行いません。

GitHub Actionsの`Reproducible release candidate` jobでも、SHA固定したAction、`contents: read`権限、credentialを保持しないcheckout、hash-locked build toolchainを使い、clean checkoutに対して同じbuildとoffline検証を行います。local候補を公開判断へ進める場合は、そのsource commitに対応するgreen jobを外部CI evidenceとして確認します。

候補directoryは[Pluginライフサイクル](Pluginライフサイクル.md)の`--candidate`へ渡し、immutable baselineからのupgrade / rollback / disable / removeにも同じ検証済みartifactを使えます。

SBOMはCycloneDX 1.7 JSONを使い、ToolUseProxy applicationと4つの配布artifactをSHA-256付きcomponentとして記録します。runtime third-party dependencyは現在ありません。build / test dependencyはrelease artifactへ同梱されないため、release SBOMのruntime componentには含めません。


新しいmanifestはschema_version 2。管理者用ファイルはwheel内のauthority_state.pyと
 authority_admin.pyから再生成したbyte列との一致も検証する。単体のhash再計算だけでは
差替えを受け入れない。過去の3 artifactを持つschema_version 1候補の検証も維持するが、
その候補に管理者用Unsetupが含まれるとは扱わない。管理者用ファイルの導入条件は
[Unsetup管理者導入](Unsetup管理者導入.md)を参照する。
