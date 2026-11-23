# ガイドモード

## 2 つの独立した設定

| 設定 | 何を決めるか | 値 |
|---|---|---|
| `guide_level` | 説明の **詳しさ** | 1 / 2 / 3（既定 1） |
| `trace_mode` | 表示する **イベントの範囲** | `requested`（既定）/ `all` |

`sandbox_create` で指定し、`session_set_guide` でいつでも変更できます（Runner は再作成されず、fd などの状態は保たれます）。
同じ実行結果に対して、ガイドレベルを変えても変わるのは表示の詳細度だけです（受け入れテスト t05）。

## Level 1 — 発行した syscall だけ

```text
openat(AT_FDCWD, "/workspace/hello.txt", O_WRONLY|O_CREAT, 0644) = 3
```

strace に似た 1 行だけを表示し、解説文は出しません。構造化レスポンスにはイベント ID、errno、fd の情報などがすべて入っています。
`= 3` はカーネルが返した本物の fd です（[tools.md](tools.md#fd-について)）。

## Level 2 — 短い解説

Level 1 に続けて `解説:` を付けます。内容は

1. その syscall の短い説明（YAML の `description`）
2. 今回の結果に即した説明（YAML の `explain.success` / `explain.failure` テンプレートに実際の値を埋め込む）
3. 失敗時の理由:
   - ポリシーで deny された場合 → 「カーネルの seccomp フィルタが実行前に EPERM を返した」
   - それ以外 → YAML の `errors` にある errno の説明

```text
openat(AT_FDCWD, "hello.txt", O_RDONLY) = 3

解説:
openat はファイルを開くためのシステムコールです。成功するとファイルディスクリプタ（fd）という番号が返り、
以降の read・write・close ではこの番号でファイルを指定します。

今回は `hello.txt` をオープンし、読み込み専用で利用できる状態にしています。
戻り値の `3` はファイルディスクリプタです（カーネルが返した値そのもの）。
以降の read・write・close ではこの `3` を指定します。
```

## Level 3 — 詳細

Level 2 に続けて次の節を出します。

| 節 | 出所 |
|---|---|
| 目的 | YAML `purpose` |
| C の関数シグネチャ | YAML `signature` |
| 引数（今回の値） | YAML `arguments`（型・意味）＋ 今回の要求の値 |
| 使用したフラグ | YAML `flags` から今回使ったもの |
| 戻り値 | 今回の値（openat はカーネルが返した fd）＋ YAML `return_value` |
| errno | 今回の errno ＋ YAML `errors`（起こりうる主な errno） |
| 実行による状態変化 | 今回（実測）: fd テーブルへの追加・削除 ＋ 一般: YAML `state_changes` |
| 【実測】カーネルに発行された syscall | Runner の自己申告と strace の観測 |
| 【一般的な仕様】関連する Linux の内部概念 | YAML `concepts`（VFS、fd テーブル、オープンファイル記述、パス解決、パーミッションなど） |
| 補足 | 実行時の注記 ＋ YAML `notes` |
| 関連する syscall / 参考 man page | YAML `related` / `man_pages` |

### 実測と一般論の区別

- 「今回（実測）」「【実測】」は、この実行で実際に得た値（戻り値、errno、Runner が発行した syscall、strace の観測）だけです。
- 「一般」「【一般的な仕様】」は man-pages に基づく一般的な説明で、見出しの直後に
  「SacredArts はカーネル内部（VFS 等）を直接観測していません」と明記します。
- strace が使えない環境では「strace による観測: このサンドボックスでは利用できません」と表示し、観測結果を作り出しません。

## trace_mode

- `requested`: AI が要求した操作だけを表示。
- `all`: 各レベルの 1 行目の後に、strace が観測した syscall を `# kernel (strace):` として追加。`trace_get` でも observed イベントを含めます。

```text
openat(AT_FDCWD, "hello.txt", O_RDONLY) = 3
# kernel (strace):
  openat(AT_FDCWD</workspace>, "hello.txt", O_RDONLY) = 3</workspace/hello.txt> <0.000066>
```

## ガイドデータ（`guides/*.yaml`）

解説は AI の自由な推測ではなく、Linux man-pages を主な参照元とした構造化データから生成します。
YAML はビルド時にバイナリへ埋め込まれ、単体テストで全ファイルの読み込みと必須項目を検証しています。

```yaml
name: openat              # ファイル名と一致必須
executable: true          # false なら syscall_describe 専用（open）
category: filesystem
summary: ファイルを開く（必要なら作成する）
description: |            # Level 2 の説明
purpose: |                # Level 3「目的」
signature: |              # C のシグネチャ
arguments:                # name / type / description
  - name: dirfd
    type: int
    description: ...
return_value: |
errors:                   # name / description
flags:                    # name / description
concepts:                 # name / description（一般的な内部概念）
state_changes: []         # 一般的な状態変化
related: [read, write, close]
man_pages: ["openat(2)", "path_resolution(7)"]
explain:                  # Level 2 の結果説明テンプレート
  success: "戻り値の `{ret}` は ..."
  failure: "エラーは `{errno}`（{errno_message}）です。"
notes: []                 # 補足（open と openat の違いなど）
```

テンプレートで使える値: `{ret}` `{real_fd}` `{errno}` `{errno_message}` `{path}` `{flags_ja}` `{mode}` `{fd}` `{count}` `{eof_note}` `{partial_note}`（syscall により異なる）。

収録: `getpid` `openat` `read` `write` `close` `mkdirat`（実行可能）、`open`（説明のみ）。
