# SacredArts

*AI-powered Linux System Call Laboratory* — **Invoke. Observe. Understand.**

[English](README.md) | **日本語**

SacredArts は、AI エージェントが Linux のシステムコールを **直接実行（Execution）・観測（Observation）・制御（Control）** し、
その意味を **段階的に解説（Guidance）** する MCP サーバーです。シェルコマンドを実行するサーバーではなく、
システムコールそのものを第一級の操作対象として扱います。

## 目次

- [できること](#できること)
- [アーキテクチャ](#アーキテクチャ)
- [必要条件](#必要条件)
- [セットアップとビルド](#セットアップとビルド)
- [MCP クライアントへの登録](#mcp-クライアントへの登録)
- [使い方](#使い方)
- [ガイドレベル](#ガイドレベル)
- [対応 syscall](#対応-syscall)
- [使用例（実際の出力）](#使用例実際の出力)
- [AI に渡すサンプルプロンプト](#ai-に渡すサンプルプロンプト)
- [テスト](#テスト)
- [セキュリティ上の制約](#セキュリティ上の制約)
- [未対応機能](#未対応機能)
- [ロードマップ](#ロードマップ)
- [License](#license)

## できること

| 機能 | 内容 |
|---|---|
| Execution | `getpid` `openat` `read` `write` `close` `mkdirat` を Docker 上の Linux で実行。fd などの状態はセッション内で保持 |
| Observation | Runner を `strace` の子プロセスとして起動し、カーネルに実際に発行された syscall を観測。AI の要求（requested）と観測（observed）を区別して記録 |
| Control | seccomp-BPF でカーネルレベルに syscall を拒否（例: `mkdirat` → `EPERM`） |
| Guidance | Level 1〜3 で解説の詳しさを切り替え。解説は man-pages ベースの構造化データ（`guides/*.yaml`）と実行結果から生成 |

## アーキテクチャ

```text
AI Agent ──MCP (stdio)──> sacredarts (macOS 上の MCP サーバー, Rust/rmcp)
                             ├─ Tool Handler / Session Manager / Event Store / Guide Engine
                             └─ Docker Backend ──`docker run -i` の stdin/stdout (JSON Lines)──┐
                                                                                             v
Docker Desktop (Linux VM) ── Sandbox Container (1 セッション = 1 コンテナ, Ubuntu 24.04)
   docker-init (PID 1)
    └─ sacredarts-supervisor        … ホストとの IPC、Runner の起動・監視・再作成、strace 出力の切り分け
        └─ strace -ttt -T -y        … 実 syscall の観測（FIFO へ出力）
            └─ sacredarts-runner    … 常駐。syscall 実行、seccomp 適用
                 fd 255 = supervisor への AF_UNIX ソケット（sendto/recvfrom）、fd 0 = /dev/null
```

主な設計判断（詳細は [docs/architecture.md](docs/architecture.md)）:

- **IPC はコンテナの stdin/stdout**。ホストにポートを公開せず、MCP サーバーが終了・クラッシュすると stdin が閉じてコンテナは自ら終了し `--rm` で削除されます。
- **Runner の内部通信は `sendto`/`recvfrom`**。ポリシーで `read`/`write`/`close` を禁止しても Runner の通信は壊れません。
- **観測の対応付けはマーカー syscall**。Runner は各要求の前後に存在しないパスへの `faccessat` を発行し、Supervisor は strace 出力をその区間で切り出します。
- **引数はそのままカーネルへ**。パス、fd 番号、Linux の全 `O_*` フラグ（数値も可）、mode（setuid・sticky ビットも含む）を書き換えずに渡すので、`EBADF`・`EMFILE`・`ENAMETOOLONG`・`EROFS` などはカーネル自身が返します。安全の境界はコンテナです。拒否する fd は Runner と supervisor をつなぐソケット 1 本だけ（`reserved_fd`）です。
- **errno の手書きの表は持たない**。errno の名前と番号の変換は glibc の `strerrorname_np` を使うので、すべての errno が名前で表示され、ポリシーにはどの errno 名でも指定できます。

## 必要条件

- macOS（Apple Silicon を主対象。Intel Mac / Linux ホストでも動作する設計）
- Docker Desktop 4.x 以降（Docker Engine 20.10 以降相当。動作確認は Docker 29.0.1 / linuxkit 6.12, arm64）
- Rust stable（edition 2024。動作確認は 1.99）
- 追加の Docker 設定は不要です（`--privileged` や `seccomp=unconfined` を使いません）

## セットアップとビルド

```sh
git clone <this repository> sacredarts && cd sacredarts

# 1) サンドボックスイメージ（Runner + Supervisor + strace）
docker build -t sacredarts-sandbox:0.1.0 .

# 2) MCP サーバー（macOS ネイティブ）
cargo build --release -p sacredarts-mcp
# => target/release/sacredarts
```

`make image` / `make build` / `make test` / `make e2e` も用意しています（[Makefile](Makefile)）。

## MCP クライアントへの登録

**Claude Code**

```sh
claude mcp add sacredarts -- /absolute/path/to/sacredarts/target/release/sacredarts
```

**Claude Desktop など（JSON 設定）** — [examples/mcp-config.json](examples/mcp-config.json)

```json
{
  "mcpServers": {
    "sacredarts": {
      "command": "/absolute/path/to/sacredarts/target/release/sacredarts",
      "env": { "SACREDARTS_LOG": "info" }
    }
  }
}
```

設定用の環境変数（AI からは変更できません）:

| 変数 | 既定値 | 説明 |
|---|---|---|
| `SACREDARTS_IMAGE` | `sacredarts-sandbox:0.1.0` | サンドボックスイメージ |
| `SACREDARTS_DOCKER` | 自動検出 | docker CLI のパス（PATH、`/usr/local/bin`、`/opt/homebrew/bin`、Docker.app 内を探索） |
| `SACREDARTS_MAX_SESSIONS` | 4 | 同時セッション数の上限（1〜16） |
| `SACREDARTS_IDLE_TIMEOUT_SECS` | 14400（4 時間） | 無操作のセッションを破棄するまでの秒数。`0` で無制限 |
| `SACREDARTS_MAX_LIFETIME_SECS` | 86400（24 時間） | セッションの最大寿命。`0` で無制限 |
| `SACREDARTS_REQUEST_TIMEOUT_MS` | 5000 | 1 回の syscall の実行時間制限 |
| `SACREDARTS_EVENTS_PER_SESSION` | 2000 | 保持するイベント数の上限（古いものから破棄） |
| `SACREDARTS_LOG` | `info` | ログレベル（ログは stderr のみ。stdout は MCP 専用） |
| `SACREDARTS_ACTIVATION` | `incantation` | `incantation`: 呪文（後述）があるときだけ使うよう AI に指示 / `always`: 制限なし |

どの設定でも、MCP サーバー（Claude Code などのセッション）が終了すればサンドボックスは削除されます。

## 使い方

### 呪文（System Call）で起動する

SacredArts は **呪文で起動** します。メッセージに **「System Call」「SystemCall」「システムコール」** のどれか
（大文字小文字・空白の有無は問わない）か「SacredArts」が含まれているときだけ、AI がツールを使うよう指示しています。
普段の会話や、ほかの作業中に syscall の話をしただけでは使いません。呪文で始めた実験を続けている間は、毎回唱え直す必要はありません。

```text
System Call. hello.txt を作って Hello と書いて、ガイドレベル 2 で説明して。
```

> MCP サーバーにはユーザーの発言が届かないため、この規則はサーバー側で強制できません。
> AI への指示（MCP の instructions と各ツールの説明）として伝えており、通常は守られますが絶対ではありません。
> 制限が不要なら `SACREDARTS_ACTIVATION=always` にしてください。

サンドボックスの起動は AI が `sandbox_create` で自動で行います。利用者が用意するのは Docker Desktop の起動だけです。

### ツール一覧

| ツール | 説明 |
|---|---|
| `sandbox_create` | コンテナ作成 → Runner 起動 → ヘルスチェック。`guide_level` / `trace_mode` / `policy` を指定可 |
| `syscall_invoke` | syscall を 1 つ実行。`{"session_id", "name", "args"}` |
| `syscall_describe` | syscall の仕様（サンドボックス不要。`open` と `openat` の違いも説明） |
| `trace_get` | イベント履歴（requested / observed / lifecycle）。`after_event_id` でページング |
| `policy_set` | seccomp 拒否ポリシーを変更（Runner を再作成。`state_reset: true`） |
| `sandbox_inspect` | Runner PID、セッションで開いた fd（パス付き）、作業ディレクトリ、ポリシー、seccomp 状態、ガイドレベル等 |
| `sandbox_destroy` | Runner 終了・コンテナ削除・セッション削除（冪等） |
| `session_set_guide` | ガイドレベル（と任意で trace_mode）を変更。Runner は再作成しない |

詳細な入出力は [docs/tools.md](docs/tools.md) を参照してください。

**エラーの 3 分類**

- `invalid_argument` / `unsupported_syscall` … SacredArts の入力検証で拒否（syscall は未発行）。`isError: true`
- Linux のエラー … syscall が `-1` を返した。**ツールとしては成功**で `success: false`、`errno` に `ENOENT` など
- `infrastructure` / `timeout` … Docker 停止、IPC 断、実行タイムアウトなど。`isError: true`

## ガイドレベル

`guide_level`（説明の詳しさ）と `trace_mode`（表示するイベントの範囲）は独立した設定です。

| Level | 出力 |
|---|---|
| 1（既定） | strace 風の 1 行のみ。例 `openat(AT_FDCWD, "hello.txt", O_WRONLY\|O_CREAT, 0644) = 3` |
| 2 | Level 1 ＋ 初心者向けの短い解説（今回の結果に即した説明） |
| 3 | Level 2 ＋ 目的、C のシグネチャ、各引数の型・意味・今回の値、使用フラグ、戻り値、errno、状態変化、【実測】カーネルに発行された syscall、【一般的な仕様】内部概念、関連 syscall、man page |

| trace_mode | 表示 |
|---|---|
| `requested`（既定） | AI が要求した操作だけ |
| `all` | ＋ strace が観測した実際のカーネル syscall（`# kernel (strace):`） |

Level 3 では「今回実測したこと」と「Linux の一般的な仕様」を見出しで分け、カーネル内部（VFS 等）は観測していないことを明記します。
詳しくは [docs/guide-mode.md](docs/guide-mode.md)。

> **補足:** Level 1 などで表示される `= 3` はカーネルが返した本物の fd です。fd 0〜2 は埋まっている（0 と 1 は `/dev/null`、2 は Runner の stderr）ので、普通のプロセスと同じく最初のファイルは 3 になります。

## 対応 syscall

| syscall | args | 備考 |
|---|---|---|
| `getpid` | なし | コンテナの PID 名前空間での PID |
| `openat` | `dirfd?`（`"AT_FDCWD"` か任意の fd）, `path`, `flags?`（配列・`"O_A\|O_B\|0x80000"`・整数。既定 `O_RDONLY`）, `mode?`（`"0644"` か整数。省略時 0） | Linux の全 `O_*` フラグ（`O_PATH`、`O_TMPFILE`、`O_NONBLOCK`、`O_SYNC`、`O_DIRECT` なども）と数値のビット。カーネルが返した fd を返す |
| `read` | `fd`（任意の整数）, `count`（0〜65536） | `data_text`（UTF-8 のとき）と `data_base64` |
| `write` | `fd`, `data`, `encoding?`（`utf8`/`base64`）, `count?` | 部分書き込みはそのまま返す |
| `close` | `fd`（任意の整数） | |
| `mkdirat` | `dirfd?`, `path`, `mode?`（既定 `"0755"`。どのビットも可） | |
| `open` | —（`syscall_describe` のみ） | `open` と `openat` の違いの説明用 |

カレントディレクトリは `/workspace` です。パスは制限せずそのままカーネルに渡すので、`/etc/passwd` なども開けます（コンテナ内のファイルです）。

## 使用例（実際の出力）

[examples/demo_client.py](examples/demo_client.py)（標準ライブラリのみの MCP クライアント）を実行した出力の抜粋です。

```text
$ python3 examples/demo_client.py target/release/sacredarts

>>> syscall_invoke {"name": "openat", "args": {"path": "/workspace/hello.txt", "flags": ["O_CREAT", "O_WRONLY"], "mode": "0644"}}
openat(AT_FDCWD, "/workspace/hello.txt", O_WRONLY|O_CREAT, 0644) = 3

>>> syscall_invoke {"name": "write", "args": {"fd": 3, "data": "Hello"}}
write(3, "Hello", 5) = 5

>>> syscall_invoke {"name": "close", "args": {"fd": 3}}
close(3) = 0

>>> session_set_guide {"guide_level": 2, "trace_mode": "all"}
guide_level=2 trace_mode=All (runner pid 13 generation 1 unchanged; fds kept)

>>> syscall_invoke {"name": "read", "args": {"fd": 3, "count": 64}}
read(3, "Hello", 64) = 5
# kernel (strace):
  read(3</workspace/hello.txt>, "Hello", 64) = 5 <0.000040>

解説:
read は、fd が指すファイルから最大 count バイトを読み込むシステムコールです。
戻り値は実際に読めたバイト数で、ファイルの終わり（EOF）では 0 になります。
...

>>> policy_set {"deny": ["mkdirat"], "errno": "EPERM"}
Policy applied: deny=["mkdirat"] errno=EPERM. Runner recreated (generation 1 -> 2, pid 20); all fds were closed (state_reset: true).
seccomp: mode=2 filters=2 (Docker's default profile counts as one filter)

>>> syscall_invoke {"name": "mkdirat", "args": {"path": "test", "mode": "0755"}}
mkdirat(AT_FDCWD, "test", 0755) = -1 EPERM (Operation not permitted)
# kernel (strace):
  mkdirat(AT_FDCWD</workspace>, "test", 0755) = -1 EPERM (Operation not permitted) <0.000023>

解説:
...
これはファイルシステムの問題ではありません。現在のポリシーで mkdirat が deny されているため、カーネルの seccomp フィルタが mkdirat の実行前に EPERM を返しました。

>>> trace_get {"limit": 12}
#2 requested req-1 openat(AT_FDCWD, "/workspace/hello.txt", O_WRONLY|O_CREAT, 0644) = 3
#3 observed  req-1 openat(AT_FDCWD</workspace>, "/workspace/hello.txt", O_WRONLY|O_CREAT, 0644) = 3</workspace/hello.txt> <0.000055>
#4 requested req-2 write(3, "Hello", 5) = 5
#5 observed  req-2 write(3</workspace/hello.txt>, "Hello", 5) = 5 <0.000051>
```

`requested` は AI の要求（fd 3）、`observed` は strace が独立に見たカーネルへの実際の呼び出し（実 fd とそのパス）です。
SacredArts はパスやフラグを書き換えないので、両者は同じ syscall の 2 つの見え方になります。全文は [examples/demo-output.txt](examples/demo-output.txt)。

## AI に渡すサンプルプロンプト

[examples/prompts.md](examples/prompts.md) にもまとめています。

- 「Linux のシステムコールだけを使ってファイルを作成して。ガイドレベル 3 で、各引数の意味も教えて。」（「システムコール」が呪文になっています）
- 「System Call. mkdirat を禁止した状態でディレクトリ作成を試し、失敗理由を説明して。」
- 「System Call. trace_mode を all にして hello.txt を読み、AI が要求した syscall とカーネルが実際に受け取った syscall の違いを説明して。」
- 「System Call. 同じファイルを 2 回 openat してそれぞれ read し、ファイルオフセットが fd ごとにどう違うか確かめて。」
- 「System Call. open と openat の違いを syscall_describe で調べて、openat で dirfd を使う例を実行して。」

## テスト

```sh
make lint                                 # rustfmt --check と clippy（警告はエラー扱い）
cargo test --workspace                    # macOS: 型・検証・パーサ・ガイド・イベントストアの単体テスト
scripts/linux-test.sh                     # Docker 内の Linux で Runner（seccomp・パス・fd・フラグ含む）等のテスト
docker build -t sacredarts-sandbox:0.1.0 .
cargo test -p sacredarts-mcp --test acceptance -- --ignored --test-threads=1   # 受け入れテスト（Docker 必須）
```

受け入れテスト（[tests/integration/acceptance.rs](tests/integration/acceptance.rs)）は実際の MCP サーバー・Docker Desktop・イメージに対して仕様の Test 1〜10 を検証します。
Docker が必要なため既定では `#[ignore]` になっています。

GitHub Actions（[.github/workflows/ci.yml](.github/workflows/ci.yml)）では、整形・clippy（Linux / macOS）、全テスト（Linux では Runner と seccomp のテストもそのまま実行）、受け入れテスト（Docker）を実行します。

## セキュリティ上の制約

詳細は [docs/security.md](docs/security.md)。

- コンテナ: 非 root（10001）、`--network none`、`--read-only`、`/workspace` と `/tmp` のみ容量制限付き tmpfs（`noexec,nosuid,nodev`）、`--cap-drop ALL`、`no-new-privileges`、CPU 0.5 / メモリ 128MB / PID 32、`nofile` 256、Docker 既定 seccomp プロファイルのまま
- Docker ソケットをマウントしません。AI は Docker の実行オプションを一切指定できません
- パス: **SacredArts は制限しません。** 書き換えずにカーネルへ渡し、届く範囲はコンテナ内でカーネルが決めます（`/etc/passwd` は読める、`/etc/shadow` は `EACCES`、`/etc` への作成は `EROFS` など）。見えるのはコンテナ内のファイルで、Mac のファイルではありません
- Docker は完全な隔離手段ではありません。コンテナは Docker Desktop の Linux VM 上で動き、カーネルは共有されます
- seccomp ポリシーは学習用の制御であり、Runner 自体（信頼されたコード）に対するセキュリティ境界ではありません

## 未対応機能

仕様のスコープ外として実装していません: 任意の syscall 番号の呼び出し、任意メモリアクセス、任意コマンド実行、`fork`/`execve`、`mmap`、ソケット・ネットワーク、eBPF、seccomp user notification、Web UI、クラウド実行、複数ユーザー共有、任意の Docker 設定。

既知の制限:

- amd64（x86_64）は Linux ホストで CI（GitHub Actions）の全テストが通っています。Intel Mac での実行は未検証です
- 観測は strace によるもので、カーネル内部の動作は観測しません

## ロードマップ

- syscall の追加: `lseek` `pread64`/`pwrite64` `fstat`/`newfstatat` `unlinkat` `renameat2` `dup`/`dup3` `pipe2` `getdents64`
- プロセス管理（`clone`/`execve`/`wait4`）、メモリ管理（`mmap`/`brk`）、ネットワーク（`socket` 系）を隔離を保ったまま段階的に
- seccomp の引数条件付きルール、seccomp user notification による対話的な許可
- eBPF（tracepoint / kprobe）によるカーネル内部イベントの観測
- 学習機能: 課題（クエスト）モード、fd テーブルやオフセットの可視化、Web UI

## License

SacredArts is dual-licensed under either of:

- MIT License ([LICENSE-MIT](LICENSE-MIT))
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))

at your option.
