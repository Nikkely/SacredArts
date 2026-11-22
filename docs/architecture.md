# アーキテクチャ

## 全体像

```text
AI Agent
   │ MCP (stdio, JSON-RPC)        ← stdout は MCP 専用。ログは stderr
   v
sacredarts  (macOS, crates/sacredarts-mcp)
   ├─ server.rs   Tool Handler（rmcp の #[tool_router]）
   ├─ session.rs  Session Manager（上限・アイドル/寿命タイムアウト・孤立コンテナ掃除）
   ├─ store.rs    Event Store（requested / observed / lifecycle、上限付きリングバッファ）
   ├─ guide       Guide Engine（crates/sacredarts-guide + guides/*.yaml）
   └─ docker.rs   Docker Backend（固定の `docker run` 引数のみ）
        │ `docker run -i --rm ...` の stdin/stdout（JSON Lines）
        v
Docker Desktop Linux VM ── Sandbox Container (Ubuntu 24.04, uid 10001)
   docker-init (PID 1, --init)
    └─ sacredarts-supervisor        (crates/sacredarts-tracer/src/supervisor.rs)
        ├─ /tmp/trace-<gen>.fifo  ← strace -o
        └─ strace -ttt -T -y -s 64 -qq -- sacredarts-runner --policy <json>
            └─ sacredarts-runner    (crates/sacredarts-runner)
                 fd 0: AF_UNIX socketpair（Supervisor 側の相手）
                 cwd: /workspace（パスは書き換えずにカーネルへ）
                 学習用ハンドル表、seccomp フィルタ
```

## クレート構成

| クレート | 役割 | 実行環境 |
|---|---|---|
| `sacredarts-core` | 共有型: syscall 要求と入力検証、IPC メッセージ、ポリシー型、GuideLevel/TraceMode、上限値、strace 風フォーマット | どこでも |
| `sacredarts-policy` | ポリシー → seccomp-BPF のコンパイルと適用（seccompiler、`libc::SYS_*` でアーキテクチャ別の番号） | Linux |
| `sacredarts-runner` | 常駐 Runner（syscall 実行、ハンドル表、安全なパス解決、マーカー） | Linux |
| `sacredarts-tracer` | strace 出力パーサ（どこでも）と Supervisor バイナリ（Linux） | 両方 |
| `sacredarts-guide` | ガイドデータの読み込みと Level 1〜3 のレンダリング | どこでも |
| `sacredarts-mcp` | MCP サーバー本体 | ホスト |

仕様の `sacredarts-runtime` は独立クレートにせず、共有型を `sacredarts-core`、Docker/セッション管理を `sacredarts-mcp` のモジュールにしました（過度な分割を避けるため）。

## ホスト ⇔ Supervisor の通信

候補（docker attach の stdio / Unix socket / ローカル RPC）を検証し、**`docker run -i` の stdin/stdout** を採用しました。

- Docker Desktop for Mac では VM 内の Unix socket をホストから直接扱えないため、socket 方式はボリューム共有か TCP 公開が必要になります。stdio ならポート公開もホストのディレクトリ共有も不要です。
- MCP サーバーが終了・クラッシュするとパイプが閉じ、Supervisor は stdin の EOF を検知して終了します。`--rm` によりコンテナも削除されます（受け入れテスト t10 で SIGKILL 時の自動削除を確認）。
- メッセージは 1 行 1 JSON（最大 4 MiB）。要求ごとに ID を付け、応答 ID を照合します。
- タイムアウト: Supervisor 側が syscall ごとの制限（既定 5 秒）を持ち、ホスト側はそれ＋15 秒で IPC 自体の停止を判定します。IPC が死んだセッションは破棄して `sandbox_terminated` を返します。

## Supervisor ⇔ Runner の通信

- `socketpair(AF_UNIX, SOCK_STREAM)` の片側を Runner の fd 0 にして起動します（strace はこの fd をそのまま子に渡します）。
- Runner は `recv(2)`/`send(2)`（カーネル上は `recvfrom`/`sendto`）だけで通信します。学習ポリシーで deny できるのは MVP の 6 syscall のみなので、内部通信は決して止まりません（Runner の統合テスト `denying_io_syscalls_does_not_break_ipc` で確認）。

## 観測（strace）とイベントの切り分け

1. Runner は要求を処理する直前と直後に `faccessat(AT_FDCWD, "/.sacredarts-marker/{begin|end}/<id>", F_OK)` を発行します（常に `ENOENT`、副作用なし）。
2. strace は FIFO に 1 行ずつ書き出し、Supervisor のスレッドが読み取ります。
3. 応答を受けた Supervisor は begin〜end の間の行だけを、その要求の Observed Event とします。IPC の `recvfrom`/`sendto` やマーカー自体は含みません。
4. strace は syscall の exit を処理してから tracee を再開するため、end マーカーの行は Runner の応答送信より先に出力されます。2 秒以内に end が来なければ `observation.status = "incomplete"` とし、推定で補いません。

起動時の `prctl(PR_SET_NO_NEW_PRIVS)` と `seccomp(SECCOMP_SET_MODE_FILTER, ...)` の行は `seccomp_evidence` として保存し、seccomp が実際に適用されたことの証拠にします。

strace が使えない環境では Runner を strace なしで起動し、`tracing.state = "unavailable"`（理由付き）を返します。Observed Event は空になり、観測済みであるかのような表示はしません。

## 3 つの視点

| 視点 | 出所 | 例 |
|---|---|---|
| requested | AI の要求（ホストが記録） | `openat(AT_FDCWD, "/workspace/hello.txt", O_WRONLY\|O_CREAT, 0644) = 3` |
| runner_issued | Runner の自己申告（実 fd 表示） | `openat(AT_FDCWD, "/workspace/hello.txt", O_WRONLY\|O_CREAT, 0644) = 3` |
| observed | strace（独立した観測） | `openat(AT_FDCWD</workspace>, "/workspace/hello.txt", ...) = 3</workspace/hello.txt> <0.000038>` |

requested と observed は `request_id` で関連付けます。パスやフラグは書き換えないので通常は 1 対 1 ですが、`close` の失敗後の状態確認（`fcntl`）のように Runner が追加で発行するものもあり、それも別の行として見えます。

## 状態管理

- **1 セッション = 1 コンテナ = 1 Supervisor**。Runner はセッション内で常駐し、ツール呼び出しごとに再起動しません。
- **学習用ハンドル**: `openat` 成功時に 3 以上の空き最小番号を割り当て、実 fd と対応付けます（上限 64）。ハンドル 0〜2 や未使用番号はカーネルに渡す前に `bad_handle` で拒否します（Runner の IPC ソケットなど内部 fd を守るため）。
- **Runner の再作成**: `policy_set`、syscall タイムアウト、Runner の異常終了で再作成します（`generation` が増え、ハンドルは失われます＝`state_reset: true`）。`session_set_guide` では再作成しません。
- **ポリシー変更の原子性**: 新しい Runner を起動して ping が通ってから旧 Runner を終了し、ホスト側のポリシーもその応答を受けてから更新します。失敗時は旧 Runner と旧ポリシーのまま `policy_apply_failed`（`policy_unchanged: true`）を返します。
- **並行性**: セッションごとに tokio の Mutex で直列化します。別セッションは並行に動きます。`sandbox_destroy` はこの Mutex を待たずにセッションを登録から外し `docker rm -f` するので、ハングした要求があっても破棄できます。

## リソース管理

| 対象 | 上限 / 処理 |
|---|---|
| セッション数 | 既定 4（作成中のものも数える） |
| アイドル | 既定 4 時間でホストが破棄（`0` で無制限）。Supervisor 側にも +60 秒のウォッチドッグ |
| 寿命 | 既定 24 時間（同上） |
| syscall の実行時間 | 既定 5 秒。超過で Runner を kill → 再作成し `syscall_timeout` |
| イベント | セッションあたり 2000 件（古いものから破棄し `dropped_events` で通知） |
| 1 要求の観測行 | 256 行（超過分は `truncated: true`） |
| パス | 制限なし（コンテナ内でカーネルが判断。[security.md](security.md#2-パスsacredarts-は制限しない)） |
| read/write | 1 回 64 KiB |
| 孤立コンテナ | 起動時にラベル `io.sacredarts.host-pid` のプロセスが存在しないものを削除 |
| 終了時 | stdin が閉じたら全セッションを破棄 |

## アーキテクチャ依存の扱い

- syscall 番号、`O_*` フラグ値、errno 名はすべて `libc` クレートのターゲット別定数から得ます（例: `O_DIRECTORY` は x86_64 と aarch64 で値が異なる）。
- requested syscall は libc のラッパーを介さず `syscall(SYS_<name>, ...)` で発行するため、カーネルが受け取る番号が確定します（glibc の `mkdir()` は x86_64 では `mkdir` を使いますが、SacredArts は常に `mkdirat`）。
- seccompiler の `TargetArch` はビルドターゲットから選びます（aarch64 / x86_64）。フィルタにはアーキテクチャ検査が含まれ、異なる ABI の syscall はプロセスを kill します。
- 動作確認済み: aarch64（Docker Desktop on Apple Silicon）。x86_64 は `cargo check --target x86_64-unknown-linux-gnu` のみ確認。

## 検証済みの環境事実（Docker Desktop 29.0.1 / linuxkit 6.12.54 / arm64）

- 非 root、`--cap-drop ALL`、`no-new-privileges`、Docker 既定 seccomp プロファイルのままで、strace が自分の子プロセスを trace できる（`CAP_SYS_PTRACE` 不要。linuxkit には Yama がない）。
- Docker 既定プロファイルは `ptrace`、`seccomp`、`close_range`、`faccessat` を許可している。
- Docker Desktop のカーネルには Landlock（非特権でファイルアクセス範囲を制限する LSM）が入っていない（`landlock_create_ruleset` が `ENOSYS`。seccomp=unconfined でも同じ）。
- Runner が自分でフィルタを追加すると `/proc/<pid>/status` の `Seccomp_filters` が 1 → 2 になる（既定プロファイルが 1 個目）。
- seccomp で拒否された syscall も strace には `mkdirat(...) = -1 EPERM (Operation not permitted)` と表示される（ptrace の syscall-entry 停止の後に seccomp が評価されるため）。
- strace の `-o FIFO` 出力は行単位で即座に読める。
