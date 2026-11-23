# MCP ツール仕様

## 起動の規則（呪文）

サーバーの instructions と全ツールの説明に、「ユーザーのメッセージに "System Call" / "SystemCall" / "システムコール"（または "SacredArts"）が含まれるときだけツールを使う」という規則を入れています（`SACREDARTS_ACTIVATION=incantation`、既定）。
サーバーはユーザーの発言を見られないため強制ではなく、AI への指示です。`SACREDARTS_ACTIVATION=always` で無効化できます。

---

すべてのツールは `content`（人が読むテキスト＋整形済み JSON）と `structuredContent`（JSON）を返します。
エラー時は `isError: true` と `structuredContent.error = {kind, code, message, details?}` を返します。

| `error.kind` | 意味 | 主な `code` |
|---|---|---|
| `invalid_argument` | 入力検証で拒否（syscall 未発行） | `invalid_path` `invalid_flags` `invalid_mode` `missing_argument` `unknown_argument` `reserved_fd` `invalid_policy` `invalid_guide_level` |
| `unsupported_syscall` | 未対応の syscall 名 | `unsupported_syscall` `unknown_syscall` |
| `session_not_found` | セッションが存在しない | `session_not_found` |
| `limit_exceeded` | 上限超過 | `too_many_sessions` `limit_exceeded` |
| `timeout` | syscall の実行時間超過、IPC 応答なし | `syscall_timeout` `ipc_timeout` |
| `infrastructure` | Docker / IPC / Runner の問題 | `docker_unavailable` `image_missing` `docker_error` `sandbox_terminated` `runner_crashed` `runner_start_failed` `policy_apply_failed` |

**Linux のエラー（errno）はツールエラーではありません。** syscall が `-1` を返した場合は `isError: false`、`success: false`、`errno: {name, code, message}` です。

---

## `sandbox_create`

入力:

```json
{ "guide_level": 2, "trace_mode": "requested", "policy": { "deny": [], "errno": "EPERM" } }
```

すべて省略可（既定: `guide_level` 1、`trace_mode` `"requested"`、ポリシーなし）。

出力（抜粋）:

```json
{
  "session_id": "c30e8a6a-d000-4a4b-bf75-9409b2f879e9",
  "status": "ready",
  "architecture": "aarch64",
  "guide_level": 2,
  "trace_mode": "requested",
  "policy": { "deny": [], "errno": "EPERM" },
  "workspace": "/workspace",
  "container": "sacredarts-c30e8a6a",
  "runner": { "pid": 13, "generation": 1, "pid_namespace": "container" },
  "tracing": { "state": "active", "tool": "strace", "version": "strace -- version 6.8" },
  "seccomp": { "mode": 2, "filters": 1, "sacredarts_filter_installed": false },
  "seccomp_evidence": []
}
```

処理: Docker の疎通・イメージ確認 → コンテナ起動 → Supervisor に初期化を送信 → Runner（strace 配下）起動 → hello 受信までをヘルスチェックとします。

## `syscall_invoke`

入力:

```json
{
  "session_id": "uuid",
  "name": "openat",
  "args": { "path": "/workspace/hello.txt", "flags": ["O_CREAT", "O_WRONLY"], "mode": "0644" }
}
```

syscall ごとの `args`:

| name | args |
|---|---|
| `getpid` | `{}` |
| `openat` | `dirfd?`: `"AT_FDCWD"`（既定）/ `-100` / 任意の fd 番号, `path`: 文字列（絶対・相対どちらも可。書き換えずにカーネルへ渡す）, `flags?`: 配列・`"O_A\|O_B\|0x80000"`・整数のいずれか（既定 `O_RDONLY`）, `mode?`: `"0644"`（8 進文字列）または整数（省略時は 0） |
| `read` | `fd`: 任意の整数, `count`: 0〜65536 |
| `write` | `fd`: 任意の整数, `data`: 文字列, `encoding?`: `"utf8"`（既定）/ `"base64"`, `count?`: 書き込むバイト数（既定は全量、`data` 長以下） |
| `close` | `fd`: 任意の整数 |
| `mkdirat` | `dirfd?`, `path`, `mode?`（既定 `"0755"`。setuid などのビットもそのまま渡す） |
| `getpriority` | `which?`: `"PRIO_PROCESS"`（既定）/ `"PRIO_PGRP"` / `"PRIO_USER"` / 整数, `who?`: 整数（既定 0 = 呼び出し元）。戻り値はカーネルの生の値 `20 - nice` |
| `setpriority` | `which?`, `who?`, `prio`: 任意の整数（カーネルが -20〜19 に丸める） |
| `fork` | `child?`: `"spin"`（既定）/ `"sleep"` / `"exit"`, `seconds?`: 0〜3600（既定 60）。`clone(SIGCHLD)` として発行し、子の PID を返す |
| `kill` | `pid`: 整数, `sig?`: シグナル名（`"SIGKILL"`、`"KILL"` も可）または整数（既定 `SIGTERM`） |
| `wait4` | `pid?`: 整数（既定 -1）, `options?`: `["WNOHANG", ...]`・`"WNOHANG\|WUNTRACED"`・整数。結果の `output` に `status`・`utime_us`・`stime_us` |
| `sched_setaffinity` | `pid?`: 整数（既定 0）, `cpus`: CPU 番号の配列（0〜1023） |
| `sched_getaffinity` | `pid?`: 整数（既定 0）。結果の `output.cpus` に CPU の一覧 |

`flags` に使える名前は Linux の全 `O_*` フラグです: `O_RDONLY O_WRONLY O_RDWR O_CREAT O_EXCL O_NOCTTY O_TRUNC O_APPEND O_NONBLOCK O_NDELAY O_DSYNC O_SYNC O_RSYNC O_ASYNC O_DIRECT O_LARGEFILE O_DIRECTORY O_NOFOLLOW O_NOATIME O_CLOEXEC O_PATH O_TMPFILE`。
名前のないビットは数値（`0x40000000`、C と同じく `0` 始まりは 8 進）で混ぜられます。値はアーキテクチャごとに違うため、名前から値への変換はサンドボックス内（Runner）で行い、`kernel.runner_issued` には strace と同じ形でデコードした結果が出ます。
アクセスモードの矛盾（`O_WRONLY` と `O_RDWR` の同時指定 = 3）や mode の省略も、そのままカーネルに渡します。

未知のキーは `unknown_argument` で拒否します。

出力（`openat` 成功、抜粋）:

```json
{
  "event_id": 2,
  "request_id": "req-1",
  "syscall": "openat",
  "success": true,
  "requested_syscall_executed": true,
  "return_value": 3,
  "errno": null,
  "formatted": "openat(AT_FDCWD, \"/workspace/hello.txt\", O_WRONLY|O_CREAT, 0644) = 3",
  "denied_by_policy": false,
  "handle": {
    "change": "opened", "handle": 3, "real_fd": 3, "path": "/workspace/hello.txt"
  },
  "guide": { "level": 2, "summary": "ファイルを開く（必要なら作成する）", "explanation": "...", "text": "..." },
  "trace_mode": "requested",
  "kernel": {
    "return_value": 3,
    "runner_issued": [
      { "syscall": "openat", "purpose": "requested",
        "args": "AT_FDCWD, \"/workspace/hello.txt\", O_WRONLY|O_CREAT, 0644", "ret": 3, "errno": null }
    ],
    "runner_pid": 13, "runner_generation": 1
  },
  "observation": { "status": "complete", "observed_event_ids": [3], "truncated": false },
  "notes": []
}
```

- `return_value` はカーネルの戻り値そのものです。`openat` ではカーネルが返した fd です（`handle.handle` と `handle.real_fd` は同じ値）。
- `read` では `data_text`（UTF-8 として正しいときのみ、そうでなければ `null`）、`data_base64`（常に）、`bytes_read` が付きます。
- パスとフラグは要求のままカーネルに渡します（`/workspace` への閉じ込めや `O_NOFOLLOW` の付加はしません）。届く範囲はコンテナ内でカーネルが決めます（[security.md](security.md#2-パスsacredarts-は制限しない)）。
- `requested_syscall_executed` は要求された syscall がカーネルに発行されたかどうかです（入力検証を通った要求では常に `true`）。
- `denied_by_policy: true` は、セッションのポリシーがこの syscall を deny しており、返った errno がポリシーの errno と一致したことを示します。
- `trace_mode: "all"` のときは `observation.syscalls` に strace の行が入り、テキストにも `# kernel (strace):` が付きます。

### fd について

Level 1 の `openat(...) = 3` の `3` は **カーネルが返した本物の fd** です。

- Runner の fd 0 は `/dev/null`、1 は `/dev/null`、2 は Runner の stderr（supervisor が診断用に読む）なので、普通のプロセスと同じく最初のファイルは 3 になります。
- どの番号でもカーネルに渡します。開いていない fd には、カーネルが `EBADF` を返します。上限は `RLIMIT_NOFILE`（256）で、超えると `EMFILE` です。
- 例外は Runner と supervisor をつなぐ IPC ソケット（通常 fd 255）だけで、`reserved_fd` で拒否します。閉じるとセッションが切れるためです。
- `sandbox_inspect` の `open_handles` には、このセッションで開いた fd とそのパス・フラグが出ます（表示用の記録で、判定には使いません）。

## `syscall_describe`

入力: `{ "name": "openat", "guide_level": 3 }`（`guide_level` 省略時 1）

サンドボックスなしで使えます。`name` は対応 6 syscall と `open`（説明専用。`executable: false`）。
Level 1: 概要とシグネチャ / Level 2: ＋説明・補足（`open` と `openat` の違いなど）・関連 / Level 3: ＋引数・フラグ・戻り値・errno・状態変化・内部概念・man page（`structuredContent.guide` に YAML の全データ）。

## `trace_get`

入力:

```json
{ "session_id": "uuid", "limit": 50, "after_event_id": 0, "trace_mode": "all" }
```

- `limit`: 1〜500（既定 50）。`after_event_id`: これより大きい ID のイベントを返す（ページング）。
- `trace_mode`: 省略時はセッションの設定。`requested` のときは observed イベントを除きます。

出力: `events`（時系列）、`next_after_event_id`（続きがあるとき）、`oldest_retained_event_id`、`dropped_events`、`retained_events`。

イベント形式:

```json
{
  "event_id": 3,
  "kind": "observed",
  "source": "strace",
  "request_id": "req-1",
  "timestamp": "2026-11-22T03:15:47.186807Z",
  "syscall": "openat",
  "arguments": { "raw": "AT_FDCWD</workspace>, \"/workspace/hello.txt\", O_WRONLY|O_CREAT, 0644" },
  "return_value": { "raw": "3</workspace/hello.txt>", "value": 3 },
  "errno": null,
  "duration_ns": 38000,
  "process": { "pid": 13, "role": "runner", "pid_namespace": "container" },
  "details": { "errno_message": null, "strace_line": "..." },
  "formatted": "openat(AT_FDCWD</workspace>, \"/workspace/hello.txt\", O_WRONLY|O_CREAT, 0644) = 3</workspace/hello.txt> <0.000038>"
}
```

| kind | source | 内容 |
|---|---|---|
| `requested` | `ai_request` | AI の要求。`return_value` は AI 向けの値。`details` に `kernel_return_value`、`handle_change`、`runner_issued`、`requested_syscall_executed`。`duration_ns` は測定していないため `null` |
| `observed` | `strace` | strace が観測した syscall。`timestamp` は strace の `-ttt`、`duration_ns` は `-T` の値 |
| `lifecycle` | `sacredarts` | `sandbox_created` `policy_applied` `guide_changed` `runner_error` |

測定していない値は `null` です。

## `policy_set`

入力: `{ "session_id": "uuid", "deny": ["mkdirat"], "errno": "EPERM" }`

- `deny` は対応 6 syscall の部分集合のみ（それ以外は `unsupported_syscall`）。空配列で制限解除。
- `errno`: Linux の errno 名なら何でも（既定 `EPERM`。`ENOSYS`、`EIO` など）。名前から番号への変換はサンドボックス内の glibc（`strerrorname_np`）で行い、知らない名前なら `invalid_policy`（入力の誤り）で失敗し、元のポリシーが残ります（ホスト側では名前の形を推測で検査しません）。
  別名（`EWOULDBLOCK`、`ENOTSUP`、`EDEADLOCK`）も使えます。カーネルの errno は正式名で報告されるので、ポリシーも正式名（`EAGAIN` など）で保存・表示します。
- Runner を新しい seccomp フィルタ付きで再作成します。**開いていた fd は失われます**（`state_reset: true`）。

出力（抜粋）:

```json
{
  "policy": { "deny": ["mkdirat"], "errno": "EPERM" },
  "previous_policy": { "deny": [], "errno": "EPERM" },
  "state_reset": true,
  "runner": { "pid": 20, "generation": 2, "previous_generation": 1 },
  "seccomp": { "mode": 2, "filters": 2, "sacredarts_filter_installed": true },
  "seccomp_evidence": [
    "... prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) = 0 <...>",
    "... seccomp(SECCOMP_SET_MODE_FILTER, 0, {len=10, filter=0x...}) = 0 <...>"
  ]
}
```

失敗時は旧 Runner・旧ポリシーのまま `policy_apply_failed`（`details.policy_unchanged: true`）。

## `sandbox_inspect`

入力: `{ "session_id": "uuid" }`

出力: `session_id`、`container`、`created_at`、`idle_seconds`、`idle_timeout_seconds`、`max_lifetime_seconds`（無制限なら `null`）、
`runner`（`pid`、`generation`、`architecture`、`seccomp`、`tracing`）、`open_handles`（`handle` → `real_fd`、`path`、`flags`）、
`cwd`（`/workspace`）、`workspace_entries`（直下のエントリ）、`policy`、`guide_level`、`trace_mode`、`event_count`、`requested_event_count`、`observed_event_count`。

## `sandbox_destroy`

入力: `{ "session_id": "uuid" }` → `{ "status": "destroyed" }` または `{ "status": "not_found_or_already_destroyed" }`

Supervisor に終了を依頼（応答がなくても続行）→ `docker rm -f` → セッション情報削除。`/workspace` と `/tmp` は tmpfs なのでコンテナと共に消えます。何度呼んでも成功します。

## `session_set_guide`

入力: `{ "session_id": "uuid", "guide_level": 3, "trace_mode": "all" }`（`trace_mode` は任意）

Runner は再作成しません（`state_reset: false`、開いている fd は維持）。
