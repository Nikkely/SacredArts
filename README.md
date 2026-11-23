# SacredArts

*AI-powered Linux System Call Laboratory* — **Invoke. Observe. Understand.**

**English** | [日本語](README.ja.md)

SacredArts is an MCP server that lets an AI agent **execute**, **observe** and **control** Linux system calls directly,
and **explain** what they mean at the level of detail you choose. It is not a shell-command runner:
system calls themselves are the first-class objects you work with.

## Contents

- [What it does](#what-it-does)
- [Architecture](#architecture)
- [Requirements](#requirements)
- [Setup and build](#setup-and-build)
- [Registering with an MCP client](#registering-with-an-mcp-client)
- [Usage](#usage)
- [Guide levels](#guide-levels)
- [Supported syscalls](#supported-syscalls)
- [Example (real output)](#example-real-output)
- [Sample prompts](#sample-prompts)
- [Testing](#testing)
- [Security](#security)
- [Not supported](#not-supported)
- [Roadmap](#roadmap)
- [License](#license)

## What it does

| Capability | Description |
|---|---|
| Execution | Runs `getpid` `openat` `read` `write` `close` `mkdirat` `getpriority` `setpriority` `fork` `kill` `wait4` `sched_setaffinity` `sched_getaffinity` on Linux inside Docker. State such as open fds persists within a session |
| Observation | The runner is started as a child of `strace`, so the syscalls that actually reached the kernel are observed. What the AI requested (requested) and what was observed (observed) are recorded separately |
| Control | Denies syscalls at the kernel level with seccomp-BPF (e.g. `mkdirat` → `EPERM`) |
| Guidance | Explanation detail switches between levels 1–3. Explanations are generated from structured data based on the Linux man-pages (`guides/*.yaml`) plus the actual result |

## Architecture

```text
AI Agent ──MCP (stdio)──> sacredarts (MCP server on macOS, Rust/rmcp)
                             ├─ Tool Handler / Session Manager / Event Store / Guide Engine
                             └─ Docker Backend ──stdin/stdout of `docker run -i` (JSON Lines)──┐
                                                                                             v
Docker Desktop (Linux VM) ── Sandbox Container (1 session = 1 container, Ubuntu 24.04)
   docker-init (PID 1)
    └─ sacredarts-supervisor        … IPC with the host; starts/monitors/recreates the runner; splits strace output
        └─ strace -ttt -T -y        … observes real syscalls (writes to a FIFO)
            └─ sacredarts-runner    … long-lived; executes syscalls, applies seccomp
                 fd 255 = AF_UNIX socket to the supervisor (sendto/recvfrom); fd 0 = /dev/null
```

Key design decisions (details in [docs/architecture.md](docs/architecture.md), Japanese):

- **IPC uses the container's stdin/stdout.** No ports are published. If the MCP server exits or crashes, stdin closes, the container exits by itself and `--rm` removes it.
- **The runner talks over `sendto`/`recvfrom`.** Denying `read`/`write`/`close` with a policy never breaks the runner's own communication.
- **Observations are attributed with marker syscalls.** Before and after each request the runner issues `faccessat` on a non-existent path; the supervisor cuts the strace output at those markers.
- **Arguments are passed to the kernel verbatim.** Paths, fd numbers, every `O_*` flag (or raw numbers), and modes (including setuid/sticky bits) go to the kernel unchanged, so `EBADF`, `EMFILE`, `ENAMETOOLONG`, `EROFS` and friends come from the kernel itself. The container is the safety boundary. The only fd that is refused is the runner's own socket to the supervisor (`reserved_fd`).
- **No hand-written tables for errno.** errno names (both directions) come from glibc's `strerrorname_np`, so every errno is shown by name and any errno name can be used in a policy.

## Requirements

- macOS (Apple Silicon is the primary target; Intel Macs and Linux hosts are supported by design)
- Docker Desktop 4.x or later (Docker Engine 20.10+; verified with Docker 29.0.1 / linuxkit 6.12, arm64)
- Rust stable (edition 2024; verified with 1.99)
- No extra Docker configuration (no `--privileged`, no `seccomp=unconfined`)

## Setup and build

```sh
git clone <this repository> sacredarts && cd sacredarts

# 1) Sandbox image (runner + supervisor + strace)
docker build -t sacredarts-sandbox:0.1.0 .

# 2) MCP server (native macOS binary)
cargo build --release -p sacredarts-mcp
# => target/release/sacredarts
```

`make image` / `make build` / `make lint` / `make test` / `make e2e` are also available ([Makefile](Makefile)).

## Registering with an MCP client

**Claude Code**

```sh
claude mcp add sacredarts -- /absolute/path/to/sacredarts/target/release/sacredarts
```

**Claude Desktop etc. (JSON config)** — [examples/mcp-config.json](examples/mcp-config.json)

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

Configuration environment variables (the AI cannot change these):

| Variable | Default | Description |
|---|---|---|
| `SACREDARTS_IMAGE` | `sacredarts-sandbox:0.1.0` | Sandbox image |
| `SACREDARTS_DOCKER` | auto-detected | Path to the docker CLI (searches PATH, `/usr/local/bin`, `/opt/homebrew/bin`, Docker.app) |
| `SACREDARTS_MAX_SESSIONS` | 4 | Maximum concurrent sessions (1–16) |
| `SACREDARTS_IDLE_TIMEOUT_SECS` | 14400 (4 hours) | Seconds of inactivity before a session is destroyed. `0` = unlimited |
| `SACREDARTS_MAX_LIFETIME_SECS` | 86400 (24 hours) | Maximum session lifetime. `0` = unlimited |
| `SACREDARTS_REQUEST_TIMEOUT_MS` | 5000 | Execution time limit for a single syscall |
| `SACREDARTS_EVENTS_PER_SESSION` | 2000 | Maximum retained events (oldest are dropped first) |
| `SACREDARTS_LOG` | `info` | Log level (logs go to stderr only; stdout is reserved for MCP) |
| `SACREDARTS_ACTIVATION` | `incantation` | `incantation`: tell the AI to use the tools only when the incantation (below) is present / `always`: no restriction |

Whatever the settings, all sandboxes are removed when the MCP server (e.g. the Claude Code session) exits.

## Usage

### Activate with the incantation "System Call"

SacredArts is **activated by an incantation**. The AI is instructed to use the tools only when your message contains
**"System Call"**, **"SystemCall"** or **"システムコール"** (case and spacing don't matter), or "SacredArts".
Ordinary conversation, or merely mentioning syscalls while doing something else, does not trigger it.
Once an experiment has been started with the incantation, you don't need to repeat it for follow-ups.

```text
System Call. Create hello.txt, write "Hello" to it, and explain at guide level 2.
```

> The MCP server never sees your messages, so this rule cannot be enforced server-side.
> It is conveyed to the AI as instructions (the MCP `instructions` and each tool's description). It is normally followed but not guaranteed.
> Set `SACREDARTS_ACTIVATION=always` if you don't want the restriction.

The AI starts the sandbox itself via `sandbox_create`. All you need is Docker Desktop running.

### Tools

| Tool | Description |
|---|---|
| `sandbox_create` | Create a container → start the runner → health check. Accepts `guide_level` / `trace_mode` / `policy` |
| `syscall_invoke` | Execute one syscall. `{"session_id", "name", "args"}` |
| `syscall_describe` | Describe a syscall (no sandbox needed; also explains `open` vs `openat`) |
| `trace_get` | Event history (requested / observed / lifecycle). Paging via `after_event_id` |
| `policy_set` | Change the seccomp deny policy (recreates the runner; `state_reset: true`) |
| `sandbox_inspect` | Runner PID, fds opened in the session (with paths), working directory, policy, seccomp state, guide level, etc. |
| `sandbox_destroy` | Stop the runner, remove the container, forget the session (idempotent) |
| `session_set_guide` | Change the guide level (and optionally trace_mode). Does not recreate the runner |

See [docs/tools.md](docs/tools.md) (Japanese) for full inputs and outputs.

**Three kinds of errors**

- `invalid_argument` / `unsupported_syscall` — rejected by SacredArts' input validation (no syscall issued). `isError: true`
- Linux errors — the syscall returned `-1`. **The tool call succeeds** with `success: false` and `errno` such as `ENOENT`
- `infrastructure` / `timeout` — Docker stopped, IPC lost, execution timeout, etc. `isError: true`

## Guide levels

`guide_level` (how detailed) and `trace_mode` (which events are shown) are independent settings.

| Level | Output |
|---|---|
| 1 (default) | One strace-like line only, e.g. `openat(AT_FDCWD, "hello.txt", O_WRONLY\|O_CREAT, 0644) = 3` |
| 2 | Level 1 + a short beginner-friendly explanation of this particular result |
| 3 | Level 2 + purpose, C signature, each argument's type/meaning/value, flags used, return value, errno, state changes, [measured] syscalls issued to the kernel, [general] internal concepts, related syscalls, man pages |

| trace_mode | Shows |
|---|---|
| `requested` (default) | Only what the AI requested |
| `all` | + the actual kernel syscalls observed by strace (`# kernel (strace):`) |

Level 3 separates "what was measured this time" from "general Linux behavior" under distinct headings, and states explicitly that kernel internals (VFS etc.) are not observed.
Details: [docs/guide-mode.md](docs/guide-mode.md) (Japanese). Explanations are currently written in Japanese.

> **Note:** the `= 3` shown at Level 1 etc. is the real fd the kernel returned. fds 0–2 are taken (fd 0/1 are `/dev/null`, fd 2 is the runner's stderr), so the first file is 3 like in any process.

## Supported syscalls

| syscall | args | Notes |
|---|---|---|
| `getpid` | none | PID in the container's PID namespace |
| `openat` | `dirfd?` (`"AT_FDCWD"` or any fd), `path`, `flags?` (array, `"O_A\|O_B\|0x80000"` or an integer; default `O_RDONLY`), `mode?` (`"0644"` or an integer; 0 if omitted) | Every Linux `O_*` flag (incl. `O_PATH`, `O_TMPFILE`, `O_NONBLOCK`, `O_SYNC`, `O_DIRECT`) plus raw bits. Returns the kernel's fd |
| `read` | `fd` (any int), `count` (0–65536) | `data_text` (when valid UTF-8) and `data_base64` |
| `write` | `fd`, `data`, `encoding?` (`utf8`/`base64`), `count?` | Short writes are reported as-is |
| `close` | `fd` (any int) | |
| `mkdirat` | `dirfd?`, `path`, `mode?` (default `"0755"`; any bits) | |
| `getpriority` | `which?` (`PRIO_PROCESS` (default) / `PRIO_PGRP` / `PRIO_USER` or an int), `who?` (default 0 = caller) | Returns the kernel's raw value `20 - nice` |
| `setpriority` | `which?`, `who?`, `prio` | The kernel clamps out-of-range values to -20..19; lowering nice needs CAP_SYS_NICE |
| `fork` | `child?` (`spin` (default; busy loop) / `sleep` / `exit`), `seconds?` (0–3600, default 60) | Issued as `clone(SIGCHLD)`. Returns the child's PID; the child never returns to the runner and `_exit`s after its program |
| `kill` | `pid`, `sig?` (`"SIGTERM"` (default) / `"SIGKILL"` / `"SIGSTOP"` / `"SIGCONT"` / ... or an int) | |
| `wait4` | `pid?` (default -1), `options?` (`WNOHANG` `WUNTRACED` `WCONTINUED`) | Returns the status and the child's CPU time (rusage). Waiting for a running child without `WNOHANG` hits the 5 s timeout and recreates the runner |
| `sched_setaffinity` | `pid?` (default 0), `cpus` (e.g. `[0]`) | |
| `sched_getaffinity` | `pid?` | Returns the CPU list; the return value is the number of mask bytes copied |
| `open` | — (`syscall_describe` only) | For explaining `open` vs `openat` |

The working directory is `/workspace`. Paths are not restricted and go to the kernel as written, so you can open `/etc/passwd` and the like (files inside the container).

## Example (real output)

Excerpt from running [examples/demo_client.py](examples/demo_client.py) (an MCP client using only the Python standard library).

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
...

>>> policy_set {"deny": ["mkdirat"], "errno": "EPERM"}
Policy applied: deny=["mkdirat"] errno=EPERM. Runner recreated (generation 1 -> 2, pid 20); all fds were closed (state_reset: true).
seccomp: mode=2 filters=2 (Docker's default profile counts as one filter)

>>> syscall_invoke {"name": "mkdirat", "args": {"path": "test", "mode": "0755"}}
mkdirat(AT_FDCWD, "test", 0755) = -1 EPERM (Operation not permitted)
# kernel (strace):
  mkdirat(AT_FDCWD</workspace>, "test", 0755) = -1 EPERM (Operation not permitted) <0.000023>

>>> trace_get {"limit": 12}
#2 requested req-1 openat(AT_FDCWD, "/workspace/hello.txt", O_WRONLY|O_CREAT, 0644) = 3
#3 observed  req-1 openat(AT_FDCWD</workspace>, "/workspace/hello.txt", O_WRONLY|O_CREAT, 0644) = 3</workspace/hello.txt> <0.000055>
#4 requested req-2 write(3, "Hello", 5) = 5
#5 observed  req-2 write(3</workspace/hello.txt>, "Hello", 5) = 5 <0.000051>
```

`requested` is the AI's request (fd 3); `observed` is the call that strace independently saw reach the kernel (real fd and its path).
Because SacredArts does not rewrite paths or flags, the two are two views of the same syscall. Full output: [examples/demo-output.txt](examples/demo-output.txt).

## Sample prompts

More in [examples/prompts.md](examples/prompts.md) (Japanese).

- "System Call. Create a file using only Linux system calls. Use guide level 3 and explain every argument."
- "System Call. Deny mkdirat, try to create a directory, and explain why it fails."
- "System Call. Set trace_mode to all, read hello.txt, and explain the difference between what the AI requested and what the kernel received."
- "System Call. openat the same file twice, read from each, and check how the file offset differs per fd."
- "System Call. Open /etc/passwd and /etc/shadow, try to create /etc/new.txt, and explain what stopped each one."

## Testing

```sh
make lint                                 # rustfmt --check and clippy incl. `pedantic` (warnings are errors; see [workspace.lints] in Cargo.toml)
cargo test --workspace                    # macOS: unit tests for types, validation, parser, guides, event store
scripts/linux-test.sh                     # Linux tests in Docker: runner (seccomp, paths, fds, flags) etc.
docker build -t sacredarts-sandbox:0.1.0 .
cargo test -p sacredarts-mcp --test acceptance -- --ignored --test-threads=1   # acceptance tests (Docker required)
```

The acceptance tests ([tests/integration/acceptance.rs](tests/integration/acceptance.rs)) run the real MCP server against Docker and the image, covering Tests 1–10 of the spec.
They are `#[ignore]` by default because they need Docker.

GitHub Actions ([.github/workflows/ci.yml](.github/workflows/ci.yml)) runs formatting and clippy (Linux / macOS), all tests (on Linux this includes the runner and seccomp tests), and the acceptance tests (Docker).

## Security

Details: [docs/security.md](docs/security.md) (Japanese).

- Container: non-root (10001), `--network none`, `--read-only`, only `/workspace` and `/tmp` are size-limited tmpfs (`noexec,nosuid,nodev`), `--cap-drop ALL`, `no-new-privileges`, CPU 0.5 / memory 128 MB / 32 PIDs, `nofile` 256, Docker's default seccomp profile kept
- The Docker socket is never mounted. The AI cannot specify any Docker option
- Paths: **SacredArts does not restrict them.** They go to the kernel verbatim, and the kernel decides what is reachable inside the container (`/etc/passwd` is readable, `/etc/shadow` gives `EACCES`, creating under `/etc` gives `EROFS`, ...). These are files inside the container, not on your Mac
- Docker is not a perfect isolation boundary. Containers run on Docker Desktop's Linux VM and share its kernel
- The seccomp policy is a learning control, not a security boundary against the runner itself (trusted code)

## Not supported

Out of scope for now: arbitrary syscall numbers, arbitrary memory access, arbitrary command execution, `fork`/`execve`, `mmap`, sockets/networking, eBPF, seccomp user notification, web UI, cloud execution, multi-user sharing, arbitrary Docker settings.

Known limitations:

- amd64 (x86_64): all tests, including the Docker acceptance tests, pass on Linux in CI (GitHub Actions); Intel Macs are unverified
- Observation is via strace; kernel internals are not observed
- Guide explanations are in Japanese only

## Roadmap

- More syscalls: `lseek` `pread64`/`pwrite64` `fstat`/`newfstatat` `unlinkat` `renameat2` `dup`/`dup3` `pipe2` `getdents64`
- Process management (`clone`/`execve`/`wait4`), memory (`mmap`/`brk`), networking (`socket` family), step by step while keeping isolation
- Argument-conditional seccomp rules; interactive approval via seccomp user notification
- Observing kernel-internal events with eBPF (tracepoints / kprobes)
- Learning features: quest mode, visualizing the fd table and offsets, web UI

## License

SacredArts is dual-licensed under either of:

- MIT License ([LICENSE-MIT](LICENSE-MIT))
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))

at your option.
