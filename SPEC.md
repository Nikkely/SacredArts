# SacredArts 仕様（MVP 実装版）

この文書は、元の「AI 実装用 最終仕様書」に対して **実際に実装した仕様** と **差異・判断の理由** をまとめたものです。
ツールの入出力の詳細は [docs/tools.md](docs/tools.md)、構成は [docs/architecture.md](docs/architecture.md)、
安全性は [docs/security.md](docs/security.md)、ガイドは [docs/guide-mode.md](docs/guide-mode.md) を参照してください。

## 1. 概要

- 名称: SacredArts — *AI-powered Linux System Call Laboratory* — *Invoke. Observe. Understand.*
- 機能: Execution（syscall 実行）/ Observation（strace による観測）/ Control（seccomp による拒否）/ Guidance（Level 1〜3 の解説）
- 形態: macOS 上の MCP サーバー（stdio）＋ Docker Desktop 上のサンドボックスコンテナ（1 セッション = 1 コンテナ）

## 2. 技術スタック（実際に使用したもの）

| 項目 | 採用 |
|---|---|
| 言語 | Rust stable（edition 2024、確認は 1.99 / コンテナ内 1.100） |
| 非同期 | Tokio 1 |
| MCP | 公式 Rust SDK `rmcp` 3.11（`server`, `macros`, `transport-io`, `schemars`） |
| シリアライズ / スキーマ | serde / serde_json / schemars 1（rmcp 経由） |
| ガイドデータ | YAML（`serde_yaml_ng` 0.10。`serde_yaml` は保守終了のため） |
| syscall | `libc` 0.2 の `syscall(SYS_*)` |
| seccomp | `seccompiler` 0.5（純 Rust、aarch64/x86_64 対応、libseccomp 不要） |
| トレース | strace 6.8（Ubuntu 24.04 パッケージ） |
| コンテナ | Ubuntu 24.04（ビルドは `rust:1-bookworm` のマルチステージ） |
| Docker 操作 | docker CLI（固定引数） |

## 3. 実装したツール

`sandbox_create` `syscall_invoke` `syscall_describe` `trace_get` `policy_set` `sandbox_inspect` `sandbox_destroy` `session_set_guide`（仕様の 8 ツールすべて）。

## 4. 対応 syscall

`getpid` `openat` `read` `write` `close` `mkdirat` `getpriority` `setpriority`（実行可能）、`open`（`syscall_describe` のみ）。

## 5. 主要な仕様（実装の要点）

- **常駐 Runner**: セッション内で常駐し、開いた fd は複数のツール呼び出しにまたがって保持される。
- **fd**: AI に返すのはカーネルが返した本物の fd。AI が指定した fd 番号もそのままカーネルに渡す（未使用なら `EBADF`、上限は `RLIMIT_NOFILE` = 256 で `EMFILE`）。拒否するのは Runner の IPC ソケット 1 本だけ（`reserved_fd`）。
- **バッファ**: テキストは UTF-8、バイナリは base64（`encoding: "base64"`）。1 回 64 KiB まで。NUL バイト可。部分読み込み・部分書き込みはカーネルの戻り値をそのまま返す（Runner は再試行しない）。
- **引数**: SacredArts は制限しない。要求されたパス・フラグ（Linux の全 `O_*` 名と数値）・mode をそのまま `openat`/`mkdirat` に渡し、届く範囲はコンテナ内でカーネルが決める（非 root、読み取り専用ルート FS。書き込めるのは `/workspace` と `/tmp`）。作業ディレクトリは `/workspace`。
- **観測**: Runner を strace の子として起動。要求の前後のマーカー syscall で strace 出力を区切り、requested / observed / lifecycle を別種のイベントとして記録。
- **seccomp**: 名前ベースの deny-list を BPF にコンパイルし、Runner が初期化後に自分へ適用。ポリシー変更は Runner の再作成（新 Runner の健全性確認後に切り替え、失敗時は旧状態を維持）。
- **エラー 3 分類**: 入力検証エラー（`invalid_argument` 等）/ Linux のエラー（ツールは成功、`success: false` と `errno`）/ 実行基盤のエラー（`infrastructure` / `timeout`）。
- **リソース**: セッション数・アイドル・寿命・syscall 実行時間・イベント数・観測行数・I/O サイズに上限。開ける fd の数はカーネル（`RLIMIT_NOFILE`）が決める。

## 6. 仕様からの変更点と理由

| 項目 | 元の仕様 | 実装 | 理由 |
|---|---|---|---|
| プロジェクト名 | SacredCall | **SacredArts**（crate `sacredarts-*`、バイナリ `sacredarts`、イメージ `sacredarts-sandbox`、環境変数 `SACREDARTS_*`、ラベル `io.sacredarts.*`） | プロジェクトオーナーの意向 |
| 起動の規則 | （なし） | 「System Call」/「システムコール」等の呪文があるときだけツールを使うよう、MCP の instructions で AI に指示し、各ツール説明は「instructions の規則に従う」とだけ書く（`SACREDARTS_ACTIVATION=always` で無効化したとき矛盾しないように） | 無関係な会話での誤作動を防ぐため（プロジェクトオーナーの要望）。サーバーはユーザー発言を受け取れないので強制はできない |
| crate 構成 | `sacredarts-runtime` を含む 6 crate | `runtime` の代わりに `sacredarts-core`（共有型）。Docker/セッション管理は `sacredarts-mcp` 内のモジュール。Supervisor は `sacredarts-tracer` のバイナリ | 不要な分割を避けつつ、Linux 専用部分とホスト部分を分離するため。仕様で許可された範囲の変更 |
| Phase の順序 | 2（MCP）→ 3（Guide）→ 4（Observation） | Supervisor を Phase 2 の時点で strace 付きで実装 | ホスト⇔コンテナの IPC と strace の起動は同じ Supervisor が担うため、作り直しを避けた |
| fd 番号 | （仮想ハンドルなら明示） | **仮想ハンドルは使わず、本物の fd。** Runner は IPC ソケットを fd 上限近く（通常 255）へ移し、fd 0 を `/dev/null` にする | 番号の付き方・`EBADF`・`EMFILE` をカーネルの本物の挙動として見せるため。IPC ソケットだけは `reserved_fd` で守る（閉じるとセッションが切れるため） |
| 不正な fd | 「不正な fd」を検証 | アプリでは検証せずカーネルに渡し、カーネルの `EBADF` を返す | アプリ側の柵はカーネルの判断を隠すため |
| フラグ・mode | 主要フラグ | Linux の全 `O_*` 名と数値を受け付け、アクセスモードの矛盾や setuid 等のビットもそのまま渡す。表示は Runner が strace と同じ形にデコード | 値はアーキテクチャ依存なので変換はサンドボックス内で行う |
| errno の名前 | — | glibc の `strerrorname_np` で名前と番号を変換（手書きの表なし）。ポリシーの errno もどの名前でも可 | 表にない errno を `EUNKNOWN` にして隠さないため |
| パスの閉じ込め | `/workspace` 配下に限定 | **閉じ込めない。** パス・フラグを書き換えずカーネルに渡す（`O_NOFOLLOW` の付加、`openat2` による事前解決もしない） | 学習者が見るべきは「カーネルが実際にどう判断するか」であり、アプリ側の柵はそれを隠すため。安全の境界はコンテナ（非 root・読み取り専用ルート FS・ネットワークなし）に置く。Landlock は Docker Desktop のカーネルに無く使えなかった |
| ポリシーの対象 | syscall 名による拒否 | 名前はその syscall 番号だけに対応（`openat` を deny しても `openat2` は対象外） | 名前と番号の対応を正確に保つため |
| `close` 失敗時のハンドル | — | `close` が失敗したら `fcntl(F_GETFD)` で fd の存在を確認し、ハンドル表を実状態に合わせる | seccomp で拒否された `close` は fd を解放しないが、Linux の通常の `close` はエラーでも解放することがあるため |
| `mkdirat` の mode | 例では指定あり | 省略時 `0755` | AI からの呼び出しを簡単にするため（応答・記録には実際の値を表示） |
| `O_CREAT` の mode | — | 省略時は 0 をカーネルに渡す（0000 のファイルができる） | C では不定値になる。アプリで弾かず、決まった値で実際の挙動を見せる |
| `trace_get` | limit とページング | `after_event_id` カーソル、`trace_mode` の上書き、`dropped_events` | 上限付き保持でも取りこぼしを利用者が判断できるように |
| `session_set_guide` | `guide_level` のみ | 任意で `trace_mode` も変更可 | TraceMode を後から切り替える手段が他にないため |
| タイムアウトの検証 | 実行タイムアウト | テストでは `docker exec` で `/workspace` に FIFO を作り、`openat(O_RDONLY)` を待たせて発生させる | MVP の syscall だけでは通常ファイルでブロックが起きないため（AI は FIFO を作れない） |
| Docker 停止の検証 | Docker 停止 | 存在しない `DOCKER_HOST` を指定したサーバーで `docker_unavailable` を確認 | テスト中に Docker Desktop 自体を止めると他の作業に影響するため |

## 7. 検証状況

| 項目 | 状況 |
|---|---|
| ホスト単体テスト（core / guide / tracer パーサ / mcp） | 実施・成功 |
| Linux 単体・統合テスト（Runner、seccomp、パス、fd、フラグ） | Docker 内 Linux（aarch64）と GitHub Actions（x86_64）で実施・成功 |
| 受け入れテスト Test 1〜10（実 MCP サーバー + Docker + イメージ） | 実施・成功（aarch64 / Docker Desktop 29.0.1、x86_64 / GitHub Actions の Ubuntu） |
| clippy（ホスト・Linux） | 警告なし |
| x86_64 | Linux ホストでは CI で全テスト成功。Intel Mac は未検証 |
| Intel Mac / Linux ホスト | 未検証 |

## 8. スコープ外

任意の syscall 番号、任意メモリアクセス、任意コマンド、`fork`/`execve`、`mmap`、ソケット・ネットワーク、eBPF、seccomp user notification、Web UI、クラウド実行、複数ユーザー共有、動的カーネル解析、任意の Docker 設定。
