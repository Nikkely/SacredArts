# セキュリティ

SacredArts は AI に Linux の syscall を実行させます。そのため「何を実行できるか」を MVP の 6 syscall に絞り、
さらに Docker・カーネル機能・アプリケーション検証を重ねて影響範囲を限定しています。
**Docker を完全な隔離手段とはみなしていません。** 以下は多層防御の各層と、残るリスクです。

## 1. AI が操作できる範囲

- 実行できるのは `getpid` `openat` `read` `write` `close` `mkdirat` のみ。名前の完全一致で判定し、それ以外は `unsupported_syscall`。
- 任意の syscall 番号、任意のメモリアドレス、任意のコマンド、`fork`/`execve` は扱いません。
- 引数（fd 番号、フラグ、mode、パス）は **そのままカーネルに渡します**。アプリ側で弾くのは、渡す形にできないもの（パス中の NUL、`data` より大きい `count`）と、IPC で運べない大きさ（read/write 64 KiB、パス 64 KiB）だけです。
  - フラグは Linux の全 `O_*` 名と数値を受け付けます。アクセスモードの組み合わせ（`O_WRONLY|O_RDWR` = 3 など）もそのまま渡します。
  - mode は setuid / setgid / sticky ビットを含めてそのまま渡します（umask の適用や可否はカーネルが決めます）。`O_CREAT` で mode を省略すると 0 を渡します。
  - 空パス・長すぎるパスは `ENOENT` / `ENAMETOOLONG` としてカーネルが返します。
- fd はどの番号でもカーネルに渡し、開いていなければカーネルが `EBADF` を返します。開ける数の上限はカーネルの `RLIMIT_NOFILE`（256、`--ulimit nofile=256`）で、超えると `EMFILE` です。
  - 唯一の例外は Runner と supervisor をつなぐ IPC ソケットです。Runner は起動時にこれを fd の上限近く（通常 255）へ移し、fd 0 を `/dev/null` にします。この 1 本だけは `reserved_fd` で拒否します（閉じるとセッションが切れるため）。
- AI は Docker の実行オプション、イメージ、マウント、環境変数を一切指定できません。サーバー設定（環境変数）は人間が MCP クライアント設定で行います。

## 2. パス（SacredArts は制限しない）

**SacredArts はパスを書き換えず、そのままカーネルに渡します。** `/workspace` への閉じ込め、`O_NOFOLLOW` の自動付加、`openat2` による事前解決はしていません。
学習者が見るのは、普通の Linux プロセスが同じ syscall を発行したときと同じカーネルの反応です。どこまで届くかを決めるのはカーネルで、その安全の境界はコンテナ（§3）です。

- 入力検証は「カーネルに渡せる形か」だけを見ます（NUL を含むパスと、64 KiB を超えるパスだけを拒否。空文字や PATH_MAX 超えはカーネルが `ENOENT` / `ENAMETOOLONG` を返します）。
- 作業ディレクトリは `/workspace` です。相対パスと `AT_FDCWD` はここから解決されます。
- シンボリックリンクは、要求に `O_NOFOLLOW` がない限り追跡されます。

コンテナの中で確認した結果（受け入れテスト t09。uid 10001）:

| 要求 | 結果 | 止めたもの |
|---|---|---|
| `openat("/etc/passwd")` | 成功 | — （誰でも読める） |
| `openat("../etc/hostname")` | 成功 | — （`..` もそのまま解決） |
| `openat("/etc/shadow")` | `EACCES` | ファイルの権限（root 以外は読めない） |
| `openat("/etc/x", O_WRONLY\|O_CREAT)` | `EROFS` | 読み取り専用のルート FS |
| `mkdirat("/usr/x")` | `EROFS` | 同上 |
| `openat("/usr/bin/sh", O_WRONLY)` | `EACCES` | ファイルの権限 |
| `mkdirat("/tmp/t")` | 成功 | — （tmpfs は書き込み可） |

ここに出てくる `/etc/passwd` などは **コンテナ内のファイル**（Ubuntu イメージの中身）で、Mac のファイルではありません。ホストのディレクトリはマウントしていません。

## 3. コンテナ（固定の `docker run` オプション）

```text
docker run -i --rm --pull never --name sacredarts-<id>
  --label io.sacredarts.managed=true --label io.sacredarts.session=<uuid> --label io.sacredarts.host-pid=<pid>
  --hostname sacredarts --network none --ipc none --read-only
  --tmpfs /workspace:rw,nosuid,nodev,noexec,size=16m,uid=10001,gid=10001,mode=0700
  --tmpfs /tmp:rw,nosuid,nodev,noexec,size=16m,uid=10001,gid=10001,mode=0700
  --user 10001:10001 --cap-drop ALL --security-opt no-new-privileges
  --cpus 0.5 --memory 128m --memory-swap 128m --pids-limit 32
  --ulimit nofile=256:256 --ulimit core=0 --log-driver none --init
  sacredarts-sandbox:0.1.0
```

| 項目 | 設定 |
|---|---|
| ユーザー | 非 root（uid/gid 10001） |
| ネットワーク | なし（ループバックのみ、経路なし） |
| ルート FS | 読み取り専用 |
| 書き込み可能 | `/workspace`・`/tmp` の tmpfs（各 16 MB、`noexec,nosuid,nodev`） |
| capability | すべて削除（`CapEff/CapPrm/CapBnd` = 0 を確認） |
| 権限昇格 | `no-new-privileges` |
| seccomp | Docker 既定プロファイルのまま（`unconfined` にしない） |
| 資源 | CPU 0.5、メモリ 128 MB（swap なし）、PID 32、fd 256、コアダンプなし |
| ホスト資源 | Docker ソケット・ホストディレクトリのマウントなし、ポート公開なし、`--privileged` なし |
| 実行時間 | syscall ごとの制限（既定 5 秒）、アイドル 4 時間、寿命 24 時間（既定。ホストと Supervisor の二重。`0` で無制限）。MCP サーバー終了時は必ず削除 |
| 後片付け | `--rm`、ホスト終了時の全削除、stdin EOF での自己終了、起動時の孤立コンテナ削除 |

受け入れテスト t09 で `docker inspect` の `HostConfig` とコンテナ内の `/proc/1/status`・`/proc/net/route`・インターフェース状態を確認しています。

### strace（ptrace）に必要だった権限

- 追加の capability は不要でした。strace は自分が起動した子プロセスを trace するため、同一 uid で `CAP_SYS_PTRACE` なしに動きます（Docker Desktop の linuxkit カーネルには Yama がありません）。
- Docker 既定 seccomp プロファイルはカーネル 4.8 以降で `ptrace` を許可しています。
- Yama の `ptrace_scope` が 2 以上のホストや、`ptrace` を禁止するプロファイルでは strace が失敗します。その場合 Runner は strace なしで起動し、`tracing.state = "unavailable"` と理由を返します（観測していないものを観測したとは表示しません）。

## 4. seccomp ポリシー（学習用の制御）

- deny できるのは MVP の 6 syscall のみ。フィルタは「既定は許可、指定番号は `SECCOMP_RET_ERRNO`」。
- Runner は初期化（IPC ソケットの移動、PID の取得）を終えてからフィルタを適用します。フィルタは不可逆なので、ポリシー変更は Runner の再作成で行います。
- Runner の内部通信（`sendto`/`recvfrom`）、状態確認（`fcntl`）、境界マーカー（`faccessat`）、メモリ管理、終了処理は deny 対象にならない syscall なので、どのポリシーでも Runner は動き続けます。
- seccomp による拒否であることの確認方法:
  1. strace にその syscall が `= -1 EPERM` として現れる（アプリ側の条件分岐なら syscall 自体が出ない）。
  2. Runner 起動時の strace に `seccomp(SECCOMP_SET_MODE_FILTER, ...)` が記録されている（`seccomp_evidence`）。
  3. `/proc/<runner>/status` の `Seccomp_filters` が Docker の既定分より 1 多い。
  4. ポリシーなしの新しい Runner では同じ要求が成功する。

**位置付け:** このフィルタは学習用の制御で、Runner（信頼されたコード）に対するセキュリティ境界ではありません。
例えば x86_64 の x32 ABI の番号は対象外ですが、Runner はそれを使わず、AI は任意の syscall を発行できないため問題になりません。
サンドボックスの安全性は §1〜3 に依存します。

## 5. ホスト側（MCP サーバー）

- ホスト上で Linux の syscall を実行しません。Linux 固有の処理はすべてコンテナ内です。
- stdout は MCP プロトコル専用で、ログは stderr に出します（受け入れテストは stdout の全行が JSON-RPC であることを確認）。
- コンテナから受け取る行は 4 MiB までに制限し、不正な行は無視します。
- セッション ID は UUID v4。セッションごとに状態とイベントを分離しています。

## 6. 残るリスク

- **カーネル共有**: コンテナは Docker Desktop の Linux VM のカーネルを共有します。カーネルの脆弱性があれば隔離を越えられる可能性があります（影響は通常 Docker Desktop の VM 内にとどまります）。
- **Docker Desktop 自体**: Docker Desktop の権限モデルや設定（ファイル共有など）は SacredArts の管理外です。
- **tmpfs の内容**: `/workspace` に書いたデータはコンテナ削除まで VM のメモリに残ります。機密情報を書かないでください。
- **ログ**: `SACREDARTS_LOG=debug` ではサンドボックスの stderr がホストのログに出ます。
- **サンドボックス内の管理用プロセスへの干渉**: パスを制限していないため、Runner と同じ uid の管理用プロセス（docker-init、Supervisor、strace）の `/proc/<pid>/fd/*` を開けます。
  例えば `/proc/1/fd/1`（ホストへの応答路）への書き込みや、`/proc/1/fd/0` からの読み込みで、**自分のセッションの通信を乱したり止めたりできます。**
  ホストは不正な行を無視し（t09 で確認）、応答が止まればタイムアウト後にセッションを破棄します。影響はそのセッション内にとどまり、Mac には届きません。
  strace の出力（FIFO）は推測できない名前にし、開いた直後にパスを削除しています。
- **`/proc/self/mem`**: 開くことはできますが、現在の syscall セット（`lseek`/`pwrite` なし）では読み書き位置を動かせないため、メモリの書き換えには使えません。位置を指定できる syscall を追加するときは再検討が必要です。
- **amd64**: x86_64 の Linux では CI で受け入れテストまで通っています。Intel Mac は未検証です。
- **孤立コンテナ判定**: ラベルの PID がたまたま再利用されている場合、そのコンテナは起動時の掃除対象外になります（ただし stdin EOF と Supervisor のウォッチドッグで自己終了します）。
