# AI エージェント向けサンプルプロンプト

SacredArts を MCP サーバーとして登録したクライアント（Claude Code など）にそのまま渡せます。

SacredArts は **呪文で起動** します。メッセージに「System Call」「SystemCall」「システムコール」のどれかを含めてください
（含まれていないと AI はツールを使いません。`SACREDARTS_ACTIVATION=always` で無効化できます）。
始めた実験の続きでは、唱え直さなくても使えます。

## 入門

1. 「Linux のシステムコールだけを使ってファイルを作成して。ガイドレベル 3 で、各引数の意味も教えて。」
   - 期待される流れ: `sandbox_create(guide_level=3)` → `openat(O_CREAT|O_WRONLY)` → `write` → `close`
2. 「System Call. hello.txt に Hello と書いてから、もう一度開いて読み戻して。ガイドレベルは 2 で。」
3. 「System Call. getpid を呼んで、コンテナの PID 名前空間について説明して。」

## 観測（Observation）

4. 「System Call. trace_mode を all にして hello.txt を読み、AI が要求した syscall とカーネルが実際に受け取った syscall の違いを説明して。」
   - AI の要求（fd）と、strace が独立に観測したカーネル側の呼び出し（実 fd とそのパス）が並んで見えます。
5. 「System Call. これまでの trace_get の結果を requested と observed に分けて表にして。」

## 制御（Control）

6. 「System Call. mkdirat を禁止した状態でディレクトリ作成を試し、失敗理由を説明して。」
   - `policy_set(deny=["mkdirat"])` → `mkdirat` が `-1 EPERM`。strace にも `mkdirat(...) = -1 EPERM` が出るので、カーネルの seccomp による拒否だと確認できます。
7. 「System Call. write を EACCES で禁止して、ファイルに書き込もうとしたらどうなるか見せて。その後ポリシーを外して成功させて。」

## 応用

8. 「System Call. 同じファイルを 2 回 openat して別々に read し、ファイルオフセットが fd ごとに独立していることを確かめて。」
9. 「System Call. open と openat の違いを syscall_describe で調べて、ディレクトリを O_DIRECTORY で開いて dirfd として使う例を実行して。」
10. 「System Call. /etc/passwd、/etc/shadow を開き、/etc/new.txt を O_CREAT で作ろうとして、それぞれの結果（成功・EACCES・EROFS）をカーネルの判断として説明して。」
11. 「System Call. 自分のサンドボックスから Mac 側のファイルに届くか調べたい。/ を開いて、/proc/self/mountinfo を read して、何が見えているか説明して。」
11. 「System Call. close した fd にもう一度 read するとどうなる？ 実際に試して。」
