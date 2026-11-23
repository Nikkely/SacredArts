//! Guide engine.
//!
//! Explanations are generated from structured data (`guides/*.yaml`, based on
//! the Linux man-pages) plus the *actual* execution result. Nothing here is
//! free-form AI text. Level 3 output separates what was measured in this run
//! (runner self-report, strace observation) from general Linux knowledge.

use sacredarts_core::format::{DISPLAY_BYTES, format_dirfd, format_flags, format_mode, quote_bytes, quote_str};
use sacredarts_core::ipc::{ErrnoInfo, HandleInfo, IssuedCall, IssuedPurpose, Observation, ObservationStatus};
use sacredarts_core::{DecodedFlags, GuideLevel, NICE_MAX, NICE_MIN, OpenFlag, PrioWhich, SyscallRequest, TraceMode};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::OnceLock;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Named {
    pub name: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArgGuide {
    pub name: String,
    #[serde(rename = "type")]
    pub ty: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Explain {
    pub success: String,
    pub failure: String,
}

/// One `guides/<name>.yaml` file.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyscallGuide {
    pub name: String,
    pub executable: bool,
    pub category: String,
    pub summary: String,
    pub description: String,
    pub purpose: String,
    pub signature: String,
    pub arguments: Vec<ArgGuide>,
    pub return_value: String,
    pub errors: Vec<Named>,
    pub flags: Vec<Named>,
    pub concepts: Vec<Named>,
    pub state_changes: Vec<String>,
    pub related: Vec<String>,
    pub man_pages: Vec<String>,
    pub explain: Explain,
    #[serde(default)]
    pub notes: Vec<String>,
}

const BUILTIN: &[(&str, &str)] = &[
    ("getpid", include_str!("../../../guides/getpid.yaml")),
    ("openat", include_str!("../../../guides/openat.yaml")),
    ("open", include_str!("../../../guides/open.yaml")),
    ("read", include_str!("../../../guides/read.yaml")),
    ("write", include_str!("../../../guides/write.yaml")),
    ("close", include_str!("../../../guides/close.yaml")),
    ("mkdirat", include_str!("../../../guides/mkdirat.yaml")),
    ("getpriority", include_str!("../../../guides/getpriority.yaml")),
    ("setpriority", include_str!("../../../guides/setpriority.yaml")),
];

pub struct Guides {
    map: BTreeMap<String, SyscallGuide>,
}

impl Guides {
    /// Parse the guide YAML files compiled into the binary.
    ///
    /// # Errors
    ///
    /// If a file is not valid guide YAML or declares a `name` different from
    /// its file name.
    pub fn parse_builtin() -> Result<Guides, String> {
        let map = BUILTIN
            .iter()
            .map(|(file, text)| {
                let g: SyscallGuide = serde_yaml_ng::from_str(text).map_err(|e| format!("guides/{file}.yaml: {e}"))?;
                if g.name != *file {
                    return Err(format!("guides/{file}.yaml declares name {:?}", g.name));
                }
                Ok((g.name.clone(), g))
            })
            .collect::<Result<_, _>>()?;
        Ok(Guides { map })
    }

    /// Guides compiled into the binary (validated by unit tests).
    ///
    /// # Panics
    ///
    /// If the embedded guide data is invalid ([`Guides::parse_builtin`]
    /// fails). A unit test parses every built-in guide, so this cannot
    /// happen in a tested build.
    pub fn builtin() -> &'static Guides {
        static G: OnceLock<Guides> = OnceLock::new();
        G.get_or_init(|| Guides::parse_builtin().expect("embedded guide data is valid"))
    }

    #[must_use]
    pub fn get(&self, name: &str) -> Option<&SyscallGuide> {
        self.map.get(name)
    }

    pub fn names(&self) -> Vec<&str> {
        self.map.keys().map(String::as_str).collect()
    }
}

/// Everything known about one executed request, from the host's view.
pub struct InvocationView<'a> {
    pub request: &'a SyscallRequest,
    /// strace-like line of the request as the AI sees it, incl. result.
    pub requested_line: String,
    /// false if an internal step failed before the requested syscall.
    pub executed: bool,
    /// Value returned to the AI (the kernel's return value).
    pub ret: i64,
    /// Value the kernel actually returned.
    pub kernel_ret: i64,
    pub errno: Option<&'a ErrnoInfo>,
    /// Handle opened/closed by this request.
    pub handle: Option<&'a HandleInfo>,
    pub read_data: Option<&'a [u8]>,
    pub issued: &'a [IssuedCall],
    pub observation: Option<&'a Observation>,
    pub trace_mode: TraceMode,
    pub notes: &'a [String],
    /// openat: flags as the kernel received them (decoded in the sandbox).
    pub open_flags: Option<&'a DecodedFlags>,
    /// The session policy denies this syscall (so an errno equal to the
    /// policy errno comes from the seccomp filter).
    pub denied_by_policy: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct Rendered {
    pub level: u8,
    pub summary: String,
    /// Level 2+: short beginner explanation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub explanation: Option<String>,
    /// Full text at the requested level.
    pub text: String,
}

/// Describes what the kernel actually received (numeric bits included).
fn access_ja(flags: &DecodedFlags) -> String {
    let mode = if flags.contains(OpenFlag::O_PATH) {
        "読み書きはできず、場所だけを指す（O_PATH）fd として利用できる"
    } else {
        match flags.access_mode {
            2 => "読み書き両用で利用できる",
            1 => "書き込み専用で利用できる",
            3 => "アクセスモード 3 で（読み書きの権限は検査されるが、read も write もできない）利用できる",
            _ => "読み込み専用で利用できる",
        }
    };
    let has = |f| flags.contains(f);
    let open = match (has(OpenFlag::O_CREAT), has(OpenFlag::O_EXCL)) {
        (true, true) => "新規作成し、",
        (true, false) => "作成またはオープンし、",
        (false, _) => "オープンし、",
    };
    let trunc = if has(OpenFlag::O_TRUNC) {
        "中身を空にして、"
    } else {
        ""
    };
    let append = if has(OpenFlag::O_APPEND) {
        "追記モードで、"
    } else {
        ""
    };
    format!("{open}{trunc}{append}{mode}")
}

fn fill(template: &str, v: &InvocationView<'_>) -> String {
    let common = [
        ("ret", v.ret.to_string()),
        (
            "real_fd",
            v.handle
                .map_or_else(|| v.kernel_ret.to_string(), |h| h.real_fd.to_string()),
        ),
        ("errno", v.errno.map_or_default(|e| e.name.clone())),
        ("errno_message", v.errno.map_or_default(|e| e.message.clone())),
    ];
    let specific: Vec<(&str, String)> = match v.request {
        SyscallRequest::Openat {
            path, flags, raw_flags, ..
        } => {
            let decoded = v
                .open_flags
                .cloned()
                .unwrap_or_else(|| DecodedFlags::from_request(flags, *raw_flags));
            vec![("path", path.clone()), ("flags_ja", access_ja(&decoded))]
        }
        SyscallRequest::Mkdirat { path, mode, .. } => vec![("path", path.clone()), ("mode", format_mode(*mode))],
        SyscallRequest::Read { fd, count } => {
            let note = if v.ret == 0 && *count > 0 {
                "0 バイトはファイルの終わり（EOF）に達したことを意味します。"
            } else if usize::try_from(v.ret).is_ok_and(|n| n < *count) {
                "要求より少ない部分読み込みです（エラーではありません）。通常ファイルでは、一般にファイルの残りがそれだけだったことを意味します。"
            } else {
                ""
            };
            vec![
                ("fd", fd.to_string()),
                ("count", count.to_string()),
                ("eof_note", note.to_string()),
            ]
        }
        SyscallRequest::Write { fd, count, .. } => {
            let note = if usize::try_from(v.ret).is_ok_and(|n| n < *count) {
                "要求より少ない部分書き込みです。残りを書くには、続きのデータで write をもう一度呼びます。"
            } else {
                ""
            };
            vec![
                ("fd", fd.to_string()),
                ("count", count.to_string()),
                ("partial_note", note.to_string()),
            ]
        }
        SyscallRequest::Close { fd } => vec![("fd", fd.to_string())],
        SyscallRequest::Getpid => vec![],
        SyscallRequest::Getpriority { which, who } => vec![
            ("which", PrioWhich::display(*which)),
            ("who", who.to_string()),
            // The raw syscall returns 20 - nice.
            ("nice", (20 - v.ret).to_string()),
        ],
        SyscallRequest::Setpriority { which, who, prio } => {
            let effective = (*prio).clamp(NICE_MIN, NICE_MAX);
            let note = if effective == *prio {
                String::new()
            } else {
                format!(
                    "要求値 {prio} は範囲外なので、カーネルは黙って {effective} に丸めました（エラーにはなりません）。"
                )
            };
            vec![
                ("which", PrioWhich::display(*which)),
                ("who", who.to_string()),
                ("prio", prio.to_string()),
                ("effective", effective.to_string()),
                ("clamp_note", note),
            ]
        }
    };
    common
        .into_iter()
        .chain(specific)
        .fold(template.to_string(), |out, (k, val)| {
            out.replace(&format!("{{{k}}}"), &val)
        })
        .trim()
        .to_string()
}

/// Build text with `writeln!(s, ..)?`. Writing to a `String` cannot fail,
/// so the `fmt::Result` only exists to allow `?`. Trailing whitespace is trimmed.
fn text(build: impl FnOnce(&mut String) -> std::fmt::Result) -> String {
    let mut s = String::new();
    build(&mut s).expect("writing to a String cannot fail");
    s.trim_end().to_string()
}

/// strace lines shown at every level when TraceMode::All.
fn observed_lines(v: &InvocationView<'_>) -> Vec<String> {
    match v.observation {
        Some(o) if o.status != ObservationStatus::Unavailable => o
            .syscalls
            .iter()
            .map(sacredarts_core::ipc::ObservedSyscall::line)
            .collect(),
        _ => vec![],
    }
}

fn level1(v: &InvocationView<'_>) -> String {
    if v.trace_mode != TraceMode::All {
        return v.requested_line.clone();
    }
    let kernel = match v.observation.map(|o| o.status) {
        Some(ObservationStatus::Unavailable) | None => " unavailable for this sandbox".to_string(),
        Some(st) => {
            let incomplete = (st == ObservationStatus::Incomplete).then(|| "# (observation incomplete)".to_string());
            let lines: Vec<String> = observed_lines(v).into_iter().chain(incomplete).collect();
            if lines.is_empty() {
                String::new()
            } else {
                format!("\n  {}", lines.join("\n  "))
            }
        }
    };
    format!("{}\n# kernel (strace):{kernel}", v.requested_line)
}

fn explanation(g: &SyscallGuide, v: &InvocationView<'_>) -> String {
    text(|s| {
        writeln!(s, "{}\n", g.description.trim())?;
        match v.errno {
            None => s.push_str(&fill(&g.explain.success, v)),
            Some(e) => {
                s.push_str(&fill(&g.explain.failure, v));
                if !v.executed {
                    write!(s, "\n要求された {} はカーネルに発行されていません。", g.name)?;
                } else if v.denied_by_policy {
                    write!(
                        s,
                        "\nこれはファイルシステムの問題ではありません。現在のポリシーで {0} が deny されているため、\
                     カーネルの seccomp フィルタが {0} の実行前に {1} を返しました。",
                        g.name, e.name
                    )?;
                } else if let Some(d) = g.errors.iter().find(|x| x.name == e.name) {
                    write!(s, "\n{}: {}", e.name, d.description.trim())?;
                }
            }
        }
        Ok(())
    })
}

fn arg_values(req: &SyscallRequest, v: &InvocationView<'_>) -> Vec<(String, String)> {
    match req {
        SyscallRequest::Getpid => vec![],
        SyscallRequest::Openat {
            dirfd,
            path,
            flags,
            raw_flags,
            mode,
        } => vec![
            ("dirfd".into(), format_dirfd(*dirfd)),
            ("pathname".into(), quote_str(path)),
            ("flags".into(), format_flags(flags, *raw_flags)),
            ("mode".into(), mode.map_or_else(|| "（指定なし）".into(), format_mode)),
        ],
        SyscallRequest::Read { fd, count } => vec![
            ("fd".into(), fd.to_string()),
            (
                "buf".into(),
                match v.read_data {
                    Some(d) => format!("（出力）{} を受け取った", quote_bytes(d, DISPLAY_BYTES)),
                    None => "（出力）".into(),
                },
            ),
            ("count".into(), count.to_string()),
        ],
        SyscallRequest::Write { fd, data, count } => vec![
            ("fd".into(), fd.to_string()),
            ("buf".into(), quote_bytes(&data[..*count], DISPLAY_BYTES)),
            ("count".into(), count.to_string()),
        ],
        SyscallRequest::Close { fd } => vec![("fd".into(), fd.to_string())],
        SyscallRequest::Mkdirat { dirfd, path, mode } => vec![
            ("dirfd".into(), format_dirfd(*dirfd)),
            ("pathname".into(), quote_str(path)),
            ("mode".into(), format_mode(*mode)),
        ],
        SyscallRequest::Getpriority { which, who } => vec![
            ("which".into(), PrioWhich::display(*which)),
            ("who".into(), who.to_string()),
        ],
        SyscallRequest::Setpriority { which, who, prio } => vec![
            ("which".into(), PrioWhich::display(*which)),
            ("who".into(), who.to_string()),
            ("prio".into(), prio.to_string()),
        ],
    }
}

fn purpose_label(p: IssuedPurpose) -> &'static str {
    match p {
        IssuedPurpose::Requested => "要求された操作",
        IssuedPurpose::StateCheck => "内部: 状態確認",
    }
}

/// Level 3: every section, with measured values separated from general rules.
fn level3(g: &SyscallGuide, v: &InvocationView<'_>) -> String {
    text(|s| {
        write_arguments(s, g, v)?;
        write_flags(s, g, v)?;
        write_return(s, g, v)?;
        write_errno(s, g, v)?;
        write_state_change(s, g, v)?;
        write_kernel_calls(s, v)?;
        write_background(s, g, v)?;
        Ok(())
    })
}

/// Purpose, C signature and the arguments with this call's values.
fn write_arguments(s: &mut String, g: &SyscallGuide, v: &InvocationView<'_>) -> std::fmt::Result {
    writeln!(s, "## 目的\n{}", g.purpose.trim())?;
    writeln!(s, "\n## C の関数シグネチャ\n```c\n{}\n```", g.signature.trim())?;

    let values = arg_values(v.request, v);
    if !g.arguments.is_empty() {
        writeln!(s, "\n## 引数（今回の値）")?;
        for a in &g.arguments {
            let val = values
                .iter()
                .find(|(n, _)| *n == a.name)
                .map_or("-", |(_, x)| x.as_str());
            writeln!(s, "- `{}` ({}) = {}\n  {}", a.name, a.ty, val, a.description.trim())?;
        }
    }
    Ok(())
}

/// openat: the flags that were used.
fn write_flags(s: &mut String, g: &SyscallGuide, v: &InvocationView<'_>) -> std::fmt::Result {
    if let SyscallRequest::Openat { flags, raw_flags, .. } = v.request {
        writeln!(s, "\n## 使用したフラグ")?;
        for f in flags {
            let d = g
                .flags
                .iter()
                .find(|x| x.name == f.as_str())
                .map_or("", |x| x.description.trim());
            writeln!(s, "- `{}`: {}", f.as_str(), d)?;
        }
        if *raw_flags != 0 {
            writeln!(
                s,
                "- `{raw_flags:#x}`: 数値で指定されたビット（そのままカーネルに渡しました。名前付きの解釈は「発行した syscall」の行を参照）"
            )?;
        }
    }
    Ok(())
}

/// This call's return value and the general rule.
fn write_return(s: &mut String, g: &SyscallGuide, v: &InvocationView<'_>) -> std::fmt::Result {
    writeln!(s, "\n## 戻り値")?;
    match (v.errno, v.request, v.handle) {
        (None, SyscallRequest::Openat { .. }, Some(h)) => {
            writeln!(s, "今回: `{}`（カーネルが返したファイルディスクリプタ）", h.real_fd)?;
        }
        (None, _, _) => {
            writeln!(s, "今回: `{}`", v.ret)?;
        }
        (Some(_), _, _) => {
            writeln!(s, "今回: `-1`")?;
        }
    }
    writeln!(s, "一般: {}", g.return_value.trim())?;
    Ok(())
}

/// This call's errno and the ones that can occur.
fn write_errno(s: &mut String, g: &SyscallGuide, v: &InvocationView<'_>) -> std::fmt::Result {
    writeln!(s, "\n## errno")?;
    match v.errno {
        Some(e) => {
            writeln!(s, "今回: `{}` ({}) = {}", e.name, e.code, e.message)?;
        }
        None => {
            writeln!(s, "今回: なし（成功）")?;
        }
    }
    writeln!(s, "起こりうる主な errno:")?;
    for e in &g.errors {
        writeln!(s, "- `{}`: {}", e.name, e.description.trim())?;
    }
    Ok(())
}

/// Measured state change (fd table) and the general rule.
fn write_state_change(s: &mut String, g: &SyscallGuide, v: &InvocationView<'_>) -> std::fmt::Result {
    writeln!(s, "\n## 実行による状態変化")?;
    match (v.handle, v.request, v.errno) {
        (Some(h), SyscallRequest::Openat { .. }, None) => {
            writeln!(
                s,
                "今回（実測）: fd {}（{}）がプロセスの fd テーブルに追加されました。",
                h.real_fd, h.path
            )?;
        }
        (Some(h), SyscallRequest::Close { .. }, _) => {
            writeln!(
                s,
                "今回（実測）: fd {}（{}）がプロセスの fd テーブルから削除されました。",
                h.real_fd, h.path
            )?;
        }
        (_, _, Some(_)) => {
            writeln!(s, "今回（実測）: 失敗したため、fd テーブルは変化していません。")?;
        }
        _ => {}
    }
    writeln!(s, "一般:")?;
    for c in &g.state_changes {
        writeln!(s, "- {}", c.trim())?;
    }
    Ok(())
}

/// Measured: what the runner issued and what strace observed.
fn write_kernel_calls(s: &mut String, v: &InvocationView<'_>) -> std::fmt::Result {
    writeln!(s, "\n## 【実測】カーネルに発行された syscall")?;
    writeln!(s, "Runner の自己申告（実 fd で表示）:")?;
    for c in v.issued {
        let ret = match &c.errno {
            Some(e) => format!("-1 {e}"),
            None => c.ret.to_string(),
        };
        writeln!(
            s,
            "  {}({}) = {}    [{}]",
            c.syscall,
            c.args,
            ret,
            purpose_label(c.purpose)
        )?;
    }
    match v.observation.map(|o| o.status) {
        Some(ObservationStatus::Complete | ObservationStatus::Incomplete) => {
            writeln!(s, "strace による観測:")?;
            for l in observed_lines(v) {
                writeln!(s, "  {l}")?;
            }
            if v.observation.map(|o| o.status) == Some(ObservationStatus::Incomplete) {
                writeln!(s, "  （観測は不完全です）")?;
            }
        }
        _ => {
            writeln!(s, "strace による観測: このサンドボックスでは利用できません。")?;
        }
    }
    Ok(())
}

/// General Linux background (not observed by SacredArts).
fn write_background(s: &mut String, g: &SyscallGuide, v: &InvocationView<'_>) -> std::fmt::Result {
    writeln!(
        s,
        "\n## 【一般的な仕様】関連する Linux の内部概念\n\
     ※ 以下は Linux man-pages などに基づく一般的な説明です。SacredArts はカーネル内部（VFS 等）を直接観測していません。"
    )?;
    for c in &g.concepts {
        writeln!(s, "- **{}**: {}", c.name, c.description.trim().replace('\n', " "))?;
    }
    if !g.notes.is_empty() || !v.notes.is_empty() {
        writeln!(s, "\n## 補足")?;
        for n in v.notes.iter().chain(g.notes.iter()) {
            writeln!(s, "- {}", n.trim().replace('\n', " "))?;
        }
    }
    writeln!(s, "\n## 関連する syscall\n{}", g.related.join(", "))?;
    writeln!(s, "\n## 参考 man page\n{}", g.man_pages.join(", "))?;
    Ok(())
}

#[must_use]
pub fn render_invocation(guides: &Guides, level: GuideLevel, v: &InvocationView<'_>) -> Rendered {
    let name = v.request.name().as_str();
    let l1 = level1(v);
    let Some(g) = guides.get(name) else {
        return Rendered {
            level: level.as_u8(),
            summary: String::new(),
            explanation: None,
            text: l1,
        };
    };
    match level {
        GuideLevel::LineOnly => Rendered {
            level: 1,
            summary: g.summary.clone(),
            explanation: None,
            text: l1,
        },
        GuideLevel::Explained | GuideLevel::Detailed => {
            let exp = explanation(g, v);
            let details = match level {
                GuideLevel::Detailed => format!("\n\n{}", level3(g, v)),
                _ => String::new(),
            };
            let text = format!("{l1}\n\n解説:\n{exp}{details}");
            Rendered {
                level: level.as_u8(),
                summary: g.summary.clone(),
                explanation: Some(exp),
                text,
            }
        }
    }
}

/// `syscall_describe`: specification only, no execution context.
#[must_use]
pub fn render_describe(g: &SyscallGuide, level: GuideLevel) -> String {
    text(|s| {
        writeln!(s, "{} — {}", g.name, g.summary)?;
        writeln!(s, "```c\n{}\n```", g.signature.trim())?;
        if !g.executable {
            writeln!(s, "※ SacredArts では {} は実行できません（説明のみ）。", g.name)?;
        }
        if level == GuideLevel::LineOnly {
            return Ok(());
        }
        writeln!(s, "\n{}", g.description.trim())?;
        for n in &g.notes {
            writeln!(s, "\n補足: {}", n.trim().replace('\n', " "))?;
        }
        writeln!(s, "\n関連: {}", g.related.join(", "))?;
        if level == GuideLevel::Explained {
            return Ok(());
        }
        writeln!(s, "\n## 目的\n{}", g.purpose.trim())?;
        if !g.arguments.is_empty() {
            writeln!(s, "\n## 引数")?;
            for a in &g.arguments {
                writeln!(s, "- `{}` ({}): {}", a.name, a.ty, a.description.trim())?;
            }
        }
        if !g.flags.is_empty() {
            writeln!(s, "\n## フラグ")?;
            for f in &g.flags {
                writeln!(s, "- `{}`: {}", f.name, f.description.trim())?;
            }
        }
        writeln!(s, "\n## 戻り値\n{}", g.return_value.trim())?;
        writeln!(s, "\n## 主な errno")?;
        for e in &g.errors {
            writeln!(s, "- `{}`: {}", e.name, e.description.trim())?;
        }
        writeln!(s, "\n## 状態変化")?;
        for c in &g.state_changes {
            writeln!(s, "- {}", c.trim())?;
        }
        writeln!(s, "\n## 関連する Linux の内部概念（一般的な説明）")?;
        for c in &g.concepts {
            writeln!(s, "- **{}**: {}", c.name, c.description.trim().replace('\n', " "))?;
        }
        writeln!(s, "\n## 参考 man page\n{}", g.man_pages.join(", "))?;
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use sacredarts_core::format::{format_call, format_result};
    use sacredarts_core::{Dirfd, SyscallName};

    #[test]
    fn all_builtin_guides_parse_and_cover_syscalls() {
        let g = Guides::parse_builtin().unwrap();
        for n in <SyscallName as strum::IntoEnumIterator>::iter() {
            let x = g.get(n.as_str()).unwrap_or_else(|| panic!("missing guide {n}"));
            assert!(x.executable);
            assert!(!x.explain.success.is_empty() && !x.explain.failure.is_empty());
        }
        assert!(!g.get("open").unwrap().executable);
        for name in g.names() {
            for r in &g.get(name).unwrap().related {
                assert!(
                    g.get(r).is_some() || ["getppid", "gettid"].contains(&r.as_str()),
                    "{name} -> {r}"
                );
            }
        }
    }

    fn view<'a>(
        req: &'a SyscallRequest,
        handle: Option<&'a HandleInfo>,
        issued: &'a [IssuedCall],
        obs: Option<&'a Observation>,
        mode: TraceMode,
    ) -> InvocationView<'a> {
        InvocationView {
            request: req,
            requested_line: format_call(req, None) + &format_result(3, None),
            executed: true,
            ret: 3,
            kernel_ret: 3,
            errno: None,
            handle,
            read_data: None,
            issued,
            observation: obs,
            trace_mode: mode,
            notes: &[],
            open_flags: None,
            denied_by_policy: false,
        }
    }

    #[test]
    fn explanation_uses_the_flags_the_kernel_received() {
        // flags given as a number: only the sandbox knows it means O_PATH
        let req = SyscallRequest::Openat {
            dirfd: Dirfd::AtFdcwd,
            path: ".".into(),
            flags: vec![],
            raw_flags: 0x20_0000,
            mode: None,
        };
        let decoded = DecodedFlags {
            access_mode: 0,
            named: vec![OpenFlag::O_PATH],
            unnamed: 0,
        };
        let mut v = view(&req, None, &[], None, TraceMode::Requested);
        v.open_flags = Some(&decoded);
        let r = render_invocation(Guides::builtin(), GuideLevel::Explained, &v);
        assert!(r.text.contains("O_PATH"), "{}", r.text);
        assert!(!r.text.contains("読み込み専用"), "{}", r.text);
    }

    #[test]
    fn levels_only_change_detail() {
        let req = SyscallRequest::Openat {
            dirfd: Dirfd::AtFdcwd,
            path: "/workspace/hello.txt".into(),
            flags: vec![OpenFlag::O_WRONLY, OpenFlag::O_CREAT],
            raw_flags: 0,
            mode: Some(0o644),
        };
        let h = HandleInfo {
            handle: 3,
            real_fd: 3,
            path: "/workspace/hello.txt".into(),
            flags: "O_WRONLY|O_CREAT".into(),
        };
        let issued = vec![IssuedCall {
            syscall: "openat".into(),
            purpose: IssuedPurpose::Requested,
            args: "AT_FDCWD, \"/workspace/hello.txt\", O_WRONLY|O_CREAT, 0644".into(),
            ret: 3,
            errno: None,
        }];
        let g = Guides::builtin();
        let v = view(&req, Some(&h), &issued, None, TraceMode::Requested);
        let r1 = render_invocation(g, GuideLevel::LineOnly, &v);
        let r2 = render_invocation(g, GuideLevel::Explained, &v);
        let r3 = render_invocation(g, GuideLevel::Detailed, &v);
        assert_eq!(
            r1.text,
            "openat(AT_FDCWD, \"/workspace/hello.txt\", O_WRONLY|O_CREAT, 0644) = 3"
        );
        assert!(r2.text.starts_with(&r1.text));
        assert!(r2.text.contains("作成またはオープンし、書き込み専用で利用できる"));
        assert!(r2.text.contains("ファイルディスクリプタ"));
        assert!(!r2.text.contains("## C の関数シグネチャ"));
        assert!(r3.text.starts_with(&r2.text));
        for needle in [
            "int openat(",
            "`dirfd` (int) = AT_FDCWD",
            "O_CREAT",
            "Virtual File System",
            "【実測】",
            "【一般的な仕様】",
            "openat(2)",
        ] {
            assert!(r3.text.contains(needle), "missing {needle}");
        }
    }

    #[test]
    fn trace_mode_all_adds_observed_lines() {
        let req = SyscallRequest::Getpid;
        let obs = Observation {
            status: ObservationStatus::Complete,
            syscalls: vec![sacredarts_core::ipc::ObservedSyscall {
                timestamp_epoch: Some(1.0),
                syscall: "getpid".into(),
                args: String::new(),
                return_raw: "14".into(),
                ret: Some(14),
                errno: None,
                errno_message: None,
                duration_ns: Some(2000),
                raw: String::new(),
            }],
            truncated: false,
        };
        let g = Guides::builtin();
        let a = render_invocation(
            g,
            GuideLevel::LineOnly,
            &view(&req, None, &[], Some(&obs), TraceMode::Requested),
        );
        let b = render_invocation(
            g,
            GuideLevel::LineOnly,
            &view(&req, None, &[], Some(&obs), TraceMode::All),
        );
        assert!(!a.text.contains("strace"));
        assert!(b.text.contains("# kernel (strace):\n  getpid() = 14 <0.000002>"));
    }

    #[test]
    fn policy_denial_is_explained() {
        let req = SyscallRequest::Mkdirat {
            dirfd: Dirfd::AtFdcwd,
            path: "test".into(),
            mode: 0o755,
        };
        let e = ErrnoInfo {
            name: "EPERM".into(),
            code: 1,
            message: "Operation not permitted".into(),
        };
        let mut v = view(&req, None, &[], None, TraceMode::Requested);
        v.errno = Some(&e);
        v.ret = -1;
        v.denied_by_policy = true;
        let r = render_invocation(Guides::builtin(), GuideLevel::Explained, &v);
        assert!(r.text.contains("seccomp フィルタ"), "{}", r.text);
    }

    #[test]
    fn describe_levels() {
        let g = Guides::builtin().get("open").unwrap();
        let l1 = render_describe(g, GuideLevel::LineOnly);
        let l3 = render_describe(g, GuideLevel::Detailed);
        assert!(l1.contains("int open("));
        assert!(!l1.contains("openat が便利"));
        assert!(l3.contains("openat(AT_FDCWD"));
    }
}
