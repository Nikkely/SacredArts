//! Entry point of the sandbox container.
//!
//! `sacredarts-supervisor [--runner PATH] [--strace PATH|none] [--workspace DIR] [--tmp DIR]`

#[cfg(target_os = "linux")]
fn main() {
    use sacredarts_tracer::supervisor::{Config, Supervisor};
    use std::path::PathBuf;

    let mut cfg = Config {
        runner_bin: PathBuf::from("/usr/local/bin/sacredarts-runner"),
        strace_bin: Some(PathBuf::from("/usr/bin/strace")),
        workspace: PathBuf::from(sacredarts_core::limits::WORKSPACE_ROOT),
        tmp: PathBuf::from("/tmp"),
    };
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        let v = args.next();
        match (a.as_str(), v) {
            ("--runner", Some(v)) => cfg.runner_bin = v.into(),
            ("--strace", Some(v)) => cfg.strace_bin = if v == "none" { None } else { Some(v.into()) },
            ("--workspace", Some(v)) => cfg.workspace = v.into(),
            ("--tmp", Some(v)) => cfg.tmp = v.into(),
            (other, _) => {
                eprintln!("sacredarts-supervisor: bad argument {other:?}");
                std::process::exit(2);
            }
        }
    }
    std::process::exit(Supervisor::new(cfg).run());
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("sacredarts-supervisor only runs on Linux (inside the SacredArts sandbox container)");
    std::process::exit(2);
}
