//! `sacredarts` — MCP server (stdio transport).
//!
//! stdout carries MCP protocol messages only; all logs go to stderr.

mod config;
mod docker;
mod errors;
mod server;
mod session;
mod store;

use rmcp::ServiceExt;
use std::time::Duration;

#[tokio::main]
async fn main() -> std::process::ExitCode {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("SACREDARTS_LOG")
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    if std::env::args().nth(1).as_deref() == Some("--version") {
        eprintln!("sacredarts {}", env!("CARGO_PKG_VERSION"));
        return std::process::ExitCode::SUCCESS;
    }

    let cfg = config::Config::from_env();
    tracing::info!(image = %cfg.image, docker = %cfg.docker_bin.display(), "starting SacredArts MCP server");
    let mgr = session::Manager::new(cfg);

    // Remove containers left behind by a previous server that died.
    match mgr.cleanup_orphans().await {
        Ok(v) if !v.is_empty() => tracing::info!("removed orphaned sandboxes: {v:?}"),
        Ok(_) => {}
        Err(e) => tracing::warn!("orphan cleanup skipped: {e}"),
    }

    {
        let mgr = mgr.clone();
        tokio::spawn(async move {
            let mut t = tokio::time::interval(Duration::from_secs(15));
            loop {
                t.tick().await;
                mgr.reap().await;
            }
        });
    }

    let service = match server::SacredArts::new(mgr.clone())
        .serve(rmcp::transport::stdio())
        .await
    {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("failed to start MCP service: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };
    tokio::select! {
        r = service.waiting() => {
            if let Err(e) = r {
                tracing::warn!("MCP service ended with error: {e}");
            }
        }
        _ = tokio::signal::ctrl_c() => tracing::info!("interrupted"),
    }
    tracing::info!("shutting down; destroying all sandboxes");
    mgr.destroy_all().await;
    std::process::ExitCode::SUCCESS
}
