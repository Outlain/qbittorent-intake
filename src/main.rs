//! Startup order is part of the recovery protocol: take the controller lock,
//! apply an offline restore, load the resulting settings, open SQLite, and only
//! then accept requests. Never move restore work into a request handler.
use anyhow::{Context, Result};
use std::sync::atomic::Ordering;
use torrent_intake::{
    config::Config,
    http::{self, App},
    persistence::{self, Database},
};

fn main() -> Result<()> {
    // This internal child performs bounded archive parsing before any threads or
    // async runtime exist. The parent supplies an already-open descriptor.
    if let Some(code) = torrent_intake::scanning::helper_main() {
        std::process::exit(code);
    }
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!("Torrent Intake (Rust)\n\nUsage: torrent-intake [--host ADDRESS] [--port PORT]\n       torrent-intake healthcheck\n\nConfiguration: TI_* environment variables and TI_DATA_DIR/settings.json.\nA new installation starts paused; use Settings & Help to configure it.\nSee README.md for setup and the explanation guide.");
        return Ok(());
    }
    if args.first().is_some_and(|a| a == "healthcheck") {
        reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()?
            .get("http://127.0.0.1:8000/health")
            .send()?
            .error_for_status()?;
        return Ok(());
    }
    let host = argument(&args, "--host").unwrap_or_else(|| "0.0.0.0".into());
    let port: u16 = argument(&args, "--port")
        .unwrap_or_else(|| "8000".into())
        .parse()
        .context("Invalid HTTP port")?;
    let initial = Config::load()?;
    #[cfg(unix)]
    unsafe {
        libc::umask(0o077);
    }
    let _controller_lock = persistence::ControllerLock::acquire(&initial.path("data_dir"))?;
    persistence::restore::apply_pending_restore(&initial.values)?;
    let config = Config::load()?;
    tracing_subscriber::fmt()
        .with_env_filter(if config.bool("debug") {
            "debug"
        } else {
            "info"
        })
        .init();
    config.persist()?;
    let restart = config.path("data_dir").join("restart-required");
    if restart.exists() {
        std::fs::remove_file(restart)?;
        persistence::state::sync_directory(&config.path("data_dir"))?;
    }
    let database_path = config.database_path()?;
    let fresh = !database_path.exists();
    let db = Database::open(database_path)?;
    let app = App::new(config, db, fresh)?;
    let worker = app.start_worker();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let serving = runtime.block_on(async {
        let listener = tokio::net::TcpListener::bind((host.as_str(), port)).await?;
        tracing::info!("Torrent Intake listening on {}", listener.local_addr()?);
        let shutdown_app = app.clone();
        axum::serve(listener, http::router(app.clone()))
            .with_graceful_shutdown(async move {
                shutdown_signal().await;
                shutdown_app.shutdown.store(true, Ordering::SeqCst);
                shutdown_app.workflow.stop();
            })
            .await
    });
    app.shutdown.store(true, Ordering::SeqCst);
    app.workflow.stop();
    worker
        .join()
        .map_err(|_| anyhow::anyhow!("Background controller panicked"))?;
    serving?;
    Ok(())
}
fn argument(args: &[String], name: &str) -> Option<String> {
    args.windows(2).find(|p| p[0] == name).map(|p| p[1].clone())
}
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("SIGTERM handler");
        tokio::select! {_ = tokio::signal::ctrl_c()=>{},_ = terminate.recv()=>{}}
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
