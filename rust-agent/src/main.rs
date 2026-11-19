mod engine;
mod server;
mod shell;
mod state;
mod stats;
mod status;
mod translator;

use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use std::collections::HashMap;
use std::env;
use std::fs;
use std::net::{IpAddr, SocketAddr};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tokio_rustls::TlsAcceptor;

use crate::engine::ProxyEngine;
use crate::server::{handle_request, AgentContext};
use crate::shell::ShellGuard;
use crate::state::{load_or_create_token, load_state, sha256_hex, VERSION};

struct CliArgs {
    listen: String,
    state_dir: PathBuf,
    token_file: Option<PathBuf>,
    base_path: String,
    tls_cert: Option<PathBuf>,
    tls_key: Option<PathBuf>,
    shell_allow_ip: Option<IpAddr>,
    show_version: bool,
}

fn parse_args() -> CliArgs {
    let mut args = CliArgs {
        listen: "[::]:2053".to_string(),
        state_dir: PathBuf::from("/etc/x-ui-agent"),
        token_file: None,
        base_path: "/".to_string(),
        tls_cert: None,
        tls_key: None,
        shell_allow_ip: None,
        show_version: false,
    };

    let mut it = env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "-listen" | "--listen" => {
                if let Some(v) = it.next() {
                    args.listen = if v.starts_with(':') {
                        format!("[::]{v}")
                    } else {
                        v
                    };
                }
            }
            "-state-dir" | "--state-dir" => {
                if let Some(v) = it.next() {
                    args.state_dir = PathBuf::from(v);
                }
            }
            "-token-file" | "--token-file" => {
                if let Some(v) = it.next() {
                    args.token_file = Some(PathBuf::from(v));
                }
            }
            "-base-path" | "--base-path" => {
                if let Some(v) = it.next() {
                    args.base_path = if v.is_empty() { "/".to_string() } else { v };
                }
            }
            "-tls-cert" | "--tls-cert" => {
                if let Some(v) = it.next() {
                    args.tls_cert = Some(PathBuf::from(v));
                }
            }
            "-tls-key" | "--tls-key" => {
                if let Some(v) = it.next() {
                    args.tls_key = Some(PathBuf::from(v));
                }
            }
            "-shell-allow-ip" | "--shell-allow-ip" => {
                if let Some(v) = it.next() {
                    args.shell_allow_ip = v.parse().ok();
                }
            }
            "-version" | "--version" => {
                args.show_version = true;
            }
            _ => {}
        }
    }
    args
}

fn load_tls_acceptor(cert_path: &Path, key_path: &Path) -> Result<(TlsAcceptor, String), String> {
    let cert_pem = fs::read(cert_path).map_err(|e| format!("read tls cert: {e}"))?;
    let key_pem = fs::read(key_path).map_err(|e| format!("read tls key: {e}"))?;

    let certs: Vec<CertificateDer<'static>> = pem::parse_many(&cert_pem)
        .map_err(|e| format!("parse cert pem: {e}"))?
        .into_iter()
        .filter(|p| p.tag() == "CERTIFICATE")
        .map(|p| CertificateDer::from(p.into_contents()))
        .collect();
    if certs.is_empty() {
        return Err("no CERTIFICATE block found in tls cert".to_string());
    }
    let fingerprint = sha256_hex(certs[0].as_ref());

    let key_block = pem::parse(&key_pem).map_err(|e| format!("parse key pem: {e}"))?;
    let key = match key_block.tag() {
        "PRIVATE KEY" => PrivateKeyDer::Pkcs8(key_block.into_contents().into()),
        "EC PRIVATE KEY" => PrivateKeyDer::Sec1(key_block.into_contents().into()),
        "RSA PRIVATE KEY" => PrivateKeyDer::Pkcs1(key_block.into_contents().into()),
        other => return Err(format!("unsupported private key PEM tag: {other}")),
    };

    let cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| format!("rustls config: {e}"))?;

    Ok((TlsAcceptor::from(Arc::new(cfg)), fingerprint))
}

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let cli = parse_args();

    if cli.show_version {
        println!("{VERSION}");
        return;
    }

    // Single-threaded Tokio runtime for minimal RAM on 128 MB VPS
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build tokio runtime");

    let local = tokio::task::LocalSet::new();
    local.block_on(&rt, async move {
        if let Err(e) = fs::create_dir_all(&cli.state_dir) {
            eprintln!("agent init mkdir {}: {e}", cli.state_dir.display());
            std::process::exit(1);
        }
        let _ = fs::set_permissions(&cli.state_dir, fs::Permissions::from_mode(0o700));

        let state_path = cli.state_dir.join("state.json");
        let config_path = cli.state_dir.join("config.yaml");
        let shell_pub_path = cli.state_dir.join("shell.pub");
        let token_path = cli
            .token_file
            .unwrap_or_else(|| cli.state_dir.join("token"));

        let st = match load_state(&state_path) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("agent init state: {e}");
                std::process::exit(1);
            }
        };
        let (token, generated) = match load_or_create_token(&token_path) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("agent init token: {e}");
                std::process::exit(1);
            }
        };
        if generated {
            println!("node token (save it as the node API token on the master): {token}");
        }

        let token_mtime = fs::metadata(&token_path).and_then(|m| m.modified()).ok();
        let tls_cert_path = cli
            .tls_cert
            .unwrap_or_else(|| cli.state_dir.join("cert.pem"));
        let tls_key_path = cli
            .tls_key
            .unwrap_or_else(|| cli.state_dir.join("key.pem"));

        struct TlsReloader {
            cert_path: PathBuf,
            key_path: PathBuf,
            cached: Option<(std::time::SystemTime, std::time::SystemTime, TlsAcceptor)>,
        }

        impl TlsReloader {
            fn new(cert_path: PathBuf, key_path: PathBuf) -> Self {
                let mut this = Self {
                    cert_path,
                    key_path,
                    cached: None,
                };
                if this.cert_path.exists() && this.key_path.exists() {
                    let _ = this.get();
                } else {
                    log::warn!("TLS cert/key not present yet; serving plain HTTP until cert.pem & key.pem exist");
                }
                this
            }

            fn get(&mut self) -> Option<TlsAcceptor> {
                let cm = fs::metadata(&self.cert_path).and_then(|m| m.modified()).ok()?;
                let km = fs::metadata(&self.key_path).and_then(|m| m.modified()).ok()?;
                if let Some((ccm, ckm, acc)) = &self.cached {
                    if *ccm == cm && *ckm == km {
                        return Some(acc.clone());
                    }
                }
                match load_tls_acceptor(&self.cert_path, &self.key_path) {
                    Ok((acc, fp)) => {
                        if self.cached.is_some() {
                            log::info!("TLS certificate reloaded (cert sha256: {fp})");
                        } else {
                            log::info!("TLS enabled (cert sha256: {fp})");
                        }
                        self.cached = Some((cm, km, acc.clone()));
                        Some(acc)
                    }
                    Err(e) => {
                        log::warn!("TLS reload failed (keeping previous state): {e}");
                        self.cached.as_ref().map(|(_, _, acc)| acc.clone())
                    }
                }
            }
        }

        let tls_reloader = Arc::new(Mutex::new(TlsReloader::new(tls_cert_path, tls_key_path)));

        let base_path = if cli.base_path.ends_with('/') {
            cli.base_path
        } else {
            format!("{}/", cli.base_path)
        };

        let panel_guid = st.panel_guid.clone();
        let ctx = Arc::new(AgentContext {
            state_dir: cli.state_dir,
            state_path,
            token_path,
            token: Mutex::new((token, token_mtime)),
            base_path,
            started_at: Instant::now(),
            state: Mutex::new(st),
            engine: Mutex::new(ProxyEngine::new(config_path)),
            raw_stats: Mutex::new(HashMap::new()),
            live_ips: Mutex::new(HashMap::new()),
            api_failures: Mutex::new(HashMap::new()),
            shell_guard: Arc::new(ShellGuard::new(shell_pub_path, cli.shell_allow_ip)),
        });

        if let Err(e) = ctx.apply().await {
            log::warn!("embedded shoes start: {e} (agent still serving API)");
        }

        let addr: SocketAddr = cli.listen.parse().expect("invalid listen address");
        let listener = TcpListener::bind(addr).await.expect("bind tcp listener");
        log::info!(
            "x-ui-agent-rs {} listening on {} (panelGuid {})",
            VERSION,
            listener.local_addr().unwrap(),
            panel_guid
        );

        let shutdown_ctx = ctx.clone();
        tokio::task::spawn_local(async move {
            let _ = tokio::signal::ctrl_c().await;
            log::info!("shutting down, stopping embedded shoes");
            let mut eng = shutdown_ctx.engine.lock().await;
            eng.stop().await;
            std::process::exit(0);
        });

        loop {
            let Ok((stream, remote_addr)) = listener.accept().await else {
                continue;
            };
            let peer_ip = remote_addr.ip();
            let req_ctx = ctx.clone();
            let tls = {
                let mut rel = tls_reloader.lock().await;
                rel.get()
            };
            tokio::task::spawn_local(async move {
                let svc = service_fn(move |req| handle_request(req_ctx.clone(), peer_ip, req));
                if let Some(acceptor) = tls {
                    match acceptor.accept(stream).await {
                        Ok(tls_stream) => {
                            let io = TokioIo::new(tls_stream);
                            if let Err(err) = http1::Builder::new()
                                .serve_connection(io, svc)
                                .with_upgrades()
                                .await
                            {
                                log::debug!("https conn error: {err}");
                            }
                        }
                        Err(err) => log::debug!("tls handshake error from {peer_ip}: {err}"),
                    }
                } else {
                    let io = TokioIo::new(stream);
                    if let Err(err) = http1::Builder::new()
                        .serve_connection(io, svc)
                        .with_upgrades()
                        .await
                    {
                        log::debug!("http conn error: {err}");
                    }
                }
            });
        }
    });
}
