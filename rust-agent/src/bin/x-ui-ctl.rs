use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::client::conn::http1;
use hyper::header::{CONNECTION, HOST, UPGRADE};
use hyper::Request;
use hyper_util::rt::TokioIo;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error as TlsError, SignatureScheme};
use sha2::{Digest, Sha256};
use std::env;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use uuid::Uuid;

const FRAME_DATA: u8 = 0x01;
const FRAME_RESIZE: u8 = 0x02;
const FRAME_PING: u8 = 0x03;

#[derive(Debug)]
struct PinnedCertVerifier {
    expected_sha256: Option<String>,
}

impl ServerCertVerifier for PinnedCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        let mut hasher = Sha256::new();
        hasher.update(end_entity.as_ref());
        let got = hex::encode(hasher.finalize());
        match &self.expected_sha256 {
            Some(want) if got.eq_ignore_ascii_case(want) => Ok(ServerCertVerified::assertion()),
            Some(want) => Err(TlsError::General(format!(
                "TLS cert pin mismatch: got {got}, expected {want}"
            ))),
            None => Err(TlsError::General(format!(
                "refusing unpinned TLS cert (pass --pin-sha256 {got})"
            ))),
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ED25519,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PKCS1_SHA256,
        ]
    }
}

fn default_key_path() -> PathBuf {
    let home = env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".config/x-ui-ctl/shell.key")
}

fn load_keypair(path: &PathBuf) -> Ed25519KeyPair {
    let b64 = fs::read_to_string(path).unwrap_or_else(|e| {
        eprintln!("failed to read private key {}: {e}", path.display());
        std::process::exit(1);
    });
    let der = B64.decode(b64.trim()).expect("decode base64 pkcs8 key");
    Ed25519KeyPair::from_pkcs8(&der).expect("parse Ed25519 pkcs8 key")
}

fn sign_headers(kp: &Ed25519KeyPair, method: &str, path: &str, body: &[u8]) -> (String, String, String) {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .to_string();
    let nonce = Uuid::new_v4().to_string();
    let mut hasher = Sha256::new();
    hasher.update(body);
    let body_hash = hex::encode(hasher.finalize());
    let msg = format!("{method}\n{path}\n{ts}\n{nonce}\n{body_hash}");
    let sig = kp.sign(msg.as_bytes());
    (ts, nonce, B64.encode(sig.as_ref()))
}

fn cmd_keygen(key_path: &PathBuf) {
    if let Some(parent) = key_path.parent() {
        fs::create_dir_all(parent).unwrap();
        let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o700));
    }
    let rng = SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let kp = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
    fs::write(key_path, format!("{}\n", B64.encode(pkcs8.as_ref()))).unwrap();
    let _ = fs::set_permissions(key_path, fs::Permissions::from_mode(0o600));
    println!("Private key saved to: {}", key_path.display());
    println!("Copy this public key to /etc/x-ui-agent/shell.pub on the VPS:");
    println!("{}", B64.encode(kp.public_key().as_ref()));
}

async fn connect_http1(
    url_str: &str,
    pin_sha256: Option<String>,
) -> (http1::SendRequest<Full<Bytes>>, String, String) {
    let parsed = url::Url::parse(url_str).expect("invalid URL");
    let scheme = parsed.scheme();
    let host = parsed.host_str().expect("missing host").to_string();
    let port = parsed.port_or_known_default().unwrap_or(2053);
    let base_path = parsed.path().trim_end_matches('/').to_string();
    let addr = format!("{host}:{port}");

    let tcp = TcpStream::connect(&addr).await.expect("connect TCP");

    if scheme == "https" {
        let verifier = Arc::new(PinnedCertVerifier {
            expected_sha256: pin_sha256,
        });
        let cfg = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(cfg));
        let server_name = ServerName::try_from(host.clone()).expect("valid server name");
        let tls = connector
            .connect(server_name, tcp)
            .await
            .expect("TLS handshake failed");
        let (sender, conn) = http1::handshake(TokioIo::new(tls))
            .await
            .expect("HTTP/1.1 handshake");
        tokio::spawn(async move {
            let _ = conn.with_upgrades().await;
        });
        (sender, format!("{host}:{port}"), base_path)
    } else {
        let (sender, conn) = http1::handshake(TokioIo::new(tcp))
            .await
            .expect("HTTP/1.1 handshake");
        tokio::spawn(async move {
            let _ = conn.with_upgrades().await;
        });
        (sender, format!("{host}:{port}"), base_path)
    }
}

async fn write_frame<W: AsyncWriteExt + Unpin>(
    w: &mut W,
    ftype: u8,
    payload: &[u8],
) -> std::io::Result<()> {
    let mut hdr = [0u8; 5];
    hdr[0] = ftype;
    hdr[1..5].copy_from_slice(&(payload.len() as u32).to_be_bytes());
    w.write_all(&hdr).await?;
    if !payload.is_empty() {
        w.write_all(payload).await?;
    }
    w.flush().await
}

async fn read_frame<R: AsyncReadExt + Unpin>(r: &mut R) -> std::io::Result<(u8, Vec<u8>)> {
    let mut hdr = [0u8; 5];
    r.read_exact(&mut hdr).await?;
    let ftype = hdr[0];
    let len = u32::from_be_bytes([hdr[1], hdr[2], hdr[3], hdr[4]]) as usize;
    let mut buf = vec![0u8; len];
    if len > 0 {
        r.read_exact(&mut buf).await?;
    }
    Ok((ftype, buf))
}

struct TermiosGuard(libc::termios);
impl Drop for TermiosGuard {
    fn drop(&mut self) {
        unsafe {
            libc::tcsetattr(0, libc::TCSANOW, &self.0);
        }
    }
}

fn enable_raw_mode() -> Option<TermiosGuard> {
    unsafe {
        let mut orig: libc::termios = std::mem::zeroed();
        if libc::tcgetattr(0, &mut orig) != 0 {
            return None;
        }
        let mut raw = orig;
        libc::cfmakeraw(&mut raw);
        libc::tcsetattr(0, libc::TCSANOW, &raw);
        Some(TermiosGuard(orig))
    }
}

fn current_winsize() -> (u16, u16) {
    unsafe {
        let mut ws: libc::winsize = std::mem::zeroed();
        if libc::ioctl(0, libc::TIOCGWINSZ, &mut ws) == 0 && ws.ws_col > 0 && ws.ws_row > 0 {
            (ws.ws_col, ws.ws_row)
        } else {
            (80, 24)
        }
    }
}

fn main() {
    let mut args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() {
        eprintln!("Usage:");
        eprintln!("  x-ui-ctl keygen [--key PATH]");
        eprintln!("  x-ui-ctl exec <URL> [--pin-sha256 HEX] [--key PATH] <CMD>");
        eprintln!("  x-ui-ctl shell <URL> [--pin-sha256 HEX] [--key PATH]");
        std::process::exit(1);
    }

    let subcmd = args.remove(0);
    let mut key_path = default_key_path();
    let mut pin_sha256: Option<String> = None;
    let mut positional = Vec::new();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--key" => {
                i += 1;
                if i < args.len() {
                    key_path = PathBuf::from(&args[i]);
                }
            }
            "--pin-sha256" => {
                i += 1;
                if i < args.len() {
                    pin_sha256 = Some(args[i].clone());
                }
            }
            _ => positional.push(args[i].clone()),
        }
        i += 1;
    }

    if subcmd == "keygen" {
        cmd_keygen(&key_path);
        return;
    }

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    rt.block_on(async move {
        let kp = load_keypair(&key_path);
        let url_str = positional.first().expect("missing target URL");
        let (mut sender, host_hdr, base_path) = connect_http1(url_str, pin_sha256).await;

        if subcmd == "exec" {
            let cmd = positional[1..].join(" ");
            let body = serde_json::to_vec(&serde_json::json!({ "cmd": cmd })).unwrap();
            let path = format!("{base_path}/panel/api/shell/exec");
            let (ts, nonce, sig) = sign_headers(&kp, "POST", "/panel/api/shell/exec", &body);

            let req = Request::builder()
                .method("POST")
                .uri(&path)
                .header(HOST, &host_hdr)
                .header("Content-Type", "application/json")
                .header("X-Shell-Timestamp", ts)
                .header("X-Shell-Nonce", nonce)
                .header("X-Shell-Signature", sig)
                .body(Full::new(Bytes::from(body)))
                .unwrap();

            let resp = sender.send_request(req).await.expect("send exec request");
            let status = resp.status();
            let raw = resp.into_body().collect().await.unwrap().to_bytes();
            if !status.is_success() {
                eprintln!("HTTP {status}: {}", String::from_utf8_lossy(&raw));
                std::process::exit(1);
            }
            let v: serde_json::Value = serde_json::from_slice(&raw).unwrap();
            if let Some(obj) = v.get("obj") {
                if let Some(out) = obj.get("stdout").and_then(|s| s.as_str()) {
                    print!("{out}");
                }
                if let Some(err) = obj.get("stderr").and_then(|s| s.as_str()) {
                    eprint!("{err}");
                }
                let code = obj.get("exitCode").and_then(|c| c.as_i64()).unwrap_or(0);
                std::process::exit(code as i32);
            }
        } else if subcmd == "shell" {
            let path = format!("{base_path}/panel/api/shell/pty");
            let (ts, nonce, sig) = sign_headers(&kp, "GET", "/panel/api/shell/pty", b"");

            let req = Request::builder()
                .method("GET")
                .uri(&path)
                .header(HOST, &host_hdr)
                .header(CONNECTION, "Upgrade")
                .header(UPGRADE, "x-ui-pty")
                .header("X-Shell-Timestamp", ts)
                .header("X-Shell-Nonce", nonce)
                .header("X-Shell-Signature", sig)
                .body(Full::new(Bytes::new()))
                .unwrap();

            let resp = sender.send_request(req).await.expect("send pty request");
            if resp.status() != hyper::StatusCode::SWITCHING_PROTOCOLS {
                let status = resp.status();
                let raw = resp.into_body().collect().await.unwrap().to_bytes();
                eprintln!("PTY upgrade rejected ({status}): {}", String::from_utf8_lossy(&raw));
                std::process::exit(1);
            }

            let upgraded = hyper::upgrade::on(resp).await.expect("upgrade pty");
            let (mut net_r, mut net_w) = tokio::io::split(TokioIo::new(upgraded));
            let _raw_guard = enable_raw_mode();

            let (cols, rows) = current_winsize();
            let mut sz = [0u8; 4];
            sz[..2].copy_from_slice(&cols.to_be_bytes());
            sz[2..].copy_from_slice(&rows.to_be_bytes());
            let _ = write_frame(&mut net_w, FRAME_RESIZE, &sz).await;

            let mut stdin = tokio::io::stdin();
            let mut stdout = tokio::io::stdout();
            let mut in_buf = [0u8; 1024];

            loop {
                tokio::select! {
                    n = stdin.read(&mut in_buf) => {
                        match n {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                if write_frame(&mut net_w, FRAME_DATA, &in_buf[..n]).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                    frame = read_frame(&mut net_r) => {
                        match frame {
                            Ok((FRAME_DATA, data)) => {
                                let _ = stdout.write_all(&data).await;
                                let _ = stdout.flush().await;
                            }
                            Ok((FRAME_PING, _)) => {}
                            Ok(_) => {}
                            Err(_) => break,
                        }
                    }
                    _ = tokio::time::sleep(std::time::Duration::from_secs(30)) => {
                        if write_frame(&mut net_w, FRAME_PING, &[]).await.is_err() {
                            break;
                        }
                    }
                }
            }
        } else {
            eprintln!("Unknown subcommand: {subcmd}");
            std::process::exit(1);
        }
    });
}
