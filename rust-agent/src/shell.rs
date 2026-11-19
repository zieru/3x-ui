use aws_lc_rs::signature::{UnparsedPublicKey, ED25519};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use bytes::Bytes;
use http_body_util::Full;
use hyper::header::{CONNECTION, UPGRADE};
use hyper::{HeaderMap, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use serde::Deserialize;
use serde_json::json;
use std::collections::{HashMap, VecDeque};
use std::ffi::CString;
use std::fs;
use std::net::IpAddr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;
use tokio::sync::Mutex;

use crate::state::sha256_hex;
use crate::stats::now_unix;

const MAX_TS_SKEW_SECS: i64 = 30;
const MAX_NONCES: usize = 1024;
const RATE_LIMIT_FAILS: u32 = 5;
const RATE_LIMIT_WINDOW_SECS: i64 = 60;
const MAX_PTY_SESSIONS: usize = 2;
const PTY_IDLE_TIMEOUT: Duration = Duration::from_secs(15 * 60);
const MAX_EXEC_OUTPUT: usize = 1024 * 1024;

pub const FRAME_DATA: u8 = 0x01;
pub const FRAME_RESIZE: u8 = 0x02;
pub const FRAME_PING: u8 = 0x03;

pub struct ShellGuard {
    pub_key_path: PathBuf,
    allow_ip: Option<IpAddr>,
    nonces: Mutex<VecDeque<(String, i64)>>,
    failures: Mutex<HashMap<IpAddr, (u32, i64)>>,
    active_ptys: Arc<AtomicUsize>,
}

impl ShellGuard {
    pub fn new(pub_key_path: PathBuf, allow_ip: Option<IpAddr>) -> Self {
        Self {
            pub_key_path,
            allow_ip,
            nonces: Mutex::new(VecDeque::with_capacity(MAX_NONCES)),
            failures: Mutex::new(HashMap::new()),
            active_ptys: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn load_pubkey(&self) -> Result<Vec<u8>, (StatusCode, &'static str)> {
        let raw = fs::read_to_string(&self.pub_key_path)
            .map_err(|_| (StatusCode::FORBIDDEN, "shell disabled (shell.pub not configured)"))?;
        let trimmed = raw.trim();
        if trimmed.len() == 64 {
            if let Ok(bytes) = hex::decode(trimmed) {
                return Ok(bytes);
            }
        }
        B64.decode(trimmed)
            .ok()
            .filter(|b| b.len() == 32)
            .ok_or((StatusCode::FORBIDDEN, "invalid shell.pub format"))
    }

    async fn record_failure(&self, ip: IpAddr, now: i64) {
        let mut map = self.failures.lock().await;
        let entry = map.entry(ip).or_insert((0, now));
        if now - entry.1 > RATE_LIMIT_WINDOW_SECS {
            *entry = (1, now);
        } else {
            entry.0 += 1;
            entry.1 = now;
        }
    }

    async fn is_rate_limited(&self, ip: IpAddr, now: i64) -> bool {
        let mut map = self.failures.lock().await;
        if let Some(&(count, ts)) = map.get(&ip) {
            if now - ts <= RATE_LIMIT_WINDOW_SECS {
                return count >= RATE_LIMIT_FAILS;
            }
            map.remove(&ip);
        }
        false
    }

    pub async fn verify_request(
        &self,
        peer_ip: IpAddr,
        method: &str,
        path: &str,
        headers: &HeaderMap,
        body: &[u8],
    ) -> Result<(), (StatusCode, &'static str)> {
        let pubkey = self.load_pubkey()?;

        if let Some(allowed) = self.allow_ip {
            if peer_ip != allowed {
                return Err((StatusCode::FORBIDDEN, "ip not allowed for shell"));
            }
        }

        let now = now_unix();
        if self.is_rate_limited(peer_ip, now).await {
            return Err((StatusCode::TOO_MANY_REQUESTS, "too many failed shell auths"));
        }

        let ts_str = headers
            .get("x-shell-timestamp")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let Ok(ts) = ts_str.parse::<i64>() else {
            self.record_failure(peer_ip, now).await;
            return Err((StatusCode::UNAUTHORIZED, "missing or invalid X-Shell-Timestamp"));
        };
        if (now - ts).abs() > MAX_TS_SKEW_SECS {
            self.record_failure(peer_ip, now).await;
            return Err((StatusCode::UNAUTHORIZED, "X-Shell-Timestamp expired"));
        }

        let nonce = headers
            .get("x-shell-nonce")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if nonce.len() < 8 || nonce.len() > 64 {
            self.record_failure(peer_ip, now).await;
            return Err((StatusCode::UNAUTHORIZED, "invalid X-Shell-Nonce"));
        }

        let sig_b64 = headers
            .get("x-shell-signature")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let Ok(sig_bytes) = B64.decode(sig_b64.trim()) else {
            self.record_failure(peer_ip, now).await;
            return Err((StatusCode::UNAUTHORIZED, "invalid X-Shell-Signature"));
        };

        let msg = format!("{method}\n{path}\n{ts}\n{nonce}\n{}", sha256_hex(body));
        let verifier = UnparsedPublicKey::new(&ED25519, &pubkey);
        if verifier.verify(msg.as_bytes(), &sig_bytes).is_err() {
            self.record_failure(peer_ip, now).await;
            log::warn!("shell auth failed from {peer_ip}");
            return Err((StatusCode::UNAUTHORIZED, "ed25519 signature verification failed"));
        }

        // Check & record nonce for replay protection
        let mut nonces = self.nonces.lock().await;
        while let Some((_, old_ts)) = nonces.front() {
            if now - *old_ts > MAX_TS_SKEW_SECS * 2 {
                nonces.pop_front();
            } else {
                break;
            }
        }
        if nonces.iter().any(|(n, _)| n == nonce) {
            self.record_failure(peer_ip, now).await;
            return Err((StatusCode::UNAUTHORIZED, "replayed nonce"));
        }
        if nonces.len() >= MAX_NONCES {
            nonces.pop_front();
        }
        nonces.push_back((nonce.to_string(), now));

        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ExecReq {
    cmd: String,
    #[serde(default = "default_timeout")]
    timeout_secs: u64,
}

fn default_timeout() -> u64 {
    30
}

pub async fn handle_exec(peer_ip: IpAddr, body: &[u8]) -> serde_json::Value {
    let Ok(req) = serde_json::from_slice::<ExecReq>(body) else {
        return json!({"exitCode": -1, "stdout": "", "stderr": "invalid json"});
    };
    let timeout = Duration::from_secs(req.timeout_secs.clamp(1, 120));
    log::info!("shell exec from {peer_ip}: {} bytes cmd", req.cmd.len());

    let child = Command::new("/bin/sh")
        .arg("-c")
        .arg(&req.cmd)
        .output();

    match tokio::time::timeout(timeout, child).await {
        Ok(Ok(out)) => {
            let mut stdout = String::from_utf8_lossy(&out.stdout).into_owned();
            let mut stderr = String::from_utf8_lossy(&out.stderr).into_owned();
            stdout.truncate(MAX_EXEC_OUTPUT);
            stderr.truncate(MAX_EXEC_OUTPUT);
            json!({
                "exitCode": out.status.code().unwrap_or(-1),
                "stdout": stdout,
                "stderr": stderr,
            })
        }
        Ok(Err(e)) => json!({"exitCode": -1, "stdout": "", "stderr": format!("exec error: {e}")}),
        Err(_) => json!({"exitCode": -1, "stdout": "", "stderr": "command timed out"}),
    }
}

pub fn upgrade_pty(
    guard: Arc<ShellGuard>,
    peer_ip: IpAddr,
    req: Request<hyper::body::Incoming>,
) -> Response<Full<Bytes>> {
    let cur = guard.active_ptys.load(Ordering::SeqCst);
    if cur >= MAX_PTY_SESSIONS {
        return Response::builder()
            .status(StatusCode::SERVICE_UNAVAILABLE)
            .body(Full::new(Bytes::from_static(b"max concurrent pty sessions reached")))
            .unwrap();
    }

    guard.active_ptys.fetch_add(1, Ordering::SeqCst);
    let counter = guard.active_ptys.clone();

    log::info!("shell pty session started from {peer_ip}");
    tokio::task::spawn_local(async move {
        match hyper::upgrade::on(req).await {
            Ok(upgraded) => {
                if let Err(e) = run_pty_bridge(TokioIo::new(upgraded)).await {
                    log::debug!("pty session ended: {e}");
                }
            }
            Err(e) => log::warn!("pty upgrade error: {e}"),
        }
        counter.fetch_sub(1, Ordering::SeqCst);
        log::info!("shell pty session closed from {peer_ip}");
    });

    Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .header(CONNECTION, "Upgrade")
        .header(UPGRADE, "x-ui-pty")
        .body(Full::new(Bytes::new()))
        .unwrap()
}

fn spawn_openpty_shell() -> std::io::Result<(OwnedFd, libc::pid_t)> {
    let mut master: libc::c_int = -1;
    let mut slave: libc::c_int = -1;
    let mut ws = libc::winsize {
        ws_row: 24,
        ws_col: 80,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };

    let rc = unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut ws,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }

    let pid = unsafe { libc::fork() };
    if pid < 0 {
        unsafe {
            libc::close(master);
            libc::close(slave);
        }
        return Err(std::io::Error::last_os_error());
    }

    if pid == 0 {
        unsafe {
            libc::close(master);
            libc::setsid();
            libc::ioctl(slave, libc::TIOCSCTTY as _, 0);
            libc::dup2(slave, 0);
            libc::dup2(slave, 1);
            libc::dup2(slave, 2);
            if slave > 2 {
                libc::close(slave);
            }
            let sh = CString::new("/bin/sh").unwrap();
            let arg0 = CString::new("-sh").unwrap();
            let arg1 = CString::new("-i").unwrap();
            let argv = [arg0.as_ptr(), arg1.as_ptr(), std::ptr::null()];
            libc::execv(sh.as_ptr(), argv.as_ptr());
            libc::_exit(127);
        }
    }

    unsafe {
        libc::close(slave);
        let flags = libc::fcntl(master, libc::F_GETFL);
        libc::fcntl(master, libc::F_SETFL, flags | libc::O_NONBLOCK);
    }

    let fd = unsafe { OwnedFd::from_raw_fd(master) };
    Ok((fd, pid))
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
    if len > 1024 * 1024 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "frame too large",
        ));
    }
    let mut buf = vec![0u8; len];
    if len > 0 {
        r.read_exact(&mut buf).await?;
    }
    Ok((ftype, buf))
}

async fn run_pty_bridge<S: AsyncReadExt + AsyncWriteExt + Unpin>(stream: S) -> std::io::Result<()> {
    let (master_fd, child_pid) = spawn_openpty_shell()?;
    let raw_fd = master_fd.as_raw_fd();
    let async_fd = AsyncFd::new(master_fd)?;
    let (mut net_r, mut net_w) = tokio::io::split(stream);

    let mut pty_buf = [0u8; 4096];
    let res: std::io::Result<()> = loop {
        tokio::select! {
            _ = tokio::time::sleep(PTY_IDLE_TIMEOUT) => {
                break Ok(());
            }
            ready = async_fd.readable() => {
                let mut guard = match ready {
                    Ok(g) => g,
                    Err(e) => break Err(e),
                };
                match guard.try_io(|inner| {
                    let n = unsafe {
                        libc::read(inner.as_raw_fd(), pty_buf.as_mut_ptr() as *mut libc::c_void, pty_buf.len())
                    };
                    if n < 0 {
                        Err(std::io::Error::last_os_error())
                    } else {
                        Ok(n as usize)
                    }
                }) {
                    Ok(Ok(0)) => break Ok(()),
                    Ok(Ok(n)) => {
                        if let Err(e) = write_frame(&mut net_w, FRAME_DATA, &pty_buf[..n]).await {
                            break Err(e);
                        }
                    }
                    Ok(Err(e)) => break Err(e),
                    Err(_would_block) => continue,
                }
            }
            frame = read_frame(&mut net_r) => {
                match frame {
                    Ok((FRAME_DATA, data)) => {
                        let mut off = 0;
                        while off < data.len() {
                            let n = unsafe {
                                libc::write(raw_fd, data[off..].as_ptr() as *const libc::c_void, data.len() - off)
                            };
                            if n < 0 {
                                let err = std::io::Error::last_os_error();
                                if err.kind() == std::io::ErrorKind::WouldBlock {
                                    tokio::time::sleep(Duration::from_millis(5)).await;
                                    continue;
                                }
                                break;
                            }
                            off += n as usize;
                        }
                    }
                    Ok((FRAME_RESIZE, data)) if data.len() == 4 => {
                        let cols = u16::from_be_bytes([data[0], data[1]]);
                        let rows = u16::from_be_bytes([data[2], data[3]]);
                        let ws = libc::winsize {
                            ws_row: rows,
                            ws_col: cols,
                            ws_xpixel: 0,
                            ws_ypixel: 0,
                        };
                        unsafe {
                            libc::ioctl(raw_fd, libc::TIOCSWINSZ, &ws);
                        }
                    }
                    Ok((FRAME_PING, _)) => {
                        let _ = write_frame(&mut net_w, FRAME_PING, &[]).await;
                    }
                    Ok(_) => {}
                    Err(_) => break Ok(()),
                }
            }
        }
    };

    unsafe {
        libc::kill(child_pid, libc::SIGHUP);
        let mut status = 0;
        libc::waitpid(child_pid, &mut status, libc::WNOHANG);
    }
    res
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_lc_rs::rand::SystemRandom;
    use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair};
    use std::net::Ipv4Addr;

    #[tokio::test]
    async fn test_ed25519_auth_replay_and_rate_limit() {
        let dir = std::env::temp_dir().join(format!("xui-shell-test-{}", now_unix()));
        fs::create_dir_all(&dir).unwrap();
        let pub_path = dir.join("shell.pub");

        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let kp = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();

        let guard = ShellGuard::new(pub_path.clone(), None);
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        // 1. Missing shell.pub -> 403 Forbidden
        let empty = HeaderMap::new();
        let err = guard.verify_request(ip, "POST", "/panel/api/shell/exec", &empty, b"{}").await.unwrap_err();
        assert_eq!(err.0, StatusCode::FORBIDDEN);

        // Write shell.pub
        fs::write(&pub_path, B64.encode(kp.public_key().as_ref())).unwrap();

        // 2. Valid signature -> Ok
        let ts = now_unix().to_string();
        let nonce = "test-nonce-123456";
        let body = b"{\"cmd\":\"uname -a\"}";
        let msg = format!("POST\n/panel/api/shell/exec\n{ts}\n{nonce}\n{}", sha256_hex(body));
        let sig = kp.sign(msg.as_bytes());

        let mut hdrs = HeaderMap::new();
        hdrs.insert("x-shell-timestamp", ts.parse().unwrap());
        hdrs.insert("x-shell-nonce", nonce.parse().unwrap());
        hdrs.insert("x-shell-signature", B64.encode(sig.as_ref()).parse().unwrap());

        guard.verify_request(ip, "POST", "/panel/api/shell/exec", &hdrs, body).await.unwrap();

        // 3. Replay same nonce -> 401
        let err = guard.verify_request(ip, "POST", "/panel/api/shell/exec", &hdrs, body).await.unwrap_err();
        assert_eq!(err.0, StatusCode::UNAUTHORIZED);

        // 4. Rate limit after 5 failures -> 429
        for _ in 0..5 {
            let _ = guard.verify_request(ip, "POST", "/panel/api/shell/exec", &empty, body).await;
        }
        let err = guard.verify_request(ip, "POST", "/panel/api/shell/exec", &hdrs, body).await.unwrap_err();
        assert_eq!(err.0, StatusCode::TOO_MANY_REQUESTS);

        let _ = fs::remove_dir_all(&dir);
    }
}
