# `x-ui-agent-rs` (Single-Binary Rust Agent + Embedded `shoes` + Remote PTY Shell)

An ultra-lightweight, single-binary Rust node agent (`v3.11.0-agent6-rs`) tailored for **`zieru/micro-net-linux`** (128 MB RAM `x86_64` static `musl`, BusyBox `/bin/sh` + `init.d`).

## Key Features
- **Single-Binary Embedded `shoes` (`no jemalloc`)**: Uses `zieru/shoes` (`micro-net-linux` branch) running in-process on a single-threaded `tokio` (`current_thread`) runtime with `musl` system allocator.
- **3x-ui Master Compatibility**: Implements `/panel/api/*` (`Bearer` token + `X-Config-Sha256`) and translates `3x-ui` `Inbound` JSON (`vless` + Reality/Vision/TLS/WS, `vmess`, `trojan`, `shadowsocks`, plus `extra-ports.json` NAT duplication) into `shoes` YAML.
- **Dropbear SSH Replacement (`x-ui-ctl` + `/panel/api/shell/*`)**:
  - Secured by **TLS (`rustls`) + Cert Pinning (`--pin-sha256`) + Ed25519 Signatures + Timestamp (±30s) + Nonce Anti-Replay + Rate Limiting + Optional `--shell-allow-ip`**.
  - Fail-closed if `/etc/x-ui-agent/shell.pub` is absent.
  - Supports both one-shot `exec` and interactive PTY (`openpty` + `/bin/sh -i` + `TIOCSWINSZ`).

## Build & Test
```bash
cargo test
bash scripts/build-musl.sh
```

## Quick Usage (Replacing Dropbear)
1. **On Physical Server**:
   ```bash
   x-ui-ctl keygen
   # Copy printed public key to /etc/x-ui-agent/shell.pub on VPS
   ```
2. **On VPS (`micro-net-linux`)**:
   ```sh
   x-ui-agent-rs -listen :2053 -state-dir /etc/x-ui-agent \
     -tls-cert /etc/x-ui-agent/cert.pem -tls-key /etc/x-ui-agent/key.pem \
     -shell-allow-ip <PHYSICAL_SERVER_IP>
   ```
   Check the startup log for `TLS enabled (cert sha256: <HEX>)`.
3. **Connect from Physical Server**:
   ```bash
   x-ui-ctl shell https://<VPS_IP>:2053 --pin-sha256 <HEX>
   x-ui-ctl exec  https://<VPS_IP>:2053 --pin-sha256 <HEX> "free -m"
   ```
