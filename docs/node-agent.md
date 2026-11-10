# x-ui mini node agent (`cmd/x-ui-agent`)

A drop-in 3x-ui **Node** for a master panel, without running the full
panel on the node. Target: a 93 MB RAM Alpine/OpenRC VPS (sgnat) that
cannot run the full 3x-ui panel (68–74 MiB RSS idle, 259 MB install).

## What it is

- A single Go binary, stdlib only (`net/http`, `encoding/json`,
  `os/exec`). Built with `-trimpath -ldflags "-s -w"`.
- Stores state in one JSON file (`<state-dir>/state.json`, 0600):
  `{panelGuid, nextId, inbounds[]}`. No SQL database.
- Renders a minimal Xray `config.json` from the stored inbounds and
  supervises one `xray-core` child process. Apply is restart-only
  (render → `xray -test` → restart); there is no gRPC hot-apply.
- Serves only the node-sync API the master actually calls, under
  `{basePath}panel/api/` (see `internal/agent/server.go`).

## What it is not (v1)

No web UI, login, sessions, subscription engine, Telegram bot,
fail2ban, LDAP, AmneziaWG/MTProto/TUIC sidecars, zstd, mTLS, or
`updatePanel` self-update. Traffic counters are honest zeros until
the Xray stats API is wired in (the master tolerates that).

## Pairing with the master panel

1. Build and install on the node:

   ```sh
   go build -trimpath -ldflags "-s -w" -o x-ui-agent ./cmd/x-ui-agent
   install -m 0755 x-ui-agent /usr/local/x-ui-agent/x-ui-agent
   install -m 0755 bin/xray-linux-amd64 /usr/local/x-ui-agent/bin/
   cp deploy/x-ui-agent.rc /etc/init.d/x-ui-agent
   chmod +x /etc/init.d/x-ui-agent
   rc-update add x-ui-agent default
   ```

2. Start it once and copy the generated token:

   ```sh
   rc-service x-ui-agent start
   cat /etc/x-ui-agent/token   # 0600, generated once if missing
   ```

3. On the **master** panel (nyetrum), add a Node:

   - Scheme: `http` (Tailscale already encrypts the link; use
     `https` + `skip`/`pin` only if the agent is public)
   - Address: `100.86.255.53` (Tailscale) or the node's public IPv6
   - Port: `2053`
   - Base path: `/`
   - API token: the token from step 2 (scope `node-sync` on the
     agent side is implicit — the agent only accepts this Bearer
     token; never give it a `node-admin` token)
   - **Allow private address: true** — required for Tailscale
     `100.x` addresses, otherwise the master's SSRF guard rejects
     the dial
   - Inbound sync: `all`

   The master probes `GET /server/status` before creating the node,
   so the agent must already be running.

## Endpoints (v1)

| Method | Path | Notes |
|---|---|---|
| GET | `/server/status` | Heartbeat; stable `panelGuid`, cpu/mem from /proc, xray state |
| GET | `/inbounds/list` | Full inbounds incl. `id`, `tag`, `clientStats` |
| POST | `/inbounds/add` | **Form-encoded** (`wireInbound`), returns `{id, tag}` |
| POST | `/inbounds/update/:id` | Form-encoded; `not found` → master falls back to add |
| POST | `/inbounds/del/:id` | Idempotent delete |
| POST | `/inbounds/:id/subSortIndex` | Stored, no-op otherwise |
| POST | `/inbounds/:id/resetTraffic`, `/inbounds/resetAllTraffics` | Zero stored counters |
| POST | `/inbounds/pushClientTraffics` | Accepted and ignored |
| POST | `/clients/add` | JSON `{"client":…, "inboundIds":[…]}`, edits inbound client list |
| POST | `/clients/:email/detach` | JSON `{"inboundIds":[…]}`, `not found` → master treats as success |
| POST | `/clients/del/:email` | Remove from all inbounds |
| POST | `/clients/update/:email?inboundIds=` | JSON = `model.Client` directly |
| POST | `/clients/resetTraffic/:email`, `/clients/bulkResetTraffic` | Zero stored counters |
| POST | `/clients/onlines`, `/clients/onlinesByGuid`, `/clients/lastOnline`, `/clients/activeInbounds` | `[]` / `{}` (honest, not implemented yet) |
| POST | `/server/restartXrayService` | Re-render + test + restart Xray |
| GET | `/server/descendants`, `/hosts/list` | `[]` |
| GET/POST | `/server/clientIps` | `[]` / accept-and-ignore |

All endpoints require `Authorization: Bearer <token>` and return the
panel envelope `{"success":true,"msg":"","obj":…}` with HTTP 200.
Bodies sent by the master carry `X-Config-Sha256`, which the agent
verifies when present. The agent never advertises `X-3x-Node-Caps:
zstd`, so the master always sends plain (uncompressed) bodies.

## Operations

- Logs: agent stdout/stderr via OpenRC; Xray log at
  `<state-dir>/config.json.log`.
- Config: `<state-dir>/config.json` (0600), regenerated on every
  mutating RPC. A config that fails `xray -test` is never installed;
  the old Xray process keeps running.
- Restart survival: `panelGuid` and inbound ids persist in
  `state.json` across restarts and reboots.
- Memory: `GOGC=50`, `GOMEMLIMIT=32MiB` in the OpenRC service.
  Tune after measuring on the node.

## Upstream safety

All agent code lives in `cmd/x-ui-agent/` and `internal/agent/` plus
`deploy/x-ui-agent.rc` and this doc. **No existing panel file is
modified in v1**, so `git fetch upstream && git rebase upstream/main`
should apply with zero conflicts. The agent re-implements the wire
format from the upstream docs; it imports no panel code, so panel
dependency changes cannot break its build.
