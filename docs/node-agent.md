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
`updatePanel` self-update.

## Traffic stats (v2)

Counters are real. The agent exec's the xray-core CLI it already
supervises (`xray api statsquery --server=127.0.0.1:10085 -pattern
">>>traffic>>>"`, at most once per 5 s) and reports per-user
`user>>><email>>>>traffic>>>uplink|downlink` counters via
`/inbounds/list` (`clientStats`) and `/server/status` (`netIO`).
Inbound totals are the sum of their clients (Xray only exposes
per-user counters here). Xray counters reset on every Xray restart,
so the agent keeps a persistent offset per client in `state.json`
(`statBase` / `statLast`): reported = base + raw, and a panel
traffic reset sets base = -raw. See `internal/agent/stats.go`.

## Online status (v3)

`clients/onlines`, `clients/onlinesByGuid`, `clients/lastOnline`,
`clients/activeInbounds` and `clients/clientIpsByGuid` are real in
v3 (they were honest stubs in v1/v2). The model mirrors upstream
(`xray_traffic_job.go`, `inbound_node.go`, `xray/process.go`):

- **Primary signal: traffic delta.** Every stats refresh, the
  emails whose counters moved are recorded with the current unix
  time in `state.json` (`lastOnline`, `inboundLastActive`). A client
  is online while its last move is within the 20 s grace window
  (upstream `onlineGracePeriodMs`), and `lastOnline` keeps the last
  move time after the client ages out. Active inbounds are the tags
  whose clients moved in the same window. A first sighting with
  traffic already on the counter counts as moved (upstream marks any
  client with Up+Down > 0 active on its first poll too).
- **Secondary signal (best-effort union):** `xray api
  statsonlineiplist -all`, refreshed at most once per 30 s and
  unioned into the delta signal, exactly like upstream unions
  `GetUsersStats` with the delta. It also feeds
  `clientIpsByGuid` (`{guid: {email: [{ip, timestamp}]}}`).
- **Verified caveat:** on Xray 26.10.21 the connection-based signal
  is unobservable — a local test server + client with
  `statsUserOnline:true` and a 24 s held, actively-transferring
  connection never produced a `user>>>email>>>online` stat
  (`statsonlineiplist -all` returned `{}` on every poll). v3 does
  **not** depend on it; the delta signal alone shows an
  actively-using client online. `statsUserOnline:true` is still
  enabled in the rendered config (upstream forces it on too), so a
  future core may populate it. See `internal/agent/online.go`.

## Performance notes (v3)

Measured on sgnat (1 CPU, 93 MB RAM): one `xray api statsquery`
exec costs 0.02–0.09 s wall and ~27 MB transient max-RSS. v3 keeps
the per-sync-tick cost at that level:

- All five online endpoints plus `/inbounds/list` share one 5 s
  traffic cache, so a master sync tick costs at most one stats
  exec.
- The online-IP exec runs at most once per 30 s (it only feeds
  `clientIpsByGuid` and the idle-client union).
- `state.json` writes are throttled: `statLast`-only changes flush
  at most once per 60 s (v2 rewrote the 4.3 KB file on every 5 s
  refresh while traffic flowed); `statBase` changes (Xray-restart
  folds, traffic resets) still save immediately, and any pending
  change is flushed on shutdown.
- No new dependencies, no gRPC client: still stdlib only, binary
  ~6.5 MB (v2: 6.6 MB).

## Outbound stats are NOT an agent problem

`sgnat-out` (the VLESS outbound from the nyetrum panel to sgnat)
shows 0 in the panel, and that is expected — two independent
reasons, both verified 2026-11-11:

1. **It lives on the master, not on the node.** `sgnat-out` is a
   local outbound of the nyetrum panel's own Xray. The master never
   fetches outbound traffic from a node (`NodeTrafficSyncJob` only
   pulls `inbounds/list`, onlines, lastOnline, activeInbounds and
   client IPs), and the agent's config has only `direct` + `block`
   outbounds. There is no agent endpoint to fix.
2. **Upstream disables outbound stats by default.** The panel's
   default Xray policy sets `statsOutboundUplink/Downlink: false`
   (`internal/web/service/config.json`), so the nyetrum Xray emits
   no `outbound>>>` counters at all — live proof: `xray api
   statsquery -pattern ">>>traffic>>>"` on nyetrum (API
   127.0.0.1:62789) returns 14 entries, zero `outbound>>>`, while
   inbound + user entries exist. Every outbound on that panel
   shows 0, not just `sgnat-out`. (Enabling the two policy flags
   in the panel's Xray settings would fix the display; that is a
   master-side change, not an agent change.)
3. **Flow 2 never carried traffic anyway.** The sgnat Reality log
   shows zero accepted VLESS connections from nyetrum IPs
   (172.93.167.29 / 2606:6080:2001:1008::a) — only failed handshake
   probes from earlier TLS tests. The routing rule that would send
   client traffic to `sgnat-out` was never installed, so even with
   outbound stats enabled, `sgnat-out` would still read 0 until
   flow 2 is actually used. Do not "fix" this in the agent.

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
| POST | `/clients/onlines`, `/clients/onlinesByGuid`, `/clients/lastOnline`, `/clients/activeInbounds`, `/clients/clientIpsByGuid` | Real in v3 (traffic-delta online + best-effort live-IP union; see "Online status (v3)") |
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
