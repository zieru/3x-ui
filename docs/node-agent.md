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

## Multi-port NAT support (v4)

Behind a NAT VPS (TierHive), the port the client connects to is
assigned randomly by the provider and forwarded to a *different*
internal port — for example, external `7102` forwards to internal
`5010`. The master panel has no "share port" field: the subscription
link always carries the inbound's own port. That forces a broken
choice — inbound port = internal port makes the link point at the
dead forward (the client must edit it by hand), and inbound port =
external port makes Xray listen where the NAT never delivers.

v4 resolves it by listening on **both** ports for one inbound:

- **Link port = inbound port in the panel = external TierHive
  port.** The panel inbound keeps port `7102`, so the subscription
  link reads `sg.wg.tsel.my.id:7102` and no client ever edits
  anything by hand.
- **Internal TierHive port = extra port in the agent.** The agent
  duplicates the inbound onto port `5010` with the same protocol,
  settings, stream settings and sniffing, under a derived tag
  (`in-7102-tcp-nat5010`). The NAT forwards `7102 -> 5010`, Xray
  answers on `5010`, and the client never knows the difference.
- The duplicates are **internal to the rendered `config.json`
  only**: `/inbounds/list` still reports the single panel inbound,
  and traffic/online stats stay correct because Xray's user
  counters aggregate per email across inbounds — a client using
  either port increments the same counter once, never twice.

Configuration lives in `<state-dir>/extra-ports.json` (0600,
operator-edited, never written by the agent or by panel pushes):

```json
{"in-7102-tcp": [5010]}
```

Keys are inbound tags (`in-<port>-<network>`, visible in
`state.json` or `/inbounds/list`); a remark is accepted as a
fallback key when no tag matches. The file is read fresh on every
config render, so adding a port is: edit the file, then restart
the agent (`rc-service x-ui-agent restart`) or trigger any inbound
push from the panel. A missing or malformed file means "no extra
ports" — the agent never fails to start over it.

Safety rules (see `internal/agent/multiport.go`): an extra port is
dropped when it is out of range, equals the inbound's own port,
equals the API port (`10085`), or collides with any other
inbound's port. The rendered config is still validated with
`xray -test` before it is installed, so a bad mapping can never
break the running Xray.

When the provider assigns a **new** external port, only two things
change: the panel inbound port (which updates the link) and the
extra-ports mapping (which keeps the internal forward answered).
If the internal forward port also changes, update the mapping to
the new internal port — the link stays untouched.

## Hot-apply (v5)

Before v5, every panel push restarted Xray, dropping ALL active
connections on the node for 1-3 s — including users untouched by
the change. v5 mirrors upstream `internal/xray/hot_diff.go`: when
a new rendered config differs from the running one ONLY in the
client lists of existing inbounds, the delta is applied through
Xray's runtime API instead of restarting. Disabling one client no
longer disconnects the others.

Mechanics (see `internal/agent/hotapply.go`):

- The diff compares the new render against the config on disk,
  tag by tag: same port/protocol/listen/streamSettings/sniffing
  and same settings-minus-clients, clients diffed by email. A
  changed client is remove+add. Only the upstream user-diffable
  protocols (vless/vmess/trojan/hysteria/masque/shadowsocks) go
  hot; reverse-tagged clients, inbound add/remove, and any other
  change take the restart path.
- Multi-port duplicates are covered automatically: the diff runs
  on rendered tags, so a removed user is removed from the primary
  tag AND every `-nat<port>` duplicate.
- Ops run through the `xray api` CLI (stdlib-only agent, no gRPC
  client): `rmu` batched per tag for removals, `adu` per tag for
  additions. The new config is written to disk (and `xray -test`ed)
  BEFORE the ops run, so a later restart loads the same user set.
  Any op failure falls back to a full restart, which converges.
- **v5 also fixes a real bug:** `renderConfig` now drops clients
  with `"enable": false`, mirroring upstream `GetXrayConfig`.
  Before v5 a client disabled in the panel kept connecting through
  this node, because the settings JSON was rendered verbatim.

`xray api adu` gotchas, verified against Xray 26.10.21:

- The payload must be a FULL CONFIG document
  (`{"inbounds":[...]}`), not a bare inbound object: adu decodes
  each file with `serial.DecodeJSONConfig` and takes
  `.InboundConfigs`. A bare inbound silently adds 0 users.
- The inbound in the payload must carry listen/port/protocol/
  settings so `Build()` succeeds (TLS/Reality inbounds need their
  streamSettings too — the adu payload is the full rendered
  inbound with only the added clients).
- adu/rmu exit 0 even when they add/remove 0 users. The agent
  parses the `Added N user(s) in total.` / `Removed N user(s) in
  total.` line and treats any mismatch as a failure.

## Self-update from GitHub Releases (v6, combined agent + core)

Builds ship from GitHub Actions, and the agent installs them itself —
both its own binary and the pinned Xray core binary:

- `.github/workflows/agent-release.yml` runs on every push to an
  `agent-v*` branch that touches agent code: vet + tests, then a
  static build (`CGO_ENABLED=0`, linux/amd64), then it fetches the
  pinned Xray core (see below) and publishes six assets to the
  floating `agent-latest` release: the agent binary, its `.sha256`,
  and `version.txt`, plus the core binary, its `.sha256`, and
  `core-version.txt`. `.github/workflows/agent-ci.yml` runs vet +
  tests only. The connector token cannot push workflow files (403,
  no `workflow` scope) — workflow files are added by the operator
  via the GitHub web UI.
- The pinned core version lives in
  `internal/agent/xray-core-version.txt` (single line, e.g.
  `26.11.9`). It is bumped only after the new core's compatibility
  with the agent is verified: adu/rmu output lines, statsquery and
  statsonlineiplist shapes, `xray -test` against the rendered
  config, and client handshakes (XHTTP+TLS and Reality) from the
  client versions in use. The workflow downloads the matching
  `Xray-linux-64.zip` from the upstream release, verifies its
  SHA2-256 against the published `.dgst`, and checks the extracted
  binary reports the pinned version.
- The agent polls the release every 6 hours (first check 5 minutes
  after start). The agent binary installs when `version.txt` is
  newer than the running `Version`; the core installs when the pin
  differs from the installed core binary — the pin wins over
  "newer", so a lowered pin deliberately downgrades. Each wanted
  artifact is downloaded, SHA-256 verified, and smoke-tested
  before anything is replaced: the staged agent binary must pass
  `-version`, and the staged core binary must report the pinned
  version AND pass `xray -test` against the live config. Then both
  are installed over the live binaries (keeping `.bak` copies),
  Xray is stopped, and the agent re-execs itself — same PID, so
  OpenRC keeps tracking it. A failed verification installs
  nothing.
- Two gates, both files under the state dir: the marker file
  `autoupdate` (presence enables installing) and `github-token`
  (0600, a fine-grained PAT with Contents: Read on zieru/3x-ui —
  required because the repository is private). Without the token
  the updater stays dormant; without the marker the background
  loop only checks.
- Manual endpoints (Bearer auth, same as the rest of the API):
  `POST server/checkUpdate` (read-only, no marker needed) and
  `POST server/applyUpdate` with optional `{"force":true}` to
  reinstall the same versions. `server/status` reports
  `updateAvailable`, `latestVersion`, `autoUpdate`,
  `coreUpdateAvailable`, and `latestCoreVersion`.
  `server/updatePanel` stays refused: the panel's "Update node"
  button must never drive updates.
- Core compatibility matrix (verified in the sandbox 2026-11-13
  for the 26.11.9 pin): `xray -test` passes on a sgnat-like
  config; statsquery / statsonlineiplist / inboundusercount
  shapes unchanged; adu prints `Added N user(s) in total.` and
  rmu prints `Removed N user(s) in total.` exactly as the agent's
  parser expects; XHTTP+TLS and Reality handshakes from 26.10.21
  clients succeed. One caveat: `statsonlineiplist` returns `{}` in
  the sandbox on both 26.10.21 and 26.11.9 (it returns live IPs on
  the production node), so the IP listing must be re-verified on
  the node after any core swap, with the `.bak` core ready for
  rollback.

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
   CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o x-ui-agent ./cmd/x-ui-agent
   # CGO_ENABLED=0 is mandatory: Alpine/musl has no glibc loader, and
   # a dynamically-linked binary fails with "No such file or directory".
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
- Multi-port (v4): `<state-dir>/extra-ports.json` (0600) maps
  inbound tags to extra listen ports; see "Multi-port NAT support
  (v4)". Edit + `rc-service x-ui-agent restart` to apply.
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
