// online.go — v3 online status.
//
// How upstream decides "online" (internal/web/job/xray_traffic_job.go,
// internal/web/service/inbound_node.go, internal/xray/process.go):
//
//   - Primary signal: traffic delta. Every traffic poll, the emails
//     whose counters moved are recorded with RefreshLocalOnline(); a
//     client is online while its last move is within
//     onlineGracePeriodMs (20 s). lastOnline is the last move time.
//     activeInbounds are the inbound tags whose clients moved in the
//     same window (Xray's user>>>email counter aggregates across
//     inbounds, so the per-inbound view is gated on tags that moved).
//   - Secondary signal (union): connection-based online users from
//     Xray's StatsService.GetUsersStats RPC, which needs
//     statsUserOnline in the policy levels. It covers the delta
//     heuristic's blind spot: an idle-but-connected client moves no
//     bytes between polls. The same RPC also feeds clientIpsByGuid.
//
// What the agent can do on a 93 MB box, stdlib only, no gRPC:
// the xray CLI exposes the same RPC as `xray api statsonlineiplist
// -all` (one exec, one RPC for all users), so the agent queries it
// and unions whatever it returns into the delta signal — exactly
// like upstream unions the two signals.
//
// Corrected 2026-11-13: the caveat below was WRONG for the live box.
// A direct check on sgnat (2026-11-13 09:41 WIB) showed
// `statsonlineiplist -all` DOES return live client IPs, and the
// agent's clientIps/clientIpsByGuid endpoints serve the same data
// the panel IP Log shows. The 2026-11-11 sandbox test that returned
// `{}` must have differed from the live configuration somehow; do
// not treat it as evidence. The connection-based IP signal IS
// observable on Xray 26.10.21 in production. Both signals are live:
// the delta signal marks actively-using clients online, and the CLI
// query adds idle-but-connected clients plus their IPs.
// statsUserOnline stays enabled in the rendered config (upstream
// forces it on for the same reason). The parser below accepts both
// protojson casings.

package agent

import (
	"context"
	"encoding/json"
	"os/exec"
	"sort"
	"time"
)

// onlineGrace mirrors upstream onlineGracePeriodMs (20 s): a client
// whose counters last moved within this window counts as online.
// It must comfortably exceed the 5 s traffic-poll interval so a
// client moving bytes every poll never flickers offline.
const onlineGrace = 20 * time.Second

// onlineIPQueryTTL throttles the second xray CLI exec (the online-IP
// list) separately from the 5 s traffic cache: the delta signal
// already covers onlines/lastOnline/activeInbounds, so the IP list
// — only used for clientIpsByGuid and the idle-client union — is
// refreshed at most twice a minute.
const onlineIPQueryTTL = 30 * time.Second

// stateSaveMinInterval throttles state.json writes for StatLast-only
// changes (see saveStateThrottledLocked): while traffic flows, every
// 5 s refresh would otherwise rewrite the file. StatBase changes
// (Xray-restart folds, traffic resets) still save immediately.
const stateSaveMinInterval = 60 * time.Second

// ClientIpEntry mirrors model.ClientIpEntry: one observed source IP
// for a client, with the unix time it was last seen.
type ClientIpEntry struct {
	IP        string `json:"ip"`
	Timestamp int64  `json:"timestamp"`
}

// onlineIP is one live source address of a client, as reported by
// `xray api statsonlineiplist -all`. LastSeen is unix seconds.
type onlineIP struct {
	IP       string
	LastSeen int64
}

// onlineIPEntry is the wire shape of one IP in the CLI output. Both
// protojson casings are accepted (lastSeen / last_seen); the larger
// wins if both are present.
type onlineIPEntry struct {
	IP          string `json:"ip"`
	LastSeen    int64  `json:"lastSeen"`
	LastSeenAlt int64  `json:"last_seen"`
}

func (e onlineIPEntry) seen() int64 {
	if e.LastSeen > e.LastSeenAlt {
		return e.LastSeen
	}
	return e.LastSeenAlt
}

type onlineUserEntry struct {
	Email string          `json:"email"`
	IPs   []onlineIPEntry `json:"ips"`
}

type onlineListOutput struct {
	Users []onlineUserEntry `json:"users"`
}

// parseOnlineIPs parses `xray api statsonlineiplist -all` JSON into
// email -> live IPs. Returns nil on unparseable input (caller keeps
// the previous snapshot; the delta signal still works).
func parseOnlineIPs(data []byte) map[string][]onlineIP {
	var out onlineListOutput
	if err := json.Unmarshal(data, &out); err != nil {
		return nil
	}
	if len(out.Users) == 0 {
		return nil
	}
	res := make(map[string][]onlineIP, len(out.Users))
	for _, u := range out.Users {
		if u.Email == "" || len(u.IPs) == 0 {
			continue
		}
		ips := make([]onlineIP, 0, len(u.IPs))
		for _, e := range u.IPs {
			if e.IP == "" {
				continue
			}
			ips = append(ips, onlineIP{IP: e.IP, LastSeen: e.seen()})
		}
		if len(ips) > 0 {
			res[u.Email] = ips
		}
	}
	if len(res) == 0 {
		return nil
	}
	return res
}

// queryOnlineIPs exec's the xray CLI once and returns the live
// online-IP map, or nil when the binary is missing, Xray is down,
// the core does not populate the API, or the output is unparseable.
func (a *Agent) queryOnlineIPs() map[string][]onlineIP {
	if a.xrayBin == "" {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, a.xrayBin, "api", "statsonlineiplist",
		"--server=127.0.0.1:10085", "-all")
	out, err := cmd.Output()
	if err != nil {
		return nil
	}
	return parseOnlineIPs(out)
}

// queryOnlineIPsIfDue runs the online-IP query at most once per
// onlineIPQueryTTL and stores the result under statsMu. It returns
// the fresh map and true only when a new query actually ran and
// returned data; otherwise (nil, false) and the caller keeps the
// previous snapshot. A failed query still advances the timer so a
// broken API is not re-probed every 5 s.
func (a *Agent) queryOnlineIPsIfDue() (map[string][]onlineIP, bool) {
	a.statsMu.Lock()
	due := time.Since(a.onlineIPsAt) >= onlineIPQueryTTL
	a.statsMu.Unlock()
	if !due {
		return nil, false
	}
	ips := a.queryOnlineIPs()
	a.statsMu.Lock()
	a.onlineIPsAt = time.Now()
	if ips != nil {
		a.onlineIPs = ips
	}
	a.statsMu.Unlock()
	return ips, ips != nil
}

// recordActivityLocked marks moved emails (traffic delta) and
// live-IP users as active now, and marks the inbounds those emails
// belong to as active. Caller holds a.mu. lastOnline is unix
// seconds, matching upstream GetClientsLastOnline.
func (a *Agent) recordActivityLocked(moved []string, ips map[string][]onlineIP, now time.Time) {
	if a.state.LastOnline == nil {
		a.state.LastOnline = map[string]int64{}
	}
	if a.state.InboundLastActive == nil {
		a.state.InboundLastActive = map[string]int64{}
	}
	unix := now.Unix()
	movedSet := make(map[string]bool, len(moved))
	for _, email := range moved {
		a.state.LastOnline[email] = unix
		movedSet[email] = true
	}
	if len(movedSet) > 0 {
		for _, ib := range a.state.Inbounds {
			for _, email := range clientEmails(ib) {
				if movedSet[email] {
					a.state.InboundLastActive[ib.Tag] = unix
					break
				}
			}
		}
	}
	// Live-IP users are online right now even if they moved no bytes
	// (idle-but-connected); their last-seen is at least now.
	for email, list := range ips {
		last := unix
		for _, ip := range list {
			if ip.LastSeen > last {
				last = ip.LastSeen
			}
		}
		if last > a.state.LastOnline[email] {
			a.state.LastOnline[email] = last
		}
	}
}

// saveStateThrottledLocked persists state.json, but StatLast-only
// changes are flushed at most once per stateSaveMinInterval; a
// baseChanged (restart fold / traffic reset) always saves now, and a
// pending dirty state is flushed on the next call once due.
// Caller holds a.mu.
func (a *Agent) saveStateThrottledLocked(changed, baseChanged bool) {
	if !changed && !a.stateDirty {
		return
	}
	if changed {
		a.stateDirty = true
	}
	if baseChanged || time.Since(a.lastStateSave) >= stateSaveMinInterval {
		_ = a.saveStateLocked()
		a.lastStateSave = time.Now()
		a.stateDirty = false
	}
}

// clientIpsByGuid returns the live-IP snapshot keyed by this
// node's panelGuid, then by client email, in upstream's shape:
// map[guid]map[email][]ClientIpEntry. Empty when the core reports
// no live users (the normal case on Xray 26.10.21, see online.go);
// the master treats an empty map as "no IP signal", not an error.
func (a *Agent) clientIpsByGuid() map[string]map[string][]ClientIpEntry {
	_, _, _, ips := a.onlineSnapshot(time.Now())
	out := map[string]map[string][]ClientIpEntry{}
	if len(ips) == 0 {
		return out
	}
	inner := make(map[string][]ClientIpEntry, len(ips))
	for email, list := range ips {
		entries := make([]ClientIpEntry, 0, len(list))
		for _, ip := range list {
			entries = append(entries, ClientIpEntry{IP: ip.IP, Timestamp: ip.LastSeen})
		}
		inner[email] = entries
	}
	out[a.PanelGuid()] = inner
	return out
}

// InboundClientIps mirrors model.InboundClientIps as the master
// decodes it (upstream internal/web/runtime/remote.go,
// FetchAllClientIps): a JSON LIST of {clientEmail, ips:
// [{ip, timestamp}]}. The master's DecodeCappedList requires the
// first token to be '[', so returning a map here fails every sync
// tick with "expected a JSON array" — the 580x "fetch client ips
// from sgnat failed" warnings seen 12 Nov 2026.
type InboundClientIps struct {
	ClientEmail string          `json:"clientEmail"`
	Ips         []ClientIpEntry `json:"ips"`
}

// clientIpsList is the flat list view of the same live-IP snapshot
// clientIpsByGuid reports per GUID, for GET /server/clientIps.
// Sorted by email for determinism; never nil, so an idle node
// returns [] (decodes cleanly) instead of null or {}.
func (a *Agent) clientIpsList() []InboundClientIps {
	byGuid := a.clientIpsByGuid()
	out := make([]InboundClientIps, 0)
	for _, inner := range byGuid {
		for email, entries := range inner {
			if len(entries) == 0 {
				entries = []ClientIpEntry{}
			}
			out = append(out, InboundClientIps{ClientEmail: email, Ips: entries})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ClientEmail < out[j].ClientEmail })
	return out
}

// onlineSnapshot returns the panel-facing online view at now:
// emails online within the grace window (sorted), the full
// lastOnline map (unix seconds, all known emails), the inbound tags
// active within the grace window (sorted), and the last live-IP
// snapshot. Callers refresh first (shared 5 s cache).
func (a *Agent) onlineSnapshot(now time.Time) (emails []string, lastOnline map[string]int64, activeTags []string, ips map[string][]onlineIP) {
	a.mu.Lock()
	defer a.mu.Unlock()
	cutoff := now.Add(-onlineGrace).Unix()
	lastOnline = make(map[string]int64, len(a.state.LastOnline))
	for email, ts := range a.state.LastOnline {
		lastOnline[email] = ts
		if ts >= cutoff {
			emails = append(emails, email)
		}
	}
	if emails == nil {
		emails = []string{}
	}
	sort.Strings(emails)
	for tag, ts := range a.state.InboundLastActive {
		if ts >= cutoff {
			activeTags = append(activeTags, tag)
		}
	}
	if activeTags == nil {
		activeTags = []string{}
	}
	sort.Strings(activeTags)

	a.statsMu.Lock()
	defer a.statsMu.Unlock()
	ips = make(map[string][]onlineIP, len(a.onlineIPs))
	for email, list := range a.onlineIPs {
		cp := make([]onlineIP, len(list))
		copy(cp, list)
		ips[email] = cp
	}
	return emails, lastOnline, activeTags, ips
}
