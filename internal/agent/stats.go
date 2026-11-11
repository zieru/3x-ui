package agent

import (
	"context"
	"encoding/json"
	"os/exec"
	"strings"
	"time"
)

// stats.go — v2 traffic stats.
//
// The agent reads per-user counters from Xray's own stats API, using
// the `xray api statsquery` CLI that ships in the same xray-core
// binary the agent already supervises. No gRPC library is needed
// (the binary is 34 MB but it is already on disk; exec'ing it is far
// cheaper than vendoring a gRPC stack into a 6.5 MB agent).
//
// Verified on sgnat (Xray 26.10.21, API 127.0.0.1:10085):
//
//	xray api statsquery --server=127.0.0.1:10085 -pattern ">>>traffic>>>"
//	{"stat": [
//	  {"name": "user>>>nazirul777@yahoo.co.id>>>traffic>>>uplink", "value": 4191380},
//	  {"name": "user>>>nazirul777@yahoo.co.id>>>traffic>>>downlink", "value": 6272607}
//	]}
//
// Only user counters exist (the agent's config enables statsUserUplink
// / statsUserDownlink, not statsInbound*), so an inbound's total is
// the sum of its clients' counters.
//
// Xray counters reset to 0 whenever Xray restarts, so the agent keeps
// a persistent offset per client in state.json (StatBase / StatLast):
// reported = base + raw. When a query sees raw < last, Xray must have
// restarted, so base += last. A panel traffic reset sets
// base = -raw, which reports 0 without touching Xray's counters.
// Offsets survive agent restarts because they live in state.json.

const statsCacheTTL = 5 * time.Second

// statPair is one user's raw Xray counters (since Xray started).
type statPair struct {
	Up   int64
	Down int64
}

// statsQueryOutput is the JSON `xray api statsquery` prints.
type statsQueryOutput struct {
	Stat []struct {
		Name  string `json:"name"`
		Value int64  `json:"value"`
	} `json:"stat"`
}

// parseStatsQuery parses `xray api statsquery` JSON into
// email -> statPair. Names look like
// "user>>><email>>>>traffic>>>uplink|downlink".
func parseStatsQuery(data []byte) map[string]statPair {
	var out statsQueryOutput
	if err := json.Unmarshal(data, &out); err != nil {
		return nil
	}
	res := make(map[string]statPair, len(out.Stat))
	for _, s := range out.Stat {
		parts := strings.Split(s.Name, ">>>")
		if len(parts) != 4 || parts[0] != "user" || parts[2] != "traffic" {
			continue
		}
		p := res[parts[1]]
		switch parts[3] {
		case "uplink":
			p.Up = s.Value
		case "downlink":
			p.Down = s.Value
		default:
			continue
		}
		res[parts[1]] = p
	}
	return res
}

// queryXrayStats exec's the xray CLI once and returns the raw
// per-user counters. Returns nil (no error) when the binary is
// missing or Xray is not running, so callers keep the last snapshot.
func (a *Agent) queryXrayStats() map[string]statPair {
	if a.xrayBin == "" {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, a.xrayBin, "api", "statsquery",
		"--server=127.0.0.1:10085", "-pattern", ">>>traffic>>>")
	out, err := cmd.Output()
	if err != nil {
		return nil
	}
	return parseStatsQuery(out)
}

// refreshStats queries Xray (at most once per statsCacheTTL) and folds
// the raw counters into the persistent offsets in state.json. It is
// safe to call from any endpoint handler; it never holds a.mu while
// exec'ing, and never holds statsMu while holding a.mu.
func (a *Agent) refreshStats() {
	a.statsMu.Lock()
	if time.Since(a.statsAt) < statsCacheTTL && a.statsRaw != nil {
		a.statsMu.Unlock()
		return
	}
	a.statsMu.Unlock()

	raw := a.queryXrayStats()
	if raw == nil {
		return // Xray down / API unreachable: keep last snapshot.
	}

	a.mu.Lock()
	changed := a.mergeRawLocked(raw)
	if changed {
		_ = a.saveStateLocked()
	}
	a.mu.Unlock()

	a.statsMu.Lock()
	a.statsRaw = raw
	a.statsAt = time.Now()
	a.statsMu.Unlock()
}

// mergeRawLocked folds raw Xray counters into StatBase/StatLast.
// Caller holds a.mu. Returns true when the persisted offsets changed.
func (a *Agent) mergeRawLocked(raw map[string]statPair) bool {
	if a.state.StatBase == nil {
		a.state.StatBase = map[string]int64{}
	}
	if a.state.StatLast == nil {
		a.state.StatLast = map[string]int64{}
	}
	changed := false
	// Known emails: prune offsets for clients that no longer exist.
	known := map[string]bool{}
	for _, ib := range a.state.Inbounds {
		for _, c := range settingsClients(ib.Settings) {
			if e := clientEmail(c); e != "" {
				known[e] = true
			}
		}
	}
	for k := range a.state.StatBase {
		email := strings.SplitN(k, "|", 2)[0]
		if !known[email] {
			delete(a.state.StatBase, k)
			delete(a.state.StatLast, k)
			changed = true
		}
	}
	for email, p := range raw {
		if !known[email] {
			continue
		}
		for _, dir := range []struct {
			key string
			val int64
		}{{"uplink", p.Up}, {"downlink", p.Down}} {
			bk := email + "|" + dir.key
			last, seen := a.state.StatLast[bk]
			if !seen {
				// First sighting: adopt the current raw value as the
				// baseline (no base yet, so reported == raw).
				a.state.StatLast[bk] = dir.val
				changed = true
				continue
			}
			if dir.val < last {
				// Xray restarted and its counter reset to 0: fold
				// everything counted so far into the base.
				a.state.StatBase[bk] += last
				changed = true
			}
			if a.state.StatLast[bk] != dir.val {
				a.state.StatLast[bk] = dir.val
				changed = true
			}
		}
	}
	return changed
}

// statsSnapshot returns a copy of the last raw counters.
func (a *Agent) statsSnapshot() map[string]statPair {
	a.statsMu.Lock()
	defer a.statsMu.Unlock()
	out := make(map[string]statPair, len(a.statsRaw))
	for k, v := range a.statsRaw {
		out[k] = v
	}
	return out
}

// reportedTraffic returns the persistent (base + raw) up/down for one
// client email. Caller holds a.mu (base lives in state); the raw
// snapshot is read under statsMu, so lock order is a.mu -> statsMu.
func (a *Agent) reportedTraffic(email string) (up, down int64) {
	raw := a.statsSnapshot()
	p := raw[email]
	up = a.state.StatBase[email+"|uplink"] + p.Up
	down = a.state.StatBase[email+"|downlink"] + p.Down
	if up < 0 {
		up = 0
	}
	if down < 0 {
		down = 0
	}
	return up, down
}

// zeroTrafficLocked zeroes the reported counters for the given emails
// by setting base = -raw (Xray's own counters are untouched).
// Caller holds a.mu; raw is the current snapshot.
func (a *Agent) zeroTrafficLocked(emails []string) {
	raw := a.statsSnapshot()
	for _, email := range emails {
		p := raw[email]
		a.state.StatBase[email+"|uplink"] = -p.Up
		a.state.StatBase[email+"|downlink"] = -p.Down
		a.state.StatLast[email+"|uplink"] = p.Up
		a.state.StatLast[email+"|downlink"] = p.Down
	}
}

// clientEmails returns every client email in the given inbound.
func clientEmails(ib Inbound) []string {
	out := []string{}
	for _, c := range settingsClients(ib.Settings) {
		if e := clientEmail(c); e != "" {
			out = append(out, e)
		}
	}
	return out
}
