// multiport.go — v4 multi-port NAT support.
//
// The problem: behind a NAT VPS (TierHive), the public port the client
// connects to is assigned randomly by the provider and forwarded to a
// different internal port (e.g. external 7102 -> internal 5010). The
// master panel has no "share port" field, so the subscription link
// always carries the inbound's own port. That forces a choice:
//
//   - inbound port = internal port (5010): the link says :5010, which
//     is the dead old forward — the client must edit the link by hand;
//   - inbound port = external port (7102): the link is correct, but
//     the NAT forwards to 5010 and nothing listens there.
//
// The fix: Xray listens on BOTH ports for the same inbound. The
// inbound's own port stays the link port (7102), and the agent
// duplicates the inbound — same protocol, settings, stream settings
// and sniffing, a derived tag — on every extra port listed for it in
// <state-dir>/extra-ports.json. The duplicates are internal only:
// /inbounds/list still reports the single panel inbound, and traffic
// / online stats stay correct because Xray's user counters aggregate
// per email across inbounds (see stats.go), never per inbound.
//
// extra-ports.json format (0600, edited by the operator, read fresh
// on every config render so an edit takes effect on the next agent
// restart or inbound push):
//
//	{"in-7102-tcp": [5010]}
//
// Keys are inbound tags (the Xray tag, e.g. in-7102-tcp); a remark
// is accepted as a fallback key when no tag matches. Values are the
// extra listen ports for that inbound. A missing or unparseable file
// means "no extra ports" — the agent never fails to start over it.

package agent

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
)

// extraPortsFileName is the operator-edited multi-port config, kept
// next to state.json but never written by the agent (panel pushes
// must not be able to clobber it, and the agent must not rewrite
// operator config when it saves state).
const extraPortsFileName = "extra-ports.json"

// apiInboundPort is the loopback stats/API inbound rendered by
// renderConfig; no duplicate may claim it.
const apiInboundPort = 10085

// parseExtraPorts parses extra-ports.json content into
// tag-or-remark -> ports. Returns nil on unparseable input (caller
// treats it as "no extra ports"). Port values are kept raw here;
// extraPortsFor applies the validity and collision rules.
func parseExtraPorts(data []byte) map[string][]int {
	var raw map[string][]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil
	}
	if len(raw) == 0 {
		return nil
	}
	out := make(map[string][]int, len(raw))
	for key, vals := range raw {
		if key == "" {
			continue
		}
		ports := make([]int, 0, len(vals))
		for _, v := range vals {
			// Tolerate a bad element (string, float, null): skip
			// it instead of dropping the whole file.
			f, ok := v.(float64)
			if !ok {
				continue
			}
			p := int(f)
			if float64(p) != f {
				continue
			}
			ports = append(ports, p)
		}
		if len(ports) > 0 {
			out[key] = ports
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// loadExtraPorts reads extra-ports.json from the state dir. A missing
// file, an empty state dir, or unparseable content all mean "no extra
// ports" — multi-port is an operator opt-in, never a startup failure.
func (a *Agent) loadExtraPorts() map[string][]int {
	if a.stateDir == "" {
		return nil
	}
	data, err := os.ReadFile(filepath.Join(a.stateDir, extraPortsFileName))
	if err != nil {
		return nil
	}
	return parseExtraPorts(data)
}

// extraPortsFor resolves the valid extra ports for one inbound:
// the tag key wins, the remark key is the fallback. A port is
// dropped when it is out of range, equals the inbound's own port,
// equals the API inbound port, collides with a port already used by
// another emitted inbound, or repeats an earlier entry. `used` is
// updated with every accepted port so later inbounds cannot collide
// with this one's duplicates either.
func extraPortsFor(ib Inbound, cfg map[string][]int, used map[int]bool) []int {
	if len(cfg) == 0 {
		return nil
	}
	ports, ok := cfg[ib.Tag]
	if !ok {
		ports, ok = cfg[ib.Remark]
		if !ok {
			return nil
		}
	}
	out := make([]int, 0, len(ports))
	for _, p := range ports {
		if p < 1 || p > 65535 {
			continue
		}
		if p == ib.Port || p == apiInboundPort || used[p] {
			continue
		}
		used[p] = true
		out = append(out, p)
	}
	return out
}

// duplicateTag derives the Xray tag for an extra-port duplicate of an
// inbound. The primary tag is unique per inbound, so the derived tag
// is unique too, and the "-nat<port>" suffix makes the NAT purpose
// visible in Xray logs (e.g. in-7102-tcp-nat5010).
func duplicateTag(tag string, port int) string {
	return fmt.Sprintf("%s-nat%d", tag, port)
}

// duplicateTagPort parses a duplicate tag back into its base tag and
// port, for tests and diagnostics. Returns ok=false for non-duplicate
// tags.
func duplicateTagPort(tag string) (base string, port int, ok bool) {
	idx := -1
	for i := len(tag) - 1; i >= 0; i-- {
		if tag[i] == '-' && i+4 < len(tag) && tag[i+1:i+4] == "nat" {
			idx = i
			break
		}
	}
	if idx < 0 {
		return "", 0, false
	}
	p, err := strconv.Atoi(tag[idx+4:])
	if err != nil || p < 1 || p > 65535 {
		return "", 0, false
	}
	return tag[:idx], p, true
}
