package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// hotapply.go — v5 hot-apply.
//
// Problem: every panel push restarted Xray, dropping ALL active
// connections on the node for 1-3 s — including users untouched by
// the change. Disabling one client must not disconnect the others.
//
// Solution, mirroring upstream internal/xray/hot_diff.go: when a new
// rendered config differs from the running one ONLY in the client
// lists of existing inbounds, apply the delta through Xray's runtime
// API (`xray api adu` / `xray api rmu`) instead of restarting. Any
// other change (port, transport, TLS/Reality settings, sniffing,
// inbound added/removed, non-user-diffable protocol) still takes the
// full restart path, as does any API failure — a failed hot-apply
// always falls back to a restart, which converges to the new config
// on disk.
//
// The agent has no gRPC client (stdlib only, by design), so the ops
// go through the `xray api` CLI shipped in the same binary already
// supervised — the same approach stats.go uses for statsquery.
//
// Verified against Xray 26.10.21 (see the v5 notes in
// docs/node-agent.md):
//
//   - `xray api adu` reads FULL CONFIG files (`{"inbounds":[...]}`),
//     not bare inbound objects: it decodes each file with
//     serial.DecodeJSONConfig and takes .InboundConfigs. A bare
//     inbound object decodes to zero inbounds and silently adds
//     0 users while exiting 0. The payload must also carry the
//     inbound's listen/port/protocol/settings so Build() succeeds.
//   - adu/rmu exit 0 even when they add/remove 0 users, so the
//     "Added N user(s) in total." / "Removed N user(s) in total."
//     lines MUST be parsed and compared against the expected count.
//   - Users added at runtime are lost on restart, so the new config
//     is always written to disk (and `xray -test`ed) BEFORE the ops
//     run; a later restart then loads exactly the same user set.

// xrayAPIAddr is the loopback API endpoint the agent's rendered
// config always exposes (see renderConfig's "api" inbound).
const xrayAPIAddr = "127.0.0.1:10085"

// userDiffableProtocols mirrors upstream userDiffableProtocols: the
// protocols whose client lists can be diffed per user.
var userDiffableProtocols = map[string]bool{
	"vless": true, "vmess": true, "trojan": true,
	"hysteria": true, "masque": true, "shadowsocks": true,
}

// filterDisabledClients drops clients with "enable": false from a
// settings JSON string, mirroring upstream GetXrayConfig, which
// skips disabled clients when building the core config. A missing
// "enable" field means enabled (same default as clientStatsFor).
// Settings without a clients array are returned unchanged.
func filterDisabledClients(settings string) string {
	if settings == "" {
		return settings
	}
	var parsed map[string]any
	dec := json.NewDecoder(strings.NewReader(settings))
	dec.UseNumber()
	if err := dec.Decode(&parsed); err != nil {
		return settings
	}
	raw, ok := parsed["clients"].([]any)
	if !ok {
		return settings
	}
	kept := make([]any, 0, len(raw))
	changed := false
	for _, c := range raw {
		m, ok := c.(map[string]any)
		if !ok {
			kept = append(kept, c)
			continue
		}
		if enable, ok := m["enable"].(bool); ok && !enable {
			changed = true
			continue
		}
		kept = append(kept, c)
	}
	if !changed {
		return settings
	}
	parsed["clients"] = kept
	out, err := json.Marshal(parsed)
	if err != nil {
		return settings
	}
	return string(out)
}

// hotInbound is one entry of a rendered config.json's inbounds
// array, with the raw sections kept for normalized comparison.
type hotInbound struct {
	Listen         json.RawMessage `json:"listen"`
	Port           int             `json:"port"`
	Protocol       string          `json:"protocol"`
	Settings       json.RawMessage `json:"settings"`
	StreamSettings json.RawMessage `json:"streamSettings"`
	Tag            string          `json:"tag"`
	Sniffing       json.RawMessage `json:"sniffing"`
}

// parseRenderedInbounds indexes a rendered config's inbounds by tag.
// ok is false when the config is unparsable or a tag is empty or
// duplicated — such a config cannot be hot-diffed.
func parseRenderedInbounds(data []byte) (map[string]hotInbound, bool) {
	var cfg struct {
		Inbounds []hotInbound `json:"inbounds"`
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(&cfg); err != nil {
		return nil, false
	}
	out := make(map[string]hotInbound, len(cfg.Inbounds))
	for _, ib := range cfg.Inbounds {
		if ib.Tag == "" {
			return nil, false
		}
		if _, dup := out[ib.Tag]; dup {
			return nil, false
		}
		out[ib.Tag] = ib
	}
	return out, true
}

// canonicalJSON renders a JSON value in canonical form (sorted object
// keys, exact number digits). Empty input and JSON null both yield
// nil, so an absent section compares equal to an explicit null.
func canonicalJSON(raw json.RawMessage) ([]byte, bool) {
	if len(raw) == 0 {
		return nil, true
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var value any
	if err := dec.Decode(&value); err != nil {
		return nil, false
	}
	if value == nil {
		return nil, true
	}
	out, err := json.Marshal(value)
	if err != nil {
		return nil, false
	}
	return out, true
}

func rawEqual(a, b json.RawMessage) bool {
	if bytes.Equal(a, b) {
		return true
	}
	na, ok := canonicalJSON(a)
	if !ok {
		return false
	}
	nb, ok := canonicalJSON(b)
	if !ok {
		return false
	}
	return bytes.Equal(na, nb)
}

// clientEntry is one settings client plus its canonical form, for
// change detection.
type clientEntry struct {
	user map[string]any
	norm []byte
}

// splitClients indexes settings.clients by email and returns the rest
// of the settings in canonical form. ok is false when there is no
// clients array, a client has no email, or an email is duplicated.
func splitClients(raw json.RawMessage) (map[string]clientEntry, []byte, bool) {
	if len(raw) == 0 {
		return nil, nil, false
	}
	settings := map[string]any{}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&settings); err != nil {
		return nil, nil, false
	}
	clientsRaw, ok := settings["clients"].([]any)
	if !ok {
		return nil, nil, false
	}
	clients := make(map[string]clientEntry, len(clientsRaw))
	for _, c := range clientsRaw {
		obj, ok := c.(map[string]any)
		if !ok {
			return nil, nil, false
		}
		email, _ := obj["email"].(string)
		if email == "" {
			return nil, nil, false
		}
		if _, dup := clients[email]; dup {
			return nil, nil, false
		}
		norm, err := json.Marshal(obj)
		if err != nil {
			return nil, nil, false
		}
		clients[email] = clientEntry{user: obj, norm: norm}
	}
	delete(settings, "clients")
	rest, err := json.Marshal(settings)
	if err != nil {
		return nil, nil, false
	}
	return clients, rest, true
}

func hasReverseClient(clients map[string]clientEntry) bool {
	for _, c := range clients {
		if v, ok := c.user["reverse"]; ok && v != nil {
			return true
		}
	}
	return false
}

// userOp is one runtime user change on one inbound tag. User is nil
// for removals; for additions it is the client's settings object.
type userOp struct {
	Tag      string
	Protocol string
	Email    string
	Remove   bool
	User     map[string]any
	// inbound carries the NEW rendered inbound (for adu payloads).
	inbound hotInbound
}

// computeUserOps diffs two rendered configs. It returns hot=false
// when anything other than client lists changed, in which case the
// caller must take the restart path. A hot diff with zero ops means
// the configs are equivalent: nothing to apply.
func computeUserOps(oldData, newData []byte) (ops []userOp, hot bool) {
	oldByTag, ok := parseRenderedInbounds(oldData)
	if !ok {
		return nil, false
	}
	newByTag, ok := parseRenderedInbounds(newData)
	if !ok {
		return nil, false
	}
	if len(oldByTag) != len(newByTag) {
		return nil, false
	}
	for tag, oldIb := range oldByTag {
		newIb, exists := newByTag[tag]
		if !exists {
			return nil, false
		}
		if oldIb.Port == newIb.Port &&
			oldIb.Protocol == newIb.Protocol &&
			rawEqual(oldIb.Listen, newIb.Listen) &&
			rawEqual(oldIb.Settings, newIb.Settings) &&
			rawEqual(oldIb.StreamSettings, newIb.StreamSettings) &&
			rawEqual(oldIb.Sniffing, newIb.Sniffing) {
			continue
		}
		// Something changed: only a client-list-only change on a
		// user-diffable protocol can go hot.
		if oldIb.Port != newIb.Port || oldIb.Protocol != newIb.Protocol {
			return nil, false
		}
		if !userDiffableProtocols[strings.ToLower(oldIb.Protocol)] {
			return nil, false
		}
		if !rawEqual(oldIb.Listen, newIb.Listen) ||
			!rawEqual(oldIb.StreamSettings, newIb.StreamSettings) ||
			!rawEqual(oldIb.Sniffing, newIb.Sniffing) {
			return nil, false
		}
		oldClients, oldRest, ok := splitClients(oldIb.Settings)
		if !ok {
			return nil, false
		}
		newClients, newRest, ok := splitClients(newIb.Settings)
		if !ok {
			return nil, false
		}
		if !bytes.Equal(oldRest, newRest) {
			return nil, false
		}
		if hasReverseClient(oldClients) || hasReverseClient(newClients) {
			return nil, false
		}
		for email, oldC := range oldClients {
			newC, exists := newClients[email]
			if exists && bytes.Equal(oldC.norm, newC.norm) {
				continue
			}
			ops = append(ops, userOp{Tag: tag, Protocol: oldIb.Protocol, Email: email, Remove: true})
			if exists {
				ops = append(ops, userOp{Tag: tag, Protocol: oldIb.Protocol, Email: email, User: newC.user, inbound: newIb})
			}
		}
		for email, newC := range newClients {
			if _, exists := oldClients[email]; !exists {
				ops = append(ops, userOp{Tag: tag, Protocol: oldIb.Protocol, Email: email, User: newC.user, inbound: newIb})
			}
		}
	}
	return ops, true
}

// parseAPICount extracts the N from "Added N user(s) in total." /
// "Removed N user(s) in total." output. ok is false when the line is
// absent — adu/rmu exit 0 even on total failure, so the count line
// is the only success signal.
func parseAPICount(out, verb string) (int, bool) {
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		var n int
		var tail string
		if _, err := fmt.Sscanf(line, verb+" %d user(s) in total.%s", &n, &tail); err == nil {
			return n, true
		}
		// Sscanf with %s fails when there is no trailing text;
		// retry with the exact prefix form.
		prefix := verb + " "
		suffix := " user(s) in total."
		if strings.HasPrefix(line, prefix) && strings.HasSuffix(line, suffix) {
			var n2 int
			if _, err := fmt.Sscanf(strings.TrimSuffix(strings.TrimPrefix(line, prefix), suffix), "%d", &n2); err == nil {
				return n2, true
			}
		}
	}
	return 0, false
}

// runXrayAPI runs `xray api <args...>` with a timeout and returns
// combined stdout+stderr.
func (a *Agent) runXrayAPI(args ...string) (string, error) {
	if a.xrayBin == "" {
		return "", fmt.Errorf("no xray binary configured")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, a.xrayBin, args...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// applyUserOps executes removals first (batched per tag), then
// additions (one adu call per tag). Any mismatch falls back to a
// restart by the caller.
func (a *Agent) applyUserOps(ops []userOp) error {
	// Removals, batched per tag.
	removals := map[string][]string{}
	var adds []userOp
	for _, op := range ops {
		if op.Remove {
			removals[op.Tag] = append(removals[op.Tag], op.Email)
		} else {
			adds = append(adds, op)
		}
	}
	for tag, emails := range removals {
		args := []string{"api", "rmu", "--server=" + xrayAPIAddr, "-t", "10", "-tag=" + tag}
		args = append(args, emails...)
		out, err := a.runXrayAPI(args...)
		if err != nil {
			return fmt.Errorf("rmu %s: %w: %s", tag, err, strings.TrimSpace(out))
		}
		n, ok := parseAPICount(out, "Removed")
		if !ok || n != len(emails) {
			return fmt.Errorf("rmu %s: removed %d/%d: %s", tag, n, len(emails), strings.TrimSpace(out))
		}
	}
	// Additions, grouped per tag: one adu call per tag with a
	// full-config payload carrying only the added clients.
	byTag := map[string][]userOp{}
	for _, op := range adds {
		byTag[op.Tag] = append(byTag[op.Tag], op)
	}
	for tag, tagOps := range byTag {
		if err := a.aduTag(tag, tagOps); err != nil {
			return err
		}
	}
	return nil
}

// aduTag adds the given users to one inbound tag via `xray api adu`.
// The payload is a full config document whose single inbound is the
// new rendered inbound with ONLY the added clients: adu decodes
// full configs and adds every client it finds.
func (a *Agent) aduTag(tag string, ops []userOp) error {
	ib := ops[0].inbound
	clients := make([]any, 0, len(ops))
	for _, op := range ops {
		clients = append(clients, op.User)
	}
	// Rebuild settings: the inbound-level keys (e.g. decryption)
	// plus only the added clients.
	var settings map[string]any
	dec := json.NewDecoder(bytes.NewReader(ib.Settings))
	dec.UseNumber()
	if err := dec.Decode(&settings); err != nil {
		return fmt.Errorf("adu %s: decode settings: %w", tag, err)
	}
	settings["clients"] = clients
	settingsRaw, err := json.Marshal(settings)
	if err != nil {
		return fmt.Errorf("adu %s: encode settings: %w", tag, err)
	}
	payload := map[string]any{
		"inbounds": []any{
			map[string]any{
				"listen":         json.RawMessage(ib.Listen),
				"port":           ib.Port,
				"protocol":       ib.Protocol,
				"settings":       json.RawMessage(settingsRaw),
				"streamSettings": json.RawMessage(nullIfEmpty(ib.StreamSettings)),
				"tag":            ib.Tag,
				"sniffing":       json.RawMessage(nullIfEmpty(ib.Sniffing)),
			},
		},
	}
	// Omit empty optional sections rather than sending nulls.
	inb := payload["inbounds"].([]any)[0].(map[string]any)
	if len(ib.StreamSettings) == 0 {
		delete(inb, "streamSettings")
	}
	if len(ib.Sniffing) == 0 {
		delete(inb, "sniffing")
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("adu %s: encode payload: %w", tag, err)
	}
	// Payload carries client UUIDs: 0600 temp file, removed at once.
	f, err := os.CreateTemp("", "x-ui-agent-adu-*.json")
	if err != nil {
		return fmt.Errorf("adu %s: temp file: %w", tag, err)
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return fmt.Errorf("adu %s: chmod temp file: %w", tag, err)
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return fmt.Errorf("adu %s: write temp file: %w", tag, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("adu %s: close temp file: %w", tag, err)
	}
	out, err := a.runXrayAPI("api", "adu", "--server="+xrayAPIAddr, "-t", "10", tmp)
	if err != nil {
		return fmt.Errorf("adu %s: %w: %s", tag, err, strings.TrimSpace(out))
	}
	n, ok := parseAPICount(out, "Added")
	if !ok || n != len(ops) {
		return fmt.Errorf("adu %s: added %d/%d: %s", tag, n, len(ops), strings.TrimSpace(out))
	}
	return nil
}

func nullIfEmpty(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 {
		return json.RawMessage("null")
	}
	return raw
}

// tryHotApply attempts a restart-free apply. It returns applied=true
// when the running Xray now serves the new config (or nothing
// changed). applied=false with err=nil means "not hot-applicable:
// take the restart path". A non-nil err is fatal: the new config
// failed validation and the old process keeps running.
func (a *Agent) tryHotApply() (applied bool, err error) {
	newData, err := a.renderConfig()
	if err != nil {
		return false, nil
	}
	oldData, err := os.ReadFile(a.configPath)
	if err != nil {
		return false, nil // no running config on disk: first start
	}
	ops, hot := computeUserOps(oldData, newData)
	if !hot {
		return false, nil
	}
	state, _, _ := a.XrayState()
	if state != "running" {
		return false, nil
	}
	// Capture counters before any removal can reset them, then
	// install the new config on disk (tested) so a later restart
	// loads exactly this user set.
	a.refreshStatsForce()
	if err := a.writeConfig(); err != nil {
		return false, err
	}
	if len(ops) == 0 {
		return true, nil
	}
	if err := a.applyUserOps(ops); err != nil {
		// Partial application is safe: the restart path rebuilds
		// the whole handler set from the new config on disk.
		return false, nil
	}
	return true, nil
}
