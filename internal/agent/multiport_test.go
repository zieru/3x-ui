package agent

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestParseExtraPorts(t *testing.T) {
	got := parseExtraPorts([]byte(`{"in-7102-tcp": [5010, 443], "v2 sg": [8080]}`))
	if len(got) != 2 || len(got["in-7102-tcp"]) != 2 || got["in-7102-tcp"][0] != 5010 {
		t.Fatalf("got %+v", got)
	}
	if parseExtraPorts([]byte(`{}`)) != nil {
		t.Fatalf("empty object should parse to nil")
	}
	if parseExtraPorts([]byte(`not json`)) != nil {
		t.Fatalf("malformed JSON should parse to nil")
	}
	if parseExtraPorts([]byte(`[]`)) != nil {
		t.Fatalf("non-object JSON should parse to nil")
	}
	// Non-integer values are skipped, not fatal.
	got = parseExtraPorts([]byte(`{"in-7102-tcp": [5010, "abc", 1.5]}`))
	if len(got["in-7102-tcp"]) != 1 || got["in-7102-tcp"][0] != 5010 {
		t.Fatalf("got %+v, want only [5010]", got["in-7102-tcp"])
	}
}

func TestExtraPortsFor(t *testing.T) {
	ib := Inbound{Tag: "in-7102-tcp", Remark: "v2 sg (clone)", Port: 7102}
	cfg := map[string][]int{
		"in-7102-tcp":    {5010, 5010, 7102, 10085, 0, -1, 70000, 8080},
		"v2 sg (clone)":  {9090},
		"other":          {7070},
	}
	used := map[int]bool{apiInboundPort: true, 7102: true}
	got := extraPortsFor(ib, cfg, used)
	if len(got) != 2 || got[0] != 5010 || got[1] != 8080 {
		t.Fatalf("got %v, want [5010 8080]", got)
	}
	if !used[5010] || !used[8080] {
		t.Fatalf("used map not updated: %v", used)
	}

	// Remark fallback when no tag key exists.
	ib2 := Inbound{Tag: "in-9999-tcp", Remark: "v2 sg (clone)", Port: 9999}
	got = extraPortsFor(ib2, cfg, map[int]bool{apiInboundPort: true, 9999: true})
	if len(got) != 1 || got[0] != 9090 {
		t.Fatalf("remark fallback got %v, want [9090]", got)
	}

	// No matching key, empty config, nil config: no duplicates.
	if extraPortsFor(Inbound{Tag: "nope"}, cfg, map[int]bool{}) != nil {
		t.Fatalf("unknown tag should yield no ports")
	}
	if extraPortsFor(ib, nil, map[int]bool{}) != nil {
		t.Fatalf("nil config should yield no ports")
	}
}

func TestDuplicateTagRoundTrip(t *testing.T) {
	tag := duplicateTag("in-7102-tcp", 5010)
	if tag != "in-7102-tcp-nat5010" {
		t.Fatalf("tag = %q", tag)
	}
	base, port, ok := duplicateTagPort(tag)
	if !ok || base != "in-7102-tcp" || port != 5010 {
		t.Fatalf("round trip = %q %d %v", base, port, ok)
	}
	if _, _, ok := duplicateTagPort("in-7102-tcp"); ok {
		t.Fatalf("plain tag must not parse as duplicate")
	}
	if _, _, ok := duplicateTagPort("in-nat-tcp"); ok {
		t.Fatalf("tag with nat in the middle must not parse as duplicate")
	}
}

type renderedInbound struct {
	Port           int             `json:"port"`
	Tag            string          `json:"tag"`
	Protocol       string          `json:"protocol"`
	Settings       json.RawMessage `json:"settings"`
	StreamSettings json.RawMessage `json:"streamSettings"`
	Sniffing       json.RawMessage `json:"sniffing"`
}

func renderTestConfig(t *testing.T, a *Agent) []renderedInbound {
	t.Helper()
	data, err := a.renderConfig()
	if err != nil {
		t.Fatalf("renderConfig: %v", err)
	}
	var cfg struct {
		Inbounds []renderedInbound `json:"inbounds"`
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("rendered config is not valid JSON: %v", err)
	}
	return cfg.Inbounds
}

func writeExtraPorts(t *testing.T, dir, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, extraPortsFileName), []byte(content), 0o600); err != nil {
		t.Fatalf("write extra-ports.json: %v", err)
	}
}

func TestRenderConfigMultiPort(t *testing.T) {
	dir := t.TempDir()
	writeExtraPorts(t, dir, `{"in-7102-tcp": [5010]}`)
	a := newTestAgent()
	a.stateDir = dir
	a.state.Inbounds = []Inbound{{
		ID:             10,
		Tag:            "in-7102-tcp",
		Remark:         "v2 sg (clone)",
		Enable:         true,
		Port:           7102,
		Protocol:       "vless",
		Settings:       `{"clients":[{"email":"a@x.id","id":"u1"}],"decryption":"x","encryption":"seed"}`,
		StreamSettings: `{"network":"tcp","security":"reality"}`,
		Sniffing:       `{"enabled":true}`,
	}}
	inbounds := renderTestConfig(t, a)
	// Primary + 1 duplicate + api inbound.
	if len(inbounds) != 3 {
		t.Fatalf("got %d inbounds, want 3", len(inbounds))
	}
	primary, dup, api := inbounds[0], inbounds[1], inbounds[2]
	if primary.Port != 7102 || primary.Tag != "in-7102-tcp" {
		t.Fatalf("primary = %+v", primary)
	}
	if dup.Port != 5010 || dup.Tag != "in-7102-tcp-nat5010" {
		t.Fatalf("duplicate = %+v, want port 5010 tag in-7102-tcp-nat5010", dup)
	}
	if dup.Protocol != primary.Protocol {
		t.Fatalf("duplicate protocol = %q, want %q", dup.Protocol, primary.Protocol)
	}
	// Settings must be identical after the same VLESS stripping.
	if string(dup.Settings) != string(primary.Settings) {
		t.Fatalf("duplicate settings differ:\n%s\nvs\n%s", dup.Settings, primary.Settings)
	}
	if string(dup.StreamSettings) != string(primary.StreamSettings) {
		t.Fatalf("duplicate streamSettings differ")
	}
	if string(dup.Sniffing) != string(primary.Sniffing) {
		t.Fatalf("duplicate sniffing differs")
	}
	if api.Tag != "api" || api.Port != 10085 {
		t.Fatalf("api inbound = %+v", api)
	}
}

func TestRenderConfigExtraPortCollisions(t *testing.T) {
	dir := t.TempDir()
	writeExtraPorts(t, dir, `{
		"in-7102-tcp": [5010, 7102, 10085, 39571],
		"in-39571-tcp": [5010]
	}`)
	a := newTestAgent()
	a.stateDir = dir
	a.state.Inbounds = []Inbound{
		{ID: 10, Tag: "in-7102-tcp", Enable: true, Port: 7102, Protocol: "vless", Settings: `{"clients":[]}`},
		{ID: 11, Tag: "in-39571-tcp", Enable: true, Port: 39571, Protocol: "vless", Settings: `{"clients":[]}`},
		{ID: 12, Tag: "in-9999-tcp", Enable: false, Port: 9999, Protocol: "vless", Settings: `{"clients":[]}`},
	}
	inbounds := renderTestConfig(t, a)
	// Primary 7102 + duplicate 5010, primary 39571 (its 5010 is taken
	// by the first inbound's duplicate), api. Disabled 9999 absent.
	if len(inbounds) != 4 {
		t.Fatalf("got %d inbounds, want 4: %+v", len(inbounds), inbounds)
	}
	ports := map[int]string{}
	for _, ib := range inbounds {
		if _, dup := ports[ib.Port]; dup {
			t.Fatalf("duplicate port %d in rendered config", ib.Port)
		}
		ports[ib.Port] = ib.Tag
	}
	if ports[5010] != "in-7102-tcp-nat5010" {
		t.Fatalf("port 5010 tag = %q", ports[5010])
	}
}

func TestRenderConfigNoExtraPortsFile(t *testing.T) {
	// No stateDir at all (unit-test agent): v3 behaviour, primary + api.
	a := newTestAgent()
	a.state.Inbounds = []Inbound{
		{ID: 10, Tag: "in-7102-tcp", Enable: true, Port: 7102, Protocol: "vless", Settings: `{"clients":[]}`},
	}
	inbounds := renderTestConfig(t, a)
	if len(inbounds) != 2 || inbounds[0].Port != 7102 || inbounds[1].Tag != "api" {
		t.Fatalf("got %+v, want primary + api only", inbounds)
	}

	// State dir exists but no extra-ports.json: same.
	a.stateDir = t.TempDir()
	inbounds = renderTestConfig(t, a)
	if len(inbounds) != 2 {
		t.Fatalf("missing extra-ports.json: got %d inbounds, want 2", len(inbounds))
	}

	// Malformed extra-ports.json: ignored, never fatal.
	writeExtraPorts(t, a.stateDir, `{broken`)
	inbounds = renderTestConfig(t, a)
	if len(inbounds) != 2 {
		t.Fatalf("malformed extra-ports.json: got %d inbounds, want 2", len(inbounds))
	}
}

// TestListInboundsIgnoresDuplicates proves the duplicate inbounds are
// internal to the rendered Xray config: the panel-facing
// /inbounds/list view still contains exactly the stored inbounds, so
// traffic and online stats (per email) are never double-counted by
// the master summing two rows for one client.
func TestListInboundsIgnoresDuplicates(t *testing.T) {
	dir := t.TempDir()
	writeExtraPorts(t, dir, `{"in-7102-tcp": [5010, 5011]}`)
	a := newTestAgent()
	a.stateDir = dir
	a.state.Inbounds = []Inbound{{
		ID: 10, Tag: "in-7102-tcp", Enable: true, Port: 7102, Protocol: "vless",
		Settings: `{"clients":[{"email":"a@x.id","id":"u1","enable":true}]}`,
	}}
	listed := a.listInbounds()
	if len(listed) != 1 || listed[0].Port != 7102 {
		t.Fatalf("listInbounds = %+v, want exactly the stored inbound", listed)
	}
}
