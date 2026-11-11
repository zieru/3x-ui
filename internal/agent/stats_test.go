package agent

import "testing"

func TestParseStatsQuery(t *testing.T) {
	data := []byte(`{"stat": [
		{"name": "user>>>a@x.id>>>traffic>>>uplink", "value": 100},
		{"name": "user>>>a@x.id>>>traffic>>>downlink", "value": 200},
		{"name": "user>>>b@x.id>>>traffic>>>uplink", "value": 5},
		{"name": "inbound>>>in-443-tcp>>>traffic>>>uplink", "value": 999},
		{"name": "garbage", "value": 1}
	]}`)
	got := parseStatsQuery(data)
	if got["a@x.id"] != (statPair{Up: 100, Down: 200}) {
		t.Fatalf("a@x.id = %+v, want {100 200}", got["a@x.id"])
	}
	if got["b@x.id"] != (statPair{Up: 5, Down: 0}) {
		t.Fatalf("b@x.id = %+v, want {5 0}", got["b@x.id"])
	}
	if len(got) != 2 {
		t.Fatalf("got %d users, want 2", len(got))
	}
	if parseStatsQuery([]byte(`not json`)) != nil {
		t.Fatalf("bad JSON should return nil")
	}
}

func newTestAgent() *Agent {
	return &Agent{state: State{
		PanelGuid: "test",
		NextID:    1,
		Inbounds: []Inbound{{
			ID:       1,
			Tag:      "in-443-tcp",
			Settings: `{"clients":[{"email":"a@x.id","id":"u1","enable":true}]}`,
		}},
	}}
}

// merge is a test helper that runs mergeRawLocked under the lock.
func (a *Agent) merge(t *testing.T, raw map[string]statPair) {
	t.Helper()
	a.mu.Lock()
	defer a.mu.Unlock()
	a.mergeRawLocked(raw)
}

func TestMergeRawFirstSighting(t *testing.T) {
	a := newTestAgent()
	a.merge(t, map[string]statPair{"a@x.id": {Up: 100, Down: 200}})
	if got := a.state.StatLast["a@x.id|uplink"]; got != 100 {
		t.Fatalf("last uplink = %d, want 100", got)
	}
	up, down := a.reportedTraffic("a@x.id")
	// reportedTraffic reads the stats snapshot, which is empty in a
	// unit test; base is 0, so emulate the snapshot path instead:
	_ = up
	_ = down
	// Direct check: base must still be 0 after first sighting.
	if got := a.state.StatBase["a@x.id|uplink"]; got != 0 {
		t.Fatalf("base uplink = %d, want 0", got)
	}
}

func TestMergeRawXrayRestart(t *testing.T) {
	a := newTestAgent()
	a.merge(t, map[string]statPair{"a@x.id": {Up: 1000, Down: 2000}})
	a.merge(t, map[string]statPair{"a@x.id": {Up: 1500, Down: 2500}})
	// Xray restarts: raw counters reset to 0, then grow to 50/80.
	a.merge(t, map[string]statPair{"a@x.id": {Up: 50, Down: 80}})
	if got := a.state.StatBase["a@x.id|uplink"]; got != 1500 {
		t.Fatalf("base uplink after restart = %d, want 1500", got)
	}
	if got := a.state.StatBase["a@x.id|downlink"]; got != 2500 {
		t.Fatalf("base downlink after restart = %d, want 2500", got)
	}
	// Reported = base + raw = 1550 / 2580.
	a.statsRaw = map[string]statPair{"a@x.id": {Up: 50, Down: 80}}
	up, down := a.reportedTraffic("a@x.id")
	if up != 1550 || down != 2580 {
		t.Fatalf("reported = %d/%d, want 1550/2580", up, down)
	}
}

// TestRestartCapture mirrors what StartXray does: force a refresh
// immediately before the restart, so StatLast holds the freshest
// pre-restart raw value and the first post-restart refresh folds it
// into the base instead of losing it.
func TestRestartCapture(t *testing.T) {
	a := newTestAgent()
	a.merge(t, map[string]statPair{"a@x.id": {Up: 1000, Down: 2000}})
	// Capture just before restart (refreshStatsForce equivalent):
	// last is now the fresh pre-restart total.
	a.merge(t, map[string]statPair{"a@x.id": {Up: 1500, Down: 2500}})
	// Restart: raw resets, then grows a little before the next refresh.
	a.merge(t, map[string]statPair{"a@x.id": {Up: 50, Down: 80}})
	if got := a.state.StatBase["a@x.id|uplink"]; got != 1500 {
		t.Fatalf("base uplink after restart = %d, want 1500 (captured value)", got)
	}
	a.statsRaw = map[string]statPair{"a@x.id": {Up: 50, Down: 80}}
	up, down := a.reportedTraffic("a@x.id")
	if up != 1550 || down != 2580 {
		t.Fatalf("reported = %d/%d, want 1550/2580", up, down)
	}
}

func TestMergeRawPrunesRemovedClients(t *testing.T) {
	a := newTestAgent()
	a.merge(t, map[string]statPair{"a@x.id": {Up: 10, Down: 10}})
	// Client removed from the inbound: its offsets must be pruned.
	a.state.Inbounds[0].Settings = `{"clients":[]}`
	a.merge(t, map[string]statPair{"a@x.id": {Up: 20, Down: 20}})
	if _, ok := a.state.StatBase["a@x.id|uplink"]; ok {
		t.Fatalf("offset for removed client was not pruned")
	}
}

func TestZeroTraffic(t *testing.T) {
	a := newTestAgent()
	a.merge(t, map[string]statPair{"a@x.id": {Up: 1000, Down: 2000}})
	a.statsRaw = map[string]statPair{"a@x.id": {Up: 1000, Down: 2000}}
	a.mu.Lock()
	a.zeroTrafficLocked([]string{"a@x.id"})
	a.mu.Unlock()
	up, down := a.reportedTraffic("a@x.id")
	if up != 0 || down != 0 {
		t.Fatalf("after reset reported = %d/%d, want 0/0", up, down)
	}
	// Traffic keeps flowing after the reset.
	a.statsRaw = map[string]statPair{"a@x.id": {Up: 1100, Down: 2100}}
	a.mu.Lock()
	a.mergeRawLocked(map[string]statPair{"a@x.id": {Up: 1100, Down: 2100}})
	a.mu.Unlock()
	up, down = a.reportedTraffic("a@x.id")
	if up != 100 || down != 100 {
		t.Fatalf("after reset + 100B reported = %d/%d, want 100/100", up, down)
	}
}
