package agent

import (
	"testing"
	"time"
)

func TestParseOnlineIPs(t *testing.T) {
	// protojson camelCase shape.
	data := []byte(`{"users": [
		{"email": "a@x.id", "ips": [{"ip": "1.2.3.4", "lastSeen": 1700000000}]},
		{"email": "b@x.id", "ips": [{"ip": "5.6.7.8", "last_seen": 1700000001}, {"ip": "9.9.9.9", "lastSeen": 1700000002, "last_seen": 1700000003}]}
	]}`)
	got := parseOnlineIPs(data)
	if len(got) != 2 {
		t.Fatalf("got %d users, want 2", len(got))
	}
	if got["a@x.id"][0] != (onlineIP{IP: "1.2.3.4", LastSeen: 1700000000}) {
		t.Fatalf("a@x.id = %+v", got["a@x.id"])
	}
	// snake_case accepted; when both are present the larger wins.
	if got["b@x.id"][0].LastSeen != 1700000001 || got["b@x.id"][1].LastSeen != 1700000003 {
		t.Fatalf("b@x.id = %+v", got["b@x.id"])
	}
	if parseOnlineIPs([]byte(`{}`)) != nil {
		t.Fatalf("empty object should return nil")
	}
	if parseOnlineIPs([]byte(`not json`)) != nil {
		t.Fatalf("bad JSON should return nil")
	}
	if parseOnlineIPs([]byte(`{"users": [{"email": "", "ips": [{"ip": "1.1.1.1", "lastSeen": 1}]}]}`)) != nil {
		t.Fatalf("user without email should be dropped")
	}
}

func TestMergeMovedDetection(t *testing.T) {
	a := newTestAgent()
	// First sighting with traffic already on the counter counts as
	// moved (the client demonstrably has traffic).
	_, _, moved := a.merge(t, map[string]statPair{"a@x.id": {Up: 100, Down: 200}})
	if len(moved) != 1 || moved[0] != "a@x.id" {
		t.Fatalf("first sighting with traffic moved = %v, want [a@x.id]", moved)
	}
	// No change: not moved.
	_, _, moved = a.merge(t, map[string]statPair{"a@x.id": {Up: 100, Down: 200}})
	if len(moved) != 0 {
		t.Fatalf("unchanged moved = %v, want none", moved)
	}
	// Uplink grows: moved.
	_, _, moved = a.merge(t, map[string]statPair{"a@x.id": {Up: 150, Down: 200}})
	if len(moved) != 1 || moved[0] != "a@x.id" {
		t.Fatalf("moved = %v, want [a@x.id]", moved)
	}
	// Restart fold (counter reset): not moved, but base changed.
// A fold that already carries new post-restart traffic (val > 0)
// DOES count as moved.
	_, baseChanged, moved := a.merge(t, map[string]statPair{"a@x.id": {Up: 10, Down: 20}})
	if len(moved) != 1 || moved[0] != "a@x.id" {
		t.Fatalf("restart fold with new traffic moved = %v, want [a@x.id]", moved)
	}
	if !baseChanged {
		t.Fatalf("restart fold should report baseChanged")
	}
	// Restart fold with a zero new value: no new traffic, not moved.
	_, _, moved = a.merge(t, map[string]statPair{"a@x.id": {Up: 0, Down: 0}})
	if len(moved) != 0 {
		t.Fatalf("zero restart fold moved = %v, want none", moved)
	}
}

func TestOnlineSnapshotGrace(t *testing.T) {
	a := newTestAgent()
	now := time.Unix(1700000000, 0)
	a.mu.Lock()
	a.recordActivityLocked([]string{"a@x.id"}, nil, now)
	a.mu.Unlock()

	emails, lastOnline, tags, _ := a.onlineSnapshot(now.Add(10 * time.Second))
	if len(emails) != 1 || emails[0] != "a@x.id" {
		t.Fatalf("within grace emails = %v, want [a@x.id]", emails)
	}
	if lastOnline["a@x.id"] != 1700000000 {
		t.Fatalf("lastOnline = %d, want 1700000000", lastOnline["a@x.id"])
	}
	if len(tags) != 1 || tags[0] != "in-443-tcp" {
		t.Fatalf("active tags = %v, want [in-443-tcp]", tags)
	}

	// Past the 20 s grace: offline, but lastOnline is retained.
	emails, lastOnline, tags, _ = a.onlineSnapshot(now.Add(25 * time.Second))
	if len(emails) != 0 {
		t.Fatalf("past grace emails = %v, want []", emails)
	}
	if lastOnline["a@x.id"] != 1700000000 {
		t.Fatalf("lastOnline past grace = %d, want retained 1700000000", lastOnline["a@x.id"])
	}
	if len(tags) != 0 {
		t.Fatalf("past grace tags = %v, want []", tags)
	}
}

func TestOnlineSnapshotLiveIPUnion(t *testing.T) {
	a := newTestAgent()
	now := time.Unix(1700000000, 0)
	// No traffic at all, but the core reports a live IP: the client
	// is online (idle-but-connected) and its IP is reported.
	ips := map[string][]onlineIP{"a@x.id": {{IP: "1.2.3.4", LastSeen: 1700000000}}}
	a.mu.Lock()
	a.recordActivityLocked(nil, ips, now)
	a.mu.Unlock()

	emails, _, _, _ := a.onlineSnapshot(now.Add(5 * time.Second))
	if len(emails) != 1 || emails[0] != "a@x.id" {
		t.Fatalf("live-IP union emails = %v, want [a@x.id]", emails)
	}
}

func TestSaveStateThrottled(t *testing.T) {
	a := newTestAgent()
	a.statePath = t.TempDir() + "/state.json"
	a.lastStateSave = time.Now()
	// StatLast-only change right after a save: must NOT save yet.
	a.saveStateThrottledLocked(true, false)
	if !a.stateDirty {
		t.Fatalf("StatLast-only change should mark state dirty")
	}
	// A base change (restart fold) saves immediately.
	a.saveStateThrottledLocked(true, true)
	if a.stateDirty {
		t.Fatalf("base change should flush and clear dirty")
	}
	// Dirty + interval elapsed: saves on the next call.
	a.stateDirty = true
	a.lastStateSave = time.Now().Add(-2 * time.Minute)
	a.saveStateThrottledLocked(false, false)
	if a.stateDirty {
		t.Fatalf("dirty state past the interval should flush")
	}
	// Nothing changed, nothing dirty: no-op.
	a.saveStateThrottledLocked(false, false)
}

func TestOnlinePrunesRemovedClients(t *testing.T) {
	a := newTestAgent()
	a.merge(t, map[string]statPair{"a@x.id": {Up: 100, Down: 200}})
	a.mu.Lock()
	a.recordActivityLocked([]string{"a@x.id"}, nil, time.Unix(1700000000, 0))
	a.mu.Unlock()
	// Client removed from the inbound: lastOnline must be pruned.
	a.state.Inbounds[0].Settings = `{"clients":[]}`
	a.merge(t, map[string]statPair{"a@x.id": {Up: 200, Down: 200}})
	_, lastOnline, _, _ := a.onlineSnapshot(time.Unix(1700000001, 0))
	if _, ok := lastOnline["a@x.id"]; ok {
		t.Fatalf("lastOnline for removed client was not pruned")
	}
}
