package agent

import (
	"encoding/json"
	"strings"
	"testing"
)

// hotTestConfig builds a minimal rendered config document from
// inbound objects, for hot-diff tests.
func hotTestConfig(t *testing.T, inbounds ...map[string]any) []byte {
	t.Helper()
	data, err := json.Marshal(map[string]any{"inbounds": inbounds})
	if err != nil {
		t.Fatalf("marshal test config: %v", err)
	}
	return data
}

func testInbound(tag string, port int, protocol string, clients ...map[string]any) map[string]any {
	arr := make([]any, 0, len(clients))
	for _, c := range clients {
		arr = append(arr, c)
	}
	return map[string]any{
		"listen":   "0.0.0.0",
		"port":     port,
		"protocol": protocol,
		"settings": map[string]any{"clients": arr, "decryption": "none"},
		"tag":      tag,
	}
}

func testClient(email, id string) map[string]any {
	return map[string]any{"email": email, "id": id, "enable": true}
}

func TestFilterDisabledClients(t *testing.T) {
	in := `{"clients":[{"email":"a@x.id","id":"u1","enable":true},{"email":"b@x.id","id":"u2","enable":false},{"email":"c@x.id","id":"u3"}],"decryption":"none"}`
	out := filterDisabledClients(in)
	if strings.Contains(out, "b@x.id") {
		t.Fatalf("disabled client survived filter: %s", out)
	}
	if !strings.Contains(out, "a@x.id") || !strings.Contains(out, "c@x.id") {
		t.Fatalf("enabled clients lost: %s", out)
	}
	if !strings.Contains(out, "decryption") {
		t.Fatalf("inbound-level keys lost: %s", out)
	}
	// No clients array: unchanged.
	if got := filterDisabledClients(`{"address":"127.0.0.1"}`); got != `{"address":"127.0.0.1"}` {
		t.Fatalf("clientless settings changed: %s", got)
	}
	// Invalid JSON: unchanged.
	if got := filterDisabledClients(`{bad`); got != `{bad` {
		t.Fatalf("invalid JSON changed: %s", got)
	}
}

func TestComputeUserOpsIdentical(t *testing.T) {
	cfg := hotTestConfig(t, testInbound("in-1", 443, "vless", testClient("a@x.id", "u1")))
	ops, hot := computeUserOps(cfg, cfg)
	if !hot {
		t.Fatalf("identical configs must be hot")
	}
	if len(ops) != 0 {
		t.Fatalf("identical configs must yield no ops, got %+v", ops)
	}
}

func TestComputeUserOpsAddRemove(t *testing.T) {
	oldCfg := hotTestConfig(t, testInbound("in-1", 443, "vless", testClient("a@x.id", "u1"), testClient("b@x.id", "u2")))
	newCfg := hotTestConfig(t, testInbound("in-1", 443, "vless", testClient("a@x.id", "u1"), testClient("c@x.id", "u3")))
	ops, hot := computeUserOps(oldCfg, newCfg)
	if !hot {
		t.Fatalf("client-only change must be hot")
	}
	var removed, added []string
	for _, op := range ops {
		if op.Remove {
			removed = append(removed, op.Email)
		} else {
			added = append(added, op.Email)
		}
		if op.Tag != "in-1" {
			t.Fatalf("op tag = %q, want in-1", op.Tag)
		}
	}
	if len(removed) != 1 || removed[0] != "b@x.id" {
		t.Fatalf("removed = %v, want [b@x.id]", removed)
	}
	if len(added) != 1 || added[0] != "c@x.id" {
		t.Fatalf("added = %v, want [c@x.id]", added)
	}
}

func TestComputeUserOpsChangedClient(t *testing.T) {
	oldCfg := hotTestConfig(t, testInbound("in-1", 443, "vless", testClient("a@x.id", "u1")))
	newCfg := hotTestConfig(t, testInbound("in-1", 443, "vless", testClient("a@x.id", "u2")))
	ops, hot := computeUserOps(oldCfg, newCfg)
	if !hot {
		t.Fatalf("client edit must be hot")
	}
	if len(ops) != 2 {
		t.Fatalf("changed client must yield remove+add, got %+v", ops)
	}
	if !ops[0].Remove || ops[0].Email != "a@x.id" {
		t.Fatalf("first op must remove a@x.id, got %+v", ops[0])
	}
	if ops[1].Remove || ops[1].User["id"] != "u2" {
		t.Fatalf("second op must add a@x.id with u2, got %+v", ops[1])
	}
}

func TestComputeUserOpsDisabledClientIsRemoval(t *testing.T) {
	// renderConfig filters disabled clients before the diff, so the
	// new config simply lacks the client: a removal op.
	oldCfg := hotTestConfig(t, testInbound("in-1", 443, "vless", testClient("a@x.id", "u1")))
	newCfg := hotTestConfig(t, testInbound("in-1", 443, "vless"))
	ops, hot := computeUserOps(oldCfg, newCfg)
	if !hot || len(ops) != 1 || !ops[0].Remove || ops[0].Email != "a@x.id" {
		t.Fatalf("hot=%v ops=%+v, want one removal of a@x.id", hot, ops)
	}
}

func TestComputeUserOpsDuplicates(t *testing.T) {
	// Multi-port duplicates share settings: ops must be emitted for
	// every tag serving the inbound, or the duplicate keeps serving
	// the removed user.
	oldCfg := hotTestConfig(t,
		testInbound("in-1", 443, "vless", testClient("a@x.id", "u1")),
		testInbound("in-1-nat5010", 5010, "vless", testClient("a@x.id", "u1")),
	)
	newCfg := hotTestConfig(t,
		testInbound("in-1", 443, "vless"),
		testInbound("in-1-nat5010", 5010, "vless"),
	)
	ops, hot := computeUserOps(oldCfg, newCfg)
	if !hot {
		t.Fatalf("duplicate tags must stay hot")
	}
	if len(ops) != 2 {
		t.Fatalf("want 2 removal ops (one per tag), got %+v", ops)
	}
	seen := map[string]bool{}
	for _, op := range ops {
		seen[op.Tag] = true
	}
	if !seen["in-1"] || !seen["in-1-nat5010"] {
		t.Fatalf("ops must cover both tags, got %+v", ops)
	}
}

func TestComputeUserOpsNotHot(t *testing.T) {
	base := testInbound("in-1", 443, "vless", testClient("a@x.id", "u1"))
	oldCfg := hotTestConfig(t, base)

	cases := map[string][]byte{
		"port change": func() []byte {
			ib := testInbound("in-1", 444, "vless", testClient("a@x.id", "u1"))
			return hotTestConfig(t, ib)
		}(),
		"streamSettings change": func() []byte {
			ib := testInbound("in-1", 443, "vless", testClient("a@x.id", "u1"))
			ib["streamSettings"] = map[string]any{"security": "tls"}
			return hotTestConfig(t, ib)
		}(),
		"settings rest change": func() []byte {
			ib := testInbound("in-1", 443, "vless", testClient("a@x.id", "u1"))
			ib["settings"] = map[string]any{"clients": []any{testClient("a@x.id", "u1")}, "decryption": "none", "fallbacks": []any{}}
			return hotTestConfig(t, ib)
		}(),
		"inbound added": hotTestConfig(t, base, testInbound("in-2", 8443, "vless", testClient("b@x.id", "u2"))),
		"inbound removed": hotTestConfig(t),
		"socks protocol": func() []byte {
			oldS := hotTestConfig(t, testInbound("in-1", 443, "socks", testClient("a@x.id", "u1")))
			_ = oldS
			return hotTestConfig(t, testInbound("in-1", 443, "socks", testClient("a@x.id", "u1"), testClient("b@x.id", "u2")))
		}(),
		"reverse client": func() []byte {
			c := testClient("a@x.id", "u1")
			c["reverse"] = "rev-tag"
			return hotTestConfig(t, testInbound("in-1", 443, "vless", c))
		}(),
	}
	for name, newCfg := range cases {
		old := oldCfg
		if name == "socks protocol" {
			old = hotTestConfig(t, testInbound("in-1", 443, "socks", testClient("a@x.id", "u1")))
		}
		if _, hot := computeUserOps(old, newCfg); hot {
			t.Fatalf("%s: must NOT be hot", name)
		}
	}
}

func TestParseAPICount(t *testing.T) {
	n, ok := parseAPICount("processing inbound: x\nadd user: a@x.id\nresult: ok\nAdded 1 user(s) in total.\n", "Added")
	if !ok || n != 1 {
		t.Fatalf("Added parse = %d,%v", n, ok)
	}
	n, ok = parseAPICount("Added 0 user(s) in total.\n", "Added")
	if !ok || n != 0 {
		t.Fatalf("Added 0 parse = %d,%v", n, ok)
	}
	n, ok = parseAPICount("remove user: a@x.id\nRemoved 2 user(s) in total.\n", "Removed")
	if !ok || n != 2 {
		t.Fatalf("Removed parse = %d,%v", n, ok)
	}
	if _, ok := parseAPICount("some other output\n", "Added"); ok {
		t.Fatalf("missing count line must not parse")
	}
}

func TestRenderConfigFiltersDisabled(t *testing.T) {
	a := newTestAgent()
	a.state.Inbounds[0].Protocol = "vless"
	a.state.Inbounds[0].Enable = true
	a.state.Inbounds[0].Port = 443
	a.state.Inbounds[0].Settings = `{"clients":[{"email":"a@x.id","id":"u1","enable":true},{"email":"b@x.id","id":"u2","enable":false}],"decryption":"none"}`
	data, err := a.renderConfig()
	if err != nil {
		t.Fatalf("renderConfig: %v", err)
	}
	if strings.Contains(string(data), "b@x.id") {
		t.Fatalf("disabled client reached rendered config: %s", data)
	}
	if !strings.Contains(string(data), "a@x.id") {
		t.Fatalf("enabled client missing: %s", data)
	}
}
