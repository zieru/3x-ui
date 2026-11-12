package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestCompareAgentVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"v3.11.0-agent5", "v3.11.0-agent5", 0},
		{"v3.11.0-agent5", "v3.11.0-agent6", -1},
		{"v3.11.0-agent6", "v3.11.0-agent5", 1},
		{"v3.11.0-agent6", "v3.11.0-agent6.1", -1},
		{"v3.11.0-agent6.1", "v3.11.0-agent6", 1},
		{"v3.11.0-agent6.1", "v3.11.0-agent6.1", 0},
		{"v3.11.0-agent6.10", "v3.11.0-agent6.9", 1}, // numeric, not lexical
		{"v3.11.0-agent10", "v3.11.0-agent9", 1},
		{"dev", "v3.11.0-agent6", -1},    // unparseable sorts below releases
		{"v3.11.0-agent6", "dev", 1},
		{"", "v3.11.0-agent6", -1},
	}
	for _, c := range cases {
		if got := compareAgentVersions(c.a, c.b); got != c.want {
			t.Fatalf("compareAgentVersions(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestReleaseAssetLookup(t *testing.T) {
	raw := `{"tag_name":"agent-latest","assets":[
		{"name":"version.txt","browser_download_url":"https://example.invalid/v"},
		{"name":"x-ui-agent-linux-amd64","browser_download_url":"https://example.invalid/b"},
		{"name":"x-ui-agent-linux-amd64.sha256","browser_download_url":"https://example.invalid/s"}
	]}`
	var rel releaseInfo
	if err := json.Unmarshal([]byte(raw), &rel); err != nil {
		t.Fatalf("parse release: %v", err)
	}
	if rel.Tag != "agent-latest" {
		t.Fatalf("tag = %q", rel.Tag)
	}
	url, ok := rel.asset("version.txt")
	if !ok || url != "https://example.invalid/v" {
		t.Fatalf("version.txt asset = %q,%v", url, ok)
	}
	if _, ok := rel.asset("nope"); ok {
		t.Fatalf("missing asset reported present")
	}
}

func TestVerifyChecksum(t *testing.T) {
	data := []byte("fake binary bytes")
	sum := sha256.Sum256(data)
	doc := hex.EncodeToString(sum[:]) + "  x-ui-agent-linux-amd64\n"
	if err := verifyChecksum(data, doc); err != nil {
		t.Fatalf("valid checksum rejected: %v", err)
	}
	if err := verifyChecksum([]byte("tampered"), doc); err == nil {
		t.Fatalf("tampered data passed checksum")
	}
	if err := verifyChecksum(data, ""); err == nil {
		t.Fatalf("empty checksum doc passed")
	}
	if err := verifyChecksum(data, "zzzz  x\n"); err == nil {
		t.Fatalf("bad hex passed")
	}
}

func TestCheckUpdateNoToken(t *testing.T) {
	a := &Agent{stateDir: t.TempDir()}
	st := a.CheckUpdateNow()
	if !st.NoToken {
		t.Fatalf("missing token file must report NoToken, got %+v", st)
	}
	if st.Available {
		t.Fatalf("no-token check must not report an update")
	}
}

func TestAutoUpdateMarker(t *testing.T) {
	dir := t.TempDir()
	a := &Agent{stateDir: dir}
	if a.autoUpdateEnabled() {
		t.Fatalf("marker absent but enabled")
	}
	if err := os.WriteFile(filepath.Join(dir, updateMarkerFile), []byte{}, 0o600); err != nil {
		t.Fatal(err)
	}
	if !a.autoUpdateEnabled() {
		t.Fatalf("marker present but disabled")
	}
}

func TestApplyUpdateRequiresMarker(t *testing.T) {
	a := &Agent{stateDir: t.TempDir()}
	if err := a.ApplyUpdate(false); err == nil {
		t.Fatalf("ApplyUpdate without marker must fail")
	}
}
