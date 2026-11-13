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
		{"dev", "v3.11.0-agent6", -1}, // unparseable sorts below releases
		{"v3.11.0-agent6", "dev", 1},
		{"", "v3.11.0-agent6", -1},
	}
	for _, c := range cases {
		if got := compareAgentVersions(c.a, c.b); got != c.want {
			t.Fatalf("compareAgentVersions(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestCompareCoreVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"26.10.21", "26.10.21", 0},
		{"26.10.21", "26.11.9", -1},
		{"26.11.9", "26.10.21", 1},
		{"26.10.31", "26.11.9", -1},
		{"26.11.9", "26.11.10", -1},  // numeric, not lexical
		{"v26.11.9", "26.11.9", 0},   // leading v tolerated
		{"26.11", "26.11.0", 0},      // missing segment counts as 0
		{"26.11.9rc1", "26.11.9", 0}, // trailing tail tolerated
		{"", "26.11.9", -1},          // unparseable sorts below
		{"26.11.9", "", 1},
		{"garbage", "26.11.9", -1},
	}
	for _, c := range cases {
		if got := compareCoreVersions(c.a, c.b); got != c.want {
			t.Fatalf("compareCoreVersions(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestPlanInstall(t *testing.T) {
	cases := []struct {
		name    string
		st      updateStatus
		force   bool
		hasCore bool
		want    installPlan
	}{
		{"nothing", updateStatus{}, false, true, installPlan{}},
		{"agent only", updateStatus{Available: true}, false, true, installPlan{agent: true}},
		{"core only", updateStatus{CoreAvailable: true}, false, true, installPlan{core: true}},
		{"both", updateStatus{Available: true, CoreAvailable: true}, false, true, installPlan{true, true}},
		{"core wanted but release has no core assets", updateStatus{CoreAvailable: true}, false, false, installPlan{}},
		{"force installs both when core present", updateStatus{}, true, true, installPlan{true, true}},
		{"force with agent-only release", updateStatus{}, true, false, installPlan{agent: true}},
	}
	for _, c := range cases {
		if got := planInstall(c.st, c.force, c.hasCore); got != c.want {
			t.Fatalf("%s: planInstall = %+v, want %+v", c.name, got, c.want)
		}
	}
}

func writeFakeXray(t *testing.T, dir, output string) string {
	t.Helper()
	path := filepath.Join(dir, "xray-fake")
	script := "#!/bin/sh\necho '" + output + "'\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestDetectXrayVersion(t *testing.T) {
	if got := detectXrayVersion(""); got != "" {
		t.Fatalf("empty bin = %q", got)
	}
	if got := detectXrayVersion(filepath.Join(t.TempDir(), "nope")); got != "" {
		t.Fatalf("missing bin = %q", got)
	}
	fake := writeFakeXray(t, t.TempDir(), "Xray 26.11.9 (Xray, Penetrates Everything.) 676eaf6 (go1.27.3 linux/amd64)")
	if got := detectXrayVersion(fake); got != "26.11.9" {
		t.Fatalf("fake xray version = %q, want 26.11.9", got)
	}
}

func TestSmokeTestCore(t *testing.T) {
	dir := t.TempDir()
	// No config file: only the version check runs.
	a := &Agent{configPath: filepath.Join(dir, "missing.json")}
	fake := writeFakeXray(t, dir, "Xray 26.11.9 (Xray, Penetrates Everything.) x")
	if err := a.smokeTestCore(fake, "26.11.9"); err != nil {
		t.Fatalf("matching core rejected: %v", err)
	}
	if err := a.smokeTestCore(fake, "26.10.21"); err == nil {
		t.Fatalf("mismatched core passed smoke test")
	}
	if err := a.smokeTestCore(filepath.Join(dir, "nope"), "26.11.9"); err == nil {
		t.Fatalf("non-running binary passed smoke test")
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
