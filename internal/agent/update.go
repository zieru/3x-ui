package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// update.go — v6 self-update from GitHub Releases.
//
// The GitHub Actions workflow (.github/workflows/agent-release.yml)
// builds the agent on every push to an agent-v* branch and publishes
// the binary to the floating `agent-latest` release. This updater
// polls that release, and when it carries a newer version it
// downloads the binary, verifies its SHA-256 checksum and smoke-tests
// it, installs it over the running executable, and re-execs itself.
//
// The repository is PRIVATE, so the GitHub API needs a token: a
// fine-grained PAT with Contents: Read on zieru/3x-ui, stored 0600
// at <state-dir>/github-token. Without it the updater stays dormant
// (checkUpdate reports "no github token") — it never fails loudly,
// because a missing token is a configuration state, not an error.
//
// Auto-install is gated by a marker file, <state-dir>/autoupdate:
// the background loop only installs when the file exists. The manual
// POST server/applyUpdate endpoint requires the marker too. The
// read-only POST server/checkUpdate endpoint does not.
// updatePanel stays refused: the panel's "Update node" button must
// never drive this (see server.go).

const (
	updateRepoOwner = "zieru"
	updateRepoName  = "3x-ui"
	updateTag       = "agent-latest"
	updateBinName   = "x-ui-agent-linux-amd64"
	updateCheckURL  = "https://api.github.com/repos/" + updateRepoOwner + "/" + updateRepoName + "/releases/tags/" + updateTag

	updateMarkerFile = "autoupdate"
	updateTokenFile  = "github-token"

	updateCheckInterval = 6 * time.Hour
	updateFirstDelay    = 5 * time.Minute
	updateMaxDownload   = 64 << 20 // binary is ~7 MB; 64 MB is a sanity cap
)

// updateStatus is the cached result of the last release check.
type updateStatus struct {
	CheckedAt   time.Time
	Latest      string
	Available   bool
	LastError   string
	NoToken     bool
	LastApplied time.Time
}

// compareAgentVersions compares "v3.11.0-agent6" style versions by
// the numeric segments after "agent": agent6 < agent6.1 < agent7.
// A version without a parseable agent suffix sorts below any
// parseable one (a dev build is always "older" than a release).
// Returns -1, 0 or 1.
func compareAgentVersions(a, b string) int {
	as := agentVersionSegments(a)
	bs := agentVersionSegments(b)
	if as == nil && bs == nil {
		if a == b {
			return 0
		}
		return strings.Compare(a, b)
	}
	if as == nil {
		return -1
	}
	if bs == nil {
		return 1
	}
	for i := 0; i < len(as) || i < len(bs); i++ {
		var av, bv int
		if i < len(as) {
			av = as[i]
		}
		if i < len(bs) {
			bv = bs[i]
		}
		if av != bv {
			if av < bv {
				return -1
			}
			return 1
		}
	}
	return 0
}

// agentVersionSegments extracts the numeric segments after "agent"
// in a version string. Returns nil when there is no parseable suffix.
func agentVersionSegments(v string) []int {
	idx := strings.LastIndex(v, "agent")
	if idx < 0 {
		return nil
	}
	rest := v[idx+len("agent"):]
	if rest == "" {
		return nil
	}
	parts := strings.Split(rest, ".")
	out := make([]int, 0, len(parts))
	for _, p := range parts {
		// Tolerate a trailing non-numeric tail ("6rc1" -> 6).
		digits := ""
		for _, r := range p {
			if r < '0' || r > '9' {
				break
			}
			digits += string(r)
		}
		if digits == "" {
			return nil
		}
		n, err := strconv.Atoi(digits)
		if err != nil {
			return nil
		}
		out = append(out, n)
	}
	return out
}

type releaseAsset struct {
	Name string `json:"name"`
	URL  string `json:"browser_download_url"`
}

type releaseInfo struct {
	Tag    string         `json:"tag_name"`
	Assets []releaseAsset `json:"assets"`
}

func (r *releaseInfo) asset(name string) (string, bool) {
	for _, a := range r.Assets {
		if a.Name == name {
			return a.URL, true
		}
	}
	return "", false
}

// githubClient is an HTTP client that sends the PAT on the initial
// request and strips Authorization when redirected to another host
// (GitHub redirects asset downloads to signed S3 URLs, which must
// not receive the token).
func githubClient(token string) *http.Client {
	return &http.Client{
		Timeout: 90 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > 0 && req.URL.Host != via[0].URL.Host {
				req.Header.Del("Authorization")
			}
			if len(via) >= 10 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
		Transport: &githubAuthTransport{token: token, base: http.DefaultTransport},
	}
}

type githubAuthTransport struct {
	token string
	base  http.RoundTripper
}

func (t *githubAuthTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	clone.Header.Set("Authorization", "Bearer "+t.token)
	clone.Header.Set("Accept", "application/vnd.github+json")
	return t.base.RoundTrip(clone)
}

// fetchURL GETs a URL with the token, enforcing the download cap.
// A non-2xx status is an error.
func fetchURL(ctx context.Context, client *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		return nil, fmt.Errorf("GET %s: HTTP %s", url, resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, updateMaxDownload+1))
}

// verifyChecksum checks data against a sha256sum-style checksum
// document ("<hex>  <filename>\n"). The filename is ignored.
func verifyChecksum(data []byte, checksumDoc string) error {
	fields := strings.Fields(checksumDoc)
	if len(fields) == 0 {
		return fmt.Errorf("empty checksum document")
	}
	want, err := hex.DecodeString(fields[0])
	if err != nil {
		return fmt.Errorf("bad checksum hex: %w", err)
	}
	sum := sha256.Sum256(data)
	if !bytesEqual(sum[:], want) {
		return fmt.Errorf("checksum mismatch")
	}
	return nil
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

// --- Agent wiring ---

// updateMu serializes update checks/applies; updateState holds the
// cached check result. Both are separate from mu: network I/O must
// never hold the state lock.
func (a *Agent) autoUpdateEnabled() bool {
	_, err := os.Stat(filepath.Join(a.stateDir, updateMarkerFile))
	return err == nil
}

func (a *Agent) githubToken() (string, error) {
	data, err := os.ReadFile(filepath.Join(a.stateDir, updateTokenFile))
	if err != nil {
		return "", err
	}
	token := strings.TrimSpace(string(data))
	if token == "" {
		return "", fmt.Errorf("empty github token file")
	}
	return token, nil
}

func (a *Agent) getUpdateStatus() updateStatus {
	a.updateMu.Lock()
	defer a.updateMu.Unlock()
	return a.updateState
}

// CheckUpdateNow queries the release and records whether a newer
// version is available. It never installs anything and does not
// require the autoupdate marker (the token is still required).
func (a *Agent) CheckUpdateNow() updateStatus {
	a.updateMu.Lock()
	defer a.updateMu.Unlock()
	st := a.updateState
	st.CheckedAt = time.Now()
	st.LastError = ""
	st.NoToken = false

	token, err := a.githubToken()
	if err != nil {
		st.NoToken = true
		st.Available = false
		st.LastError = "no github token: " + err.Error()
		a.updateState = st
		return st
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	client := githubClient(token)
	raw, err := fetchURL(ctx, client, updateCheckURL)
	if err != nil {
		st.LastError = err.Error()
		a.updateState = st
		return st
	}
	var rel releaseInfo
	if err := json.Unmarshal(raw, &rel); err != nil {
		st.LastError = "parse release: " + err.Error()
		a.updateState = st
		return st
	}
	verURL, ok := rel.asset("version.txt")
	if !ok {
		st.LastError = "release has no version.txt asset"
		a.updateState = st
		return st
	}
	verRaw, err := fetchURL(ctx, client, verURL)
	if err != nil {
		st.LastError = "fetch version.txt: " + err.Error()
		a.updateState = st
		return st
	}
	latest := strings.TrimSpace(string(verRaw))
	st.Latest = latest
	st.Available = compareAgentVersions(Version, latest) < 0
	a.updateState = st
	return st
}

// ApplyUpdate downloads, verifies and installs the latest release,
// then re-execs the agent. force installs even when the release
// version equals the running one (recovery / pipeline proof). It
// returns nil only when no install was needed; a successful install
// never returns (the process image is replaced). Callers that need a
// reply (HTTP) must respond before calling this in a goroutine.
func (a *Agent) ApplyUpdate(force bool) error {
	if !a.autoUpdateEnabled() {
		return fmt.Errorf("autoupdate is not enabled (missing %s marker file)", updateMarkerFile)
	}
	st := a.CheckUpdateNow()
	if st.NoToken {
		return fmt.Errorf("autoupdate: %s", st.LastError)
	}
	if st.LastError != "" {
		return fmt.Errorf("update check failed: %s", st.LastError)
	}
	if !st.Available && !force {
		return nil // already current; not an error
	}
	if err := a.installRelease(st.Latest); err != nil {
		return err
	}
	// installRelease replaced the executable on disk. Stop Xray so
	// the new process starts clean (no orphan holding the ports),
	// persist state, then replace this process image: same PID, so
	// OpenRC keeps tracking it and the API port never closes
	// longer than the exec takes.
	a.Shutdown()
	exe, err := os.Executable()
	if err != nil {
		// Last resort: restart Xray under the old image; the new
		// binary takes over at the next agent restart.
		_ = a.StartXray()
		return fmt.Errorf("os.Executable: %w (new binary installed, takes effect on next agent restart)", err)
	}
	log.Printf("autoupdate: installed %s, re-execing", st.Latest)
	if err := syscall.Exec(exe, os.Args, os.Environ()); err != nil {
		_ = a.StartXray()
		return fmt.Errorf("re-exec %s: %w (new binary installed, takes effect on next agent restart)", exe, err)
	}
	return nil // unreachable
}

// installRelease downloads the release binary + checksum, verifies
// both, smoke-tests the binary, and atomically installs it over the
// running executable (keeping a .bak copy of the previous binary).
func (a *Agent) installRelease(expectVersion string) error {
	token, err := a.githubToken()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	client := githubClient(token)
	raw, err := fetchURL(ctx, client, updateCheckURL)
	if err != nil {
		return fmt.Errorf("fetch release: %w", err)
	}
	var rel releaseInfo
	if err := json.Unmarshal(raw, &rel); err != nil {
		return fmt.Errorf("parse release: %w", err)
	}
	binURL, ok := rel.asset(updateBinName)
	if !ok {
		return fmt.Errorf("release has no %s asset", updateBinName)
	}
	sumURL, ok := rel.asset(updateBinName + ".sha256")
	if !ok {
		return fmt.Errorf("release has no %s.sha256 asset", updateBinName)
	}
	bin, err := fetchURL(ctx, client, binURL)
	if err != nil {
		return fmt.Errorf("download binary: %w", err)
	}
	sumDoc, err := fetchURL(ctx, client, sumURL)
	if err != nil {
		return fmt.Errorf("download checksum: %w", err)
	}
	if err := verifyChecksum(bin, string(sumDoc)); err != nil {
		return fmt.Errorf("verify binary: %w", err)
	}
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("os.Executable: %w", err)
	}
	dir := filepath.Dir(exe)
	staging := filepath.Join(dir, filepath.Base(exe)+".new")
	if err := os.WriteFile(staging, bin, 0o755); err != nil {
		return fmt.Errorf("write staging binary: %w", err)
	}
	// Smoke test: the staged binary must run and report the
	// expected version. A binary that cannot even do that must
	// never replace the live one.
	smokeCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	out, err := exec.CommandContext(smokeCtx, staging, "-version").CombinedOutput()
	if err != nil {
		_ = os.Remove(staging)
		return fmt.Errorf("smoke test %s -version: %w: %s", staging, err, strings.TrimSpace(string(out)))
	}
	if !strings.Contains(string(out), expectVersion) {
		_ = os.Remove(staging)
		return fmt.Errorf("smoke test: staged binary reports %q, want %q", strings.TrimSpace(string(out)), expectVersion)
	}
	// Keep a backup of the running binary, then swap. Renaming over
	// a running executable is safe on Linux (the old inode stays
	// alive for the running process).
	bak := exe + ".bak"
	if cur, err := os.ReadFile(exe); err == nil {
		_ = os.WriteFile(bak, cur, 0o755)
	}
	if err := os.Rename(staging, exe); err != nil {
		_ = os.Remove(staging)
		return fmt.Errorf("install binary: %w", err)
	}
	a.updateMu.Lock()
	a.updateState.LastApplied = time.Now()
	a.updateMu.Unlock()
	return nil
}

// StartUpdater launches the background update loop. It returns
// immediately; the loop first waits, then checks every
// updateCheckInterval and installs when the marker file exists and a
// newer release is available. All failures are logged and retried on
// the next cycle — the loop never kills the agent.
func (a *Agent) StartUpdater() {
	go func() {
		timer := time.NewTimer(updateFirstDelay)
		defer timer.Stop()
		for {
			<-timer.C
			timer.Reset(updateCheckInterval)
			if !a.autoUpdateEnabled() {
				continue
			}
			st := a.CheckUpdateNow()
			if st.NoToken {
				log.Printf("autoupdate: dormant, %s", st.LastError)
				continue
			}
			if st.LastError != "" {
				log.Printf("autoupdate: check failed: %s", st.LastError)
				continue
			}
			if !st.Available {
				continue
			}
			log.Printf("autoupdate: %s available (running %s), installing", st.Latest, Version)
			// ApplyUpdate re-execs on success and never returns.
			// On failure it returns an error; keep serving.
			if err := a.ApplyUpdate(false); err != nil {
				log.Printf("autoupdate: install failed: %v", err)
			}
		}
	}()
}
