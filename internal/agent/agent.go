// Package agent implements the x-ui mini node agent.
//
// The agent is a drop-in 3x-ui Node for a master panel, without running
// the full panel (no web UI, no SQL database, no Telegram bot, no
// frontend). It speaks the subset of the upstream node-sync API that the
// master actually calls (see docs/node-agent.md and
// ~/workspace/3x-ui-agent-design/NODE_API.md), stores its state in a
// single JSON file, renders a minimal Xray config.json and supervises a
// single xray-core child process (restart-only apply, no gRPC).
//
// Isolated by design: this package imports only the Go standard library
// and shares no code with internal/web, internal/database or
// internal/xray, so upstream panel updates do not break it. The wire
// format (envelope, form-encoded inbound pushes, Bearer node-sync
// token) is re-implemented here from the upstream documentation, not
// imported.
package agent

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Version is the agent's own version string, reported as panelVersion
// in GET /server/status. Keep it distinct from the upstream panel
// version so a master can tell an agent node from a full panel node.
const Version = "v3.11.0-agent1"

// Inbound mirrors the fields of model.Inbound that the master reads
// back from GET /inbounds/list and pushes via wireInbound().
// Settings / StreamSettings / Sniffing are stored as raw JSON strings,
// exactly as pushed by the master.
type Inbound struct {
	ID                   int    `json:"id"`
	Up                   int64  `json:"up"`
	Down                 int64  `json:"down"`
	Total                int64  `json:"total"`
	Remark               string `json:"remark"`
	SubSortIndex         int    `json:"subSortIndex"`
	ExcludeFromSub       bool   `json:"excludeFromSub"`
	Enable               bool   `json:"enable"`
	ExpiryTime           int64  `json:"expiryTime"`
	TrafficReset         string `json:"trafficReset"`
	TrafficResetDay      int    `json:"trafficResetDay"`
	LastTrafficResetTime int64  `json:"lastTrafficResetTime"`
	Listen               string `json:"listen"`
	Port                 int    `json:"port"`
	Protocol             string `json:"protocol"`
	Settings             string `json:"settings"`
	StreamSettings       string `json:"streamSettings"`
	Tag                  string `json:"tag"`
	Sniffing             string `json:"sniffing"`
	ShareAddrStrategy    string `json:"shareAddrStrategy"`
	ShareAddr            string `json:"shareAddr"`
	DisableFlow          bool   `json:"disableFlow"`
	OriginNodeGuid       string `json:"originNodeGuid,omitempty"`
	// ClientStats is derived from Settings.clients on read; counters
	// are honest zeros in v1 (see traffic.go notes in docs/node-agent.md).
	ClientStats []ClientTraffic `json:"clientStats"`
}

// ClientTraffic mirrors xray.ClientTraffic for the fields the master
// decodes from /inbounds/list.
type ClientTraffic struct {
	ID         int    `json:"id"`
	InboundID  int    `json:"inboundId"`
	Enable     bool   `json:"enable"`
	Email      string `json:"email"`
	UUID       string `json:"uuid,omitempty"`
	SubID      string `json:"subId,omitempty"`
	Up         int64  `json:"up"`
	Down       int64  `json:"down"`
	ExpiryTime int64  `json:"expiryTime"`
	Total      int64  `json:"total"`
	Reset      int    `json:"reset"`
}

// State is the agent's whole persistent state, stored as one JSON file
// (0600) in the state dir. No SQL database.
type State struct {
	PanelGuid string    `json:"panelGuid"`
	NextID    int       `json:"nextId"`
	Inbounds  []Inbound `json:"inbounds"`
}

// Agent holds the runtime state.
type Agent struct {
	mu             sync.Mutex
	xrayMu         sync.Mutex // protects xray process pointer/state only
	statePath      string
	configPath     string
	tokenPath      string
	xrayBin        string
	token          string
	tokenGenerated bool
	state          State
	startedAt      time.Time
	xray           *xrayProcess
	xrayVersion    string
}

// New creates an Agent. It loads (or creates) the state file and the
// token file. If the token file does not exist, a random token is
// generated and written 0600 — the operator copies it once to the
// master panel (Settings → API Tokens is not used on the agent side;
// the master stores this plaintext token as the node's API token).
func New(stateDir, tokenPath, xrayBin string) (*Agent, error) {
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return nil, err
	}
	a := &Agent{
		statePath:  filepath.Join(stateDir, "state.json"),
		configPath: filepath.Join(stateDir, "config.json"),
		tokenPath:  tokenPath,
		xrayBin:    xrayBin,
		startedAt:  time.Now(),
	}
	if err := a.loadState(); err != nil {
		return nil, err
	}
	if err := a.loadOrCreateToken(); err != nil {
		return nil, err
	}
	a.xrayVersion = detectXrayVersion(xrayBin)
	return a, nil
}

func (a *Agent) loadState() error {
	data, err := os.ReadFile(a.statePath)
	if err != nil {
		if os.IsNotExist(err) {
			a.state = State{PanelGuid: newUUID(), NextID: 1, Inbounds: []Inbound{}}
			return a.saveStateLocked()
		}
		return err
	}
	if err := json.Unmarshal(data, &a.state); err != nil {
		return fmt.Errorf("parse state file: %w", err)
	}
	if a.state.PanelGuid == "" {
		a.state.PanelGuid = newUUID()
	}
	if a.state.NextID < 1 {
		a.state.NextID = 1
	}
	if a.state.Inbounds == nil {
		a.state.Inbounds = []Inbound{}
	}
	return nil
}

func (a *Agent) saveStateLocked() error {
	data, err := json.MarshalIndent(a.state, "", "  ")
	if err != nil {
		return err
	}
	tmp := a.statePath + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, a.statePath)
}

// Save persists the state file. Caller must hold no lock; Save locks.
func (a *Agent) Save() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.saveStateLocked()
}

func (a *Agent) loadOrCreateToken() error {
	if a.tokenPath == "" {
		return fmt.Errorf("token file path is empty")
	}
	data, err := os.ReadFile(a.tokenPath)
	if err == nil {
		a.token = strings.TrimSpace(string(data))
		if a.token != "" {
			return nil
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	// Generate a fresh token once. The operator copies it to the master.
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return err
	}
	a.token = hex.EncodeToString(b)
	a.tokenGenerated = true
	if dir := filepath.Dir(a.tokenPath); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	if err := os.WriteFile(a.tokenPath, []byte(a.token+"\n"), 0o600); err != nil {
		return err
	}
	return nil
}

// Token returns the plaintext node-sync token (for logging once at
// startup only; never log it per-request).
func (a *Agent) Token() string { return a.token }

// TokenGenerated reports whether the token file was created fresh on
// this start (vs. loaded from an existing file).
func (a *Agent) TokenGenerated() bool { return a.tokenGenerated }

// PanelGuid returns the stable node identity.
func (a *Agent) PanelGuid() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.state.PanelGuid
}

// checkToken does a constant-time Bearer comparison.
func (a *Agent) checkToken(authHeader string) bool {
	const prefix = "Bearer "
	if !strings.HasPrefix(authHeader, prefix) {
		return false
	}
	got := strings.TrimSpace(authHeader[len(prefix):])
	if got == "" || a.token == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(a.token)) == 1
}

// sha256Hex is the wirecodec.Sha256Hex equivalent.
func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func newUUID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// Fall back to a time-based value; still unique enough for v1.
		return fmt.Sprintf("agent-%d", time.Now().UnixNano())
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func parseBool(s string) bool {
	b, _ := strconv.ParseBool(strings.TrimSpace(s))
	return b
}

func parseInt(s string, def int) int {
	if s == "" {
		return def
	}
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return def
	}
	return n
}

func parseInt64(s string, def int64) int64 {
	if s == "" {
		return def
	}
	n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil {
		return def
	}
	return n
}
