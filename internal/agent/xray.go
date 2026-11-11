package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// xrayProcess supervises a single xray-core child process.
// Restart-only apply: every config change rewrites config.json,
// runs `xray -test`, then restarts the child. No gRPC hot-apply in v1.
type xrayProcess struct {
	bin        string
	configPath string
	cmd        *exec.Cmd
	state      string // "running" | "stop" | "error"
	errMsg     string
	logPath    string
	done       chan struct{} // closed by the monitor goroutine after Wait
}

func detectXrayVersion(bin string) string {
	if bin == "" {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, bin, "-version").Output()
	if err != nil {
		return ""
	}
	// Output is like "Xray 25.10.31 (Xray, Penetrates Everything.) ..."
	fields := strings.Fields(string(out))
	if len(fields) >= 2 {
		return fields[1]
	}
	return strings.TrimSpace(string(out))
}

// stripVlessEncryption removes the top-level "encryption" key from a
// VLESS settings JSON string, mirroring
// model.StripVlessInboundEncryption in upstream. Returns the original
// string unchanged when there is nothing to strip.
func stripVlessEncryption(settings string) string {
	if settings == "" {
		return settings
	}
	var parsed map[string]any
	if err := json.Unmarshal([]byte(settings), &parsed); err != nil {
		return settings
	}
	if _, ok := parsed["encryption"]; !ok {
		return settings
	}
	delete(parsed, "encryption")
	out, err := json.Marshal(parsed)
	if err != nil {
		return settings
	}
	return string(out)
}

// settingsClients extracts the clients array from a settings JSON
// string, as []map[string]any, for client add/remove/update and for
// building clientStats. Returns an empty slice on parse failure.
func settingsClients(settings string) []map[string]any {
	var parsed map[string]any
	if err := json.Unmarshal([]byte(settings), &parsed); err != nil {
		return nil
	}
	raw, ok := parsed["clients"].([]any)
	if !ok {
		return nil
	}
	out := make([]map[string]any, 0, len(raw))
	for _, c := range raw {
		if m, ok := c.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

// setSettingsClients replaces the clients array in a settings JSON
// string and returns the new JSON. Other top-level keys are preserved.
func setSettingsClients(settings string, clients []map[string]any) string {
	var parsed map[string]any
	if err := json.Unmarshal([]byte(settings), &parsed); err != nil {
		parsed = map[string]any{}
	}
	raw := make([]any, 0, len(clients))
	for _, c := range clients {
		raw = append(raw, c)
	}
	parsed["clients"] = raw
	out, err := json.Marshal(parsed)
	if err != nil {
		return settings
	}
	return string(out)
}

func clientEmail(c map[string]any) string {
	if v, ok := c["email"].(string); ok {
		return v
	}
	return ""
}

func clientID(c map[string]any) string {
	if v, ok := c["id"].(string); ok {
		return v
	}
	return ""
}

// clientStatsFor builds the ClientTraffic rows the master decodes from
// /inbounds/list. Counters are real Xray stats in v2 (see stats.go);
// caller holds a.mu and must have called refreshStats() first.
func (a *Agent) clientStatsFor(ib Inbound) []ClientTraffic {
	clients := settingsClients(ib.Settings)
	out := make([]ClientTraffic, 0, len(clients))
	for i, c := range clients {
		email := clientEmail(c)
		enable := true
		if v, ok := c["enable"].(bool); ok {
			enable = v
		}
		var expiry int64
		if v, ok := c["expiryTime"].(float64); ok {
			expiry = int64(v)
		}
		var total int64
		if v, ok := c["totalGB"].(float64); ok {
			total = int64(v) * 1024 * 1024 * 1024
		}
		up, down := a.reportedTraffic(email)
		out = append(out, ClientTraffic{
			ID:         i + 1,
			InboundID:  ib.ID,
			Enable:     enable,
			Email:      email,
			UUID:       clientID(c),
			Up:         up,
			Down:       down,
			ExpiryTime: expiry,
			Total:      total,
		})
	}
	return out
}

// renderConfig builds the minimal Xray config.json from the stored
// inbounds: static template (log / api / routing / policy / stats) +
// enabled inbounds only. StreamSettings are passed through unchanged;
// VLESS settings get the "encryption" key stripped, as upstream does.
func (a *Agent) renderConfig() ([]byte, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	type inboundCfg struct {
		Listen         json.RawMessage `json:"listen"`
		Port           int             `json:"port"`
		Protocol       string          `json:"protocol"`
		Settings       json.RawMessage `json:"settings"`
		StreamSettings json.RawMessage `json:"streamSettings,omitempty"`
		Tag            string          `json:"tag"`
		Sniffing       json.RawMessage `json:"sniffing,omitempty"`
	}
	inbounds := make([]inboundCfg, 0, len(a.state.Inbounds)+1)
	for _, ib := range a.state.Inbounds {
		if !ib.Enable {
			continue
		}
		listen := ib.Listen
		if listen == "" {
			listen = "0.0.0.0"
		}
		listenJSON, _ := json.Marshal(listen)
		settings := ib.Settings
		if strings.EqualFold(ib.Protocol, "vless") {
			settings = stripVlessEncryption(settings)
		}
		if settings == "" {
			settings = "{}"
		}
		cfg := inboundCfg{
			Listen:   listenJSON,
			Port:     ib.Port,
			Protocol: ib.Protocol,
			Settings: json.RawMessage(settings),
			Tag:      ib.Tag,
		}
		if ib.StreamSettings != "" {
			cfg.StreamSettings = json.RawMessage(ib.StreamSettings)
		}
		if ib.Sniffing != "" {
			cfg.Sniffing = json.RawMessage(ib.Sniffing)
		}
		inbounds = append(inbounds, cfg)
	}
	// Loopback API inbound (tag "api") — required if stats are ever
	// wired in v2; harmless in v1.
	inbounds = append(inbounds, inboundCfg{
		Listen:   json.RawMessage(`"127.0.0.1"`),
		Port:     10085,
		Protocol: "dokodemo-door",
		Settings: json.RawMessage(`{"address":"127.0.0.1"}`),
		Tag:      "api",
	})
	cfg := map[string]any{
		"log":      map[string]any{"loglevel": "warning"},
		"inbounds": inbounds,
		"outbounds": []map[string]any{
			{"protocol": "freedom", "tag": "direct"},
			{"protocol": "blackhole", "tag": "block"},
		},
		"routing": map[string]any{"rules": []map[string]any{
			{"type": "field", "inboundTag": []string{"api"}, "outboundTag": "api"},
			{"type": "field", "protocol": []string{"bittorrent"}, "outboundTag": "block"},
		}},
		"policy": map[string]any{"levels": map[string]any{"0": map[string]any{
			"statsUserUplink": true, "statsUserDownlink": true}}},
		"api":   map[string]any{"tag": "api", "services": []string{"HandlerService", "LoggerService", "StatsService"}},
		"stats": map[string]any{},
	}
	return json.MarshalIndent(cfg, "", "  ")
}

// writeConfig renders and atomically writes config.json (0600).
// The new config is first written to a temp file and validated with
// `xray -test`; only a passing config replaces the live one, so a bad
// inbound push can never leave a broken config.json behind.
func (a *Agent) writeConfig() error {
	data, err := a.renderConfig()
	if err != nil {
		return err
	}
	// Temp file MUST keep a .json suffix: xray infers the config
	// format from the file extension, and "config.json.tmp" fails
	// with "Failed to get format".
	tmp := a.configPath + ".test.json"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if err := a.testConfigFile(tmp); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, a.configPath)
}

// testConfigFile runs `xray -test -c <path>` (30 s timeout).
// Returns nil when there is no xray binary (nothing to test — the
// agent still serves the API, with xray.state "stop").
func (a *Agent) testConfigFile(path string) error {
	if a.xrayBin == "" {
		return nil
	}
	if _, err := os.Stat(a.xrayBin); err != nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, a.xrayBin, "-test", "-c", path)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("xray -test failed: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// testConfig validates the current config.json on disk.
func (a *Agent) testConfig() error {
	return a.testConfigFile(a.configPath)
}

// killStrayXray terminates any xray process using this agent's
// config file that the agent is not currently tracking — e.g. an
// orphan left behind when a previous agent instance was killed
// without a clean shutdown. Without this, a restarted agent would
// start a second xray while the orphan still holds the inbound
// ports, and traffic would be split between two processes.
func (a *Agent) killStrayXray() {
	a.xrayMu.Lock()
	tracked := 0
	if a.xray != nil && a.xray.cmd != nil && a.xray.cmd.Process != nil {
		tracked = a.xray.cmd.Process.Pid
	}
	a.xrayMu.Unlock()
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return
	}
	var strays []int
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid == os.Getpid() || pid == tracked {
			continue
		}
		cmdline, err := os.ReadFile(filepath.Join("/proc", e.Name(), "cmdline"))
		if err != nil {
			continue
		}
		parts := strings.Split(string(cmdline), "\x00")
		isXray := false
		usesConfig := false
		for _, p := range parts {
			if strings.HasSuffix(p, "/xray") || p == "xray" {
				isXray = true
			}
			if p == a.configPath {
				usesConfig = true
			}
		}
		if isXray && usesConfig {
			strays = append(strays, pid)
		}
	}
	for _, pid := range strays {
		proc, err := os.FindProcess(pid)
		if err != nil {
			continue
		}
		_ = proc.Signal(syscall.SIGTERM)
	}
	if len(strays) == 0 {
		return
	}
	deadline := time.Now().Add(3 * time.Second)
	for _, pid := range strays {
		for time.Now().Before(deadline) {
			if _, err := os.Stat(filepath.Join("/proc", strconv.Itoa(pid))); err != nil {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		if _, err := os.Stat(filepath.Join("/proc", strconv.Itoa(pid))); err == nil {
			if proc, err := os.FindProcess(pid); err == nil {
				_ = proc.Kill()
			}
		}
	}
}

// StartXray renders, tests and (re)starts the xray child process.
// On test failure the previous config and running process are kept.
func (a *Agent) StartXray() error {
	if err := a.writeConfig(); err != nil {
		return err
	}
	if err := a.testConfig(); err != nil {
		a.setXrayState("error", err.Error())
		return err
	}
	a.stopXray()
	a.killStrayXray()
	if a.xrayBin == "" {
		a.setXrayState("stop", "xray binary not configured")
		return nil
	}
	if _, err := os.Stat(a.xrayBin); err != nil {
		a.setXrayState("stop", "xray binary not found: "+a.xrayBin)
		return nil
	}
	logFile, err := os.OpenFile(a.configPath+".log", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		logFile = nil
	}
	cmd := exec.Command(a.xrayBin, "-c", a.configPath)
	if logFile != nil {
		cmd.Stdout = logFile
		cmd.Stderr = logFile
	}
	// Detach from the agent's process group so a terminal hangup does
	// not kill Xray with the agent; the agent still tracks the child.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		a.setXrayState("error", err.Error())
		return err
	}
	done := make(chan struct{})
	a.xrayMu.Lock()
	a.xray = &xrayProcess{bin: a.xrayBin, configPath: a.configPath, cmd: cmd, state: "running", done: done}
	a.xrayMu.Unlock()
	// Reap the child exactly once in a monitor goroutine; stopXray
	// waits on xray.done instead of calling Wait itself (Wait may
	// only be called once per Cmd).
	go func(c *exec.Cmd) {
		err := c.Wait()
		a.xrayMu.Lock()
		defer a.xrayMu.Unlock()
		if a.xray != nil && a.xray.cmd == c {
			if err != nil {
				a.xray.state = "error"
				a.xray.errMsg = err.Error()
			} else {
				a.xray.state = "stop"
				a.xray.errMsg = ""
			}
		}
		if logFile != nil {
			_ = logFile.Close()
		}
		close(done)
	}(cmd)
	return nil
}

func (a *Agent) setXrayState(state, errMsg string) {
	a.xrayMu.Lock()
	defer a.xrayMu.Unlock()
	if a.xray == nil {
		a.xray = &xrayProcess{bin: a.xrayBin, configPath: a.configPath}
	}
	a.xray.state = state
	a.xray.errMsg = errMsg
}

// stopXray stops the running child, waiting up to 5 s for a clean
// exit before SIGKILL. It does not hold xrayMu while waiting, so the
// monitor goroutine can acquire it to close done.
func (a *Agent) stopXray() {
	a.xrayMu.Lock()
	if a.xray == nil || a.xray.cmd == nil || a.xray.cmd.Process == nil {
		a.xrayMu.Unlock()
		return
	}
	proc := a.xray.cmd.Process
	done := a.xray.done
	a.xrayMu.Unlock()
	_ = proc.Signal(syscall.SIGTERM)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		_ = proc.Kill()
		<-done
	}
	a.xrayMu.Lock()
	if a.xray != nil {
		a.xray.cmd = nil
		a.xray.state = "stop"
		a.xray.errMsg = ""
	}
	a.xrayMu.Unlock()
}

// XrayState returns the current xray state for /server/status.
func (a *Agent) XrayState() (state, errMsg, version string) {
	a.xrayMu.Lock()
	defer a.xrayMu.Unlock()
	if a.xray == nil {
		return "stop", "", a.xrayVersion
	}
	return a.xray.state, a.xray.errMsg, a.xrayVersion
}

// Apply regenerates config.json, tests it, and restarts Xray.
// On test failure it returns the error and keeps the old process.
func (a *Agent) Apply() error {
	return a.StartXray()
}

// Shutdown stops the xray child process. Called on SIGTERM/SIGINT
// so a clean agent shutdown does not orphan xray.
func (a *Agent) Shutdown() {
	a.stopXray()
}
