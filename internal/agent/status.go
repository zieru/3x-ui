package agent

import (
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// statusSnapshot is the minimal Status object the master reads from
// GET /server/status. Fields match upstream
// internal/web/service/server.go Status for the subset the master
// actually uses (cpu, mem, xray, panelVersion, panelGuid, uptime,
// netIO, loads). Values come from /proc directly — no gopsutil, which
// is far too heavy for a 93 MB box.
type statusSnapshot struct {
	CPU          float64   `json:"cpu"`
	CPUCores     int       `json:"cpuCores"`
	Mem          memInfo   `json:"mem"`
	Swap         memInfo   `json:"swap"`
	Disk         memInfo   `json:"disk"`
	Xray         xrayInfo  `json:"xray"`
	PanelVersion string    `json:"panelVersion"`
	PanelGuid    string    `json:"panelGuid"`
	Uptime       uint64    `json:"uptime"`
	Loads        []float64 `json:"loads"`
	NetIO        netIO     `json:"netIO"`
	// Self-update state (v6). The master ignores unknown fields.
	UpdateAvailable bool   `json:"updateAvailable"`
	LatestVersion   string `json:"latestVersion"`
	AutoUpdate      bool   `json:"autoUpdate"`
	// Pinned-core update state (v6 combined updater).
	CoreUpdateAvailable bool   `json:"coreUpdateAvailable"`
	LatestCoreVersion   string `json:"latestCoreVersion"`
}

type memInfo struct {
	Current uint64 `json:"current"`
	Total   uint64 `json:"total"`
}

type xrayInfo struct {
	State    string `json:"state"`
	ErrorMsg string `json:"errorMsg"`
	Version  string `json:"version"`
}

type netIO struct {
	Up   uint64 `json:"up"`
	Down uint64 `json:"down"`
}

func readMeminfo() (total, available, swapTotal, swapFree uint64) {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, 0, 0, 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		v, err := strconv.ParseUint(f[1], 10, 64)
		if err != nil {
			continue
		}
		switch f[0] {
		case "MemTotal:":
			total = v * 1024
		case "MemAvailable:":
			available = v * 1024
		case "SwapTotal:":
			swapTotal = v * 1024
		case "SwapFree:":
			swapFree = v * 1024
		}
	}
	return total, available, swapTotal, swapFree
}

func readLoadAvg() []float64 {
	data, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return nil
	}
	f := strings.Fields(string(data))
	out := make([]float64, 0, 3)
	for i := 0; i < 3 && i < len(f); i++ {
		v, err := strconv.ParseFloat(f[i], 64)
		if err == nil {
			out = append(out, v)
		}
	}
	return out
}

func readCPUPercent() float64 {
	// Two samples 200 ms apart, like a cheap top. Called only from
	// /server/status, which the master polls every 5 s, so the cost
	// is acceptable and the value stays fresh.
	read := func() (idle, total uint64) {
		data, err := os.ReadFile("/proc/stat")
		if err != nil {
			return 0, 0
		}
		for _, line := range strings.Split(string(data), "\n") {
			if !strings.HasPrefix(line, "cpu ") {
				continue
			}
			f := strings.Fields(line)
			for i, s := range f[1:] {
				v, err := strconv.ParseUint(s, 10, 64)
				if err != nil {
					continue
				}
				total += v
				if i == 3 || i == 4 { // idle + iowait
					idle += v
				}
			}
			return idle, total
		}
		return 0, 0
	}
	idle1, total1 := read()
	if total1 == 0 {
		return 0
	}
	time.Sleep(200 * time.Millisecond)
	idle2, total2 := read()
	if total2 <= total1 {
		return 0
	}
	dIdle := float64(idle2 - idle1)
	dTotal := float64(total2 - total1)
	if dTotal == 0 {
		return 0
	}
	return (1 - dIdle/dTotal) * 100
}

func diskUsage(path string) (used, total uint64) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, 0
	}
	total = st.Blocks * uint64(st.Bsize)
	free := st.Bfree * uint64(st.Bsize)
	if total >= free {
		used = total - free
	}
	return used, total
}

// Status builds the heartbeat payload. It is cheap: /proc reads only,
// no Xray restart, no subprocess per call (the stats exec is cached
// at most once per 5 s in refreshStats).
func (a *Agent) Status() statusSnapshot {
	a.refreshStats()
	memTotal, memAvail, swapTotal, swapFree := readMeminfo()
	var memUsed uint64
	if memTotal >= memAvail {
		memUsed = memTotal - memAvail
	}
	diskUsed, diskTotal := diskUsage(a.statePath)
	xrayState, xrayErr, xrayVer := a.XrayState()
	// NetIO is the sum of all clients' reported traffic (v2).
	var netUp, netDown uint64
	a.mu.Lock()
	for _, ib := range a.state.Inbounds {
		for _, cs := range a.clientStatsFor(ib) {
			netUp += uint64(cs.Up)
			netDown += uint64(cs.Down)
		}
	}
	a.mu.Unlock()
	upd := a.getUpdateStatus()
	return statusSnapshot{
		CPU:                 readCPUPercent(),
		CPUCores:            1,
		Mem:                 memInfo{Current: memUsed, Total: memTotal},
		Swap:                memInfo{Current: swapTotal - swapFree, Total: swapTotal},
		Disk:                memInfo{Current: diskUsed, Total: diskTotal},
		Xray:                xrayInfo{State: xrayState, ErrorMsg: xrayErr, Version: xrayVer},
		PanelVersion:        Version,
		PanelGuid:           a.PanelGuid(),
		Uptime:              uint64(time.Since(a.startedAt).Seconds()),
		Loads:               readLoadAvg(),
		NetIO:               netIO{Up: netUp, Down: netDown},
		UpdateAvailable:     upd.Available,
		LatestVersion:       upd.Latest,
		AutoUpdate:          a.autoUpdateEnabled(),
		CoreUpdateAvailable: upd.CoreAvailable,
		LatestCoreVersion:   upd.CoreLatest,
	}
}
