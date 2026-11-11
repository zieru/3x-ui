package agent

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// envelope is the panel response format every node endpoint returns.
// The master requires HTTP 200 + success:true; success:false with
// HTTP 200 is a remoteAPIError ("remote: <msg>").
type envelope struct {
	Success bool   `json:"success"`
	Msg     string `json:"msg"`
	Obj     any    `json:"obj"`
}

func writeEnvelope(w http.ResponseWriter, success bool, msg string, obj any) {
	w.Header().Set("Content-Type", "application/json")
	// Never advertise zstd: the agent does not implement zstd
	// decompression in v1, so the master must always send plain bodies.
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(envelope{Success: success, Msg: msg, Obj: obj})
}

func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(envelope{Success: false, Msg: msg, Obj: nil})
}

// Server is the agent's HTTP server. It serves only the node-sync API
// under {basePath}panel/api/ — no web UI, no login page, no subscription.
type Server struct {
	agent    *Agent
	basePath string // e.g. "/" (default) — stripped before routing
}

func NewServer(a *Agent, basePath string) *Server {
	if basePath == "" {
		basePath = "/"
	}
	if !strings.HasSuffix(basePath, "/") {
		basePath += "/"
	}
	return &Server{agent: a, basePath: basePath}
}

// ServeHTTP strips the base path, authenticates, verifies the
// X-Config-Sha256 body hash when present, and dispatches.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	if s.basePath != "/" {
		if !strings.HasPrefix(path, strings.TrimSuffix(s.basePath, "/")) {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		path = "/" + strings.TrimPrefix(path, strings.TrimSuffix(s.basePath, "/"))
	}
	if !strings.HasPrefix(path, "/panel/api/") {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	// Auth: Bearer node-sync token, constant-time compare. Missing or
	// wrong token -> 401, mirroring upstream checkAPIAuth.
	if !s.agent.checkToken(r.Header.Get("Authorization")) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	// zstd is never advertised, so a zstd body is a protocol error.
	if r.Header.Get("Content-Encoding") == "zstd" {
		writeError(w, http.StatusBadRequest, "zstd not supported by this agent")
		return
	}
	var body []byte
	if r.ContentLength != 0 {
		var err error
		body, err = io.ReadAll(io.LimitReader(r.Body, 64<<20))
		if err != nil {
			writeError(w, http.StatusBadRequest, "read body: "+err.Error())
			return
		}
	}
	// X-Config-Sha256: master sends the SHA-256 of the uncompressed
	// body on every call that has one. Verify when present.
	if len(body) > 0 {
		if want := r.Header.Get("X-Config-Sha256"); want != "" {
			if subtle.ConstantTimeCompare([]byte(sha256Hex(body)), []byte(strings.ToLower(want))) != 1 {
				writeError(w, http.StatusBadRequest, "X-Config-Sha256 mismatch")
				return
			}
		}
	}
	s.dispatch(w, r, strings.TrimPrefix(path, "/panel/api/"), body)
}

func (s *Server) dispatch(w http.ResponseWriter, r *http.Request, path string, body []byte) {
	// Split path into segments for /inbounds/update/:id style routes.
	seg := strings.Split(strings.Trim(path, "/"), "/")
	method := r.Method

	switch {
	// --- heartbeat / status (MUST) ---
	case method == "GET" && path == "server/status":
		writeEnvelope(w, true, "", s.agent.Status())
		return
	case method == "POST" && path == "server/restartXrayService":
		if err := s.agent.Apply(); err != nil {
			writeEnvelope(w, false, err.Error(), nil)
			return
		}
		writeEnvelope(w, true, "", nil)
		return
	case method == "POST" && path == "server/updatePanel":
		// Never expose self-update. The agent must never hold a
		// node-admin token.
		writeEnvelope(w, false, "updatePanel not supported by this agent", nil)
		return
	case method == "GET" && path == "server/getWebCertFiles":
		writeError(w, http.StatusNotFound, "not implemented")
		return
	case method == "GET" && path == "server/descendants":
		writeEnvelope(w, true, "", []any{})
		return
	case method == "GET" && path == "server/clientIps":
		writeEnvelope(w, true, "", []any{})
		return
	case method == "POST" && path == "server/clientIps":
		writeEnvelope(w, true, "", nil)
		return

	// --- inbounds (MUST) ---
	case method == "GET" && path == "inbounds/list":
		writeEnvelope(w, true, "", s.agent.listInbounds())
		return
	case method == "POST" && path == "inbounds/add":
		s.addInbound(w, body)
		return
	case method == "POST" && len(seg) == 3 && seg[0] == "inbounds" && seg[1] == "update":
		s.updateInbound(w, seg[2], body)
		return
	case method == "POST" && len(seg) == 3 && seg[0] == "inbounds" && seg[1] == "del":
		s.delInbound(w, seg[2])
		return
	case method == "POST" && len(seg) == 3 && seg[0] == "inbounds" && seg[2] == "subSortIndex":
		s.setSubSortIndex(w, seg[1], body)
		return
	case method == "POST" && len(seg) == 3 && seg[0] == "inbounds" && seg[2] == "resetTraffic":
		s.resetInboundTraffic(w, seg[1])
		return
	case method == "POST" && path == "inbounds/resetAllTraffics":
		s.agent.resetAllCounters()
		writeEnvelope(w, true, "", nil)
		return
	case method == "POST" && path == "inbounds/pushClientTraffics":
		// Master pushes its aggregated counters to the node; v1
		// accepts and ignores them (never folds them into the
		// counters it reports back).
		writeEnvelope(w, true, "", nil)
		return

	// --- clients (MUST) ---
	case method == "POST" && path == "clients/add":
		s.addClient(w, body)
		return
	case method == "POST" && len(seg) == 3 && seg[0] == "clients" && seg[2] == "detach":
		s.detachClient(w, seg[1], body)
		return
	case method == "POST" && len(seg) == 3 && seg[0] == "clients" && seg[1] == "del":
		s.delClient(w, seg[2])
		return
	case method == "POST" && len(seg) == 3 && seg[0] == "clients" && seg[1] == "update":
		s.updateClient(w, seg[2], r, body)
		return
	case method == "POST" && len(seg) == 3 && seg[0] == "clients" && seg[1] == "resetTraffic":
		s.agent.resetAllCounters()
		writeEnvelope(w, true, "", nil)
		return
	case method == "POST" && path == "clients/bulkResetTraffic":
		s.agent.resetAllCounters()
		writeEnvelope(w, true, "", nil)
		return
	case method == "POST" && path == "clients/onlines":
		writeEnvelope(w, true, "", []any{})
		return
	case method == "POST" && path == "clients/onlinesByGuid":
		writeEnvelope(w, true, "", map[string]any{})
		return
	case method == "POST" && path == "clients/lastOnline":
		writeEnvelope(w, true, "", map[string]any{})
		return
	case method == "POST" && path == "clients/activeInbounds":
		writeEnvelope(w, true, "", map[string]any{})
		return
	case method == "POST" && path == "clients/clientIpsByGuid":
		writeEnvelope(w, true, "", map[string]any{})
		return

	// --- hosts (SKIP) ---
	case method == "GET" && path == "hosts/list":
		writeEnvelope(w, true, "", []any{})
		return
	}
	writeError(w, http.StatusNotFound, "not found: "+path)
}

// --- inbound store helpers (state lock held by caller where noted) ---

func (a *Agent) listInbounds() []Inbound {
	a.refreshStats() // v2: fold live Xray counters into the offsets
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]Inbound, 0, len(a.state.Inbounds))
	for _, ib := range a.state.Inbounds {
		ib.ClientStats = a.clientStatsFor(ib)
		// Inbound totals are the sum of its clients (Xray only
		// exposes per-user counters, not per-inbound ones).
		var up, down int64
		for _, cs := range ib.ClientStats {
			up += cs.Up
			down += cs.Down
		}
		ib.Up, ib.Down = up, down
		out = append(out, ib)
	}
	return out
}

func (a *Agent) findByTagLocked(tag string) *Inbound {
	for i := range a.state.Inbounds {
		if a.state.Inbounds[i].Tag == tag {
			return &a.state.Inbounds[i]
		}
	}
	return nil
}

func (a *Agent) findByIDLocked(id int) *Inbound {
	for i := range a.state.Inbounds {
		if a.state.Inbounds[i].ID == id {
			return &a.state.Inbounds[i]
		}
	}
	return nil
}

func (a *Agent) resetAllCounters() {
	a.refreshStats()
	a.mu.Lock()
	defer a.mu.Unlock()
	for i := range a.state.Inbounds {
		a.zeroTrafficLocked(clientEmails(a.state.Inbounds[i]))
		a.state.Inbounds[i].Up = 0
		a.state.Inbounds[i].Down = 0
	}
	_ = a.saveStateLocked()
}

// parseWireInbound parses a wireInbound() form body into an Inbound.
// Field names mirror remote.go wireInbound(); settings/streamSettings/
// sniffing are JSON strings inside form values.
func parseWireInbound(body []byte) (Inbound, error) {
	vals, err := url.ParseQuery(string(body))
	if err != nil {
		return Inbound{}, fmt.Errorf("parse form: %w", err)
	}
	ib := Inbound{
		Total:             parseInt64(vals.Get("total"), 0),
		Remark:            vals.Get("remark"),
		SubSortIndex:      parseInt(vals.Get("subSortIndex"), 1),
		ExcludeFromSub:    parseBool(vals.Get("excludeFromSub")),
		Enable:            parseBool(vals.Get("enable")),
		ExpiryTime:        parseInt64(vals.Get("expiryTime"), 0),
		Listen:            vals.Get("listen"),
		Port:              parseInt(vals.Get("port"), 0),
		Protocol:          vals.Get("protocol"),
		Settings:          vals.Get("settings"),
		StreamSettings:    vals.Get("streamSettings"),
		Tag:               vals.Get("tag"),
		Sniffing:          vals.Get("sniffing"),
		ShareAddrStrategy: vals.Get("shareAddrStrategy"),
		ShareAddr:         vals.Get("shareAddr"),
		DisableFlow:       parseBool(vals.Get("disableFlow")),
		TrafficReset:      vals.Get("trafficReset"),
		TrafficResetDay:   parseInt(vals.Get("trafficResetDay"), 0),
	}
	if ib.Tag == "" {
		return Inbound{}, fmt.Errorf("tag is required")
	}
	if ib.Port < 0 || ib.Port > 65535 {
		return Inbound{}, fmt.Errorf("port out of range")
	}
	if ib.Protocol == "" {
		return Inbound{}, fmt.Errorf("protocol is required")
	}
	return ib, nil
}

// mutateInbound applies fn to the state, persists it, and applies the
// Xray config. On Xray test failure the state change is kept (so the
// next push can fix it) but the error is returned and the old Xray
// process keeps running with the last good config.
func (s *Server) mutateInbound(fn func() error) error {
	s.agent.mu.Lock()
	if err := fn(); err != nil {
		s.agent.mu.Unlock()
		return err
	}
	if err := s.agent.saveStateLocked(); err != nil {
		s.agent.mu.Unlock()
		return err
	}
	s.agent.mu.Unlock()
	return s.agent.Apply()
}

func (s *Server) addInbound(w http.ResponseWriter, body []byte) {
	ib, err := parseWireInbound(body)
	if err != nil {
		writeEnvelope(w, false, err.Error(), nil)
		return
	}
	var createdID int
	var createdTag string
	err = s.mutateInbound(func() error {
		// Idempotent: a re-push of the same tag updates in place
		// instead of duplicating the inbound.
		if existing := s.agent.findByTagLocked(ib.Tag); existing != nil {
			ib.ID = existing.ID
			*existing = ib
			createdID, createdTag = ib.ID, ib.Tag
			return nil
		}
		ib.ID = s.agent.state.NextID
		s.agent.state.NextID++
		s.agent.state.Inbounds = append(s.agent.state.Inbounds, ib)
		createdID, createdTag = ib.ID, ib.Tag
		return nil
	})
	if err != nil {
		writeEnvelope(w, false, err.Error(), nil)
		return
	}
	writeEnvelope(w, true, "", map[string]any{"id": createdID, "tag": createdTag})
}

func (s *Server) updateInbound(w http.ResponseWriter, idStr string, body []byte) {
	id, err := strconv.Atoi(idStr)
	if err != nil {
		writeEnvelope(w, false, "invalid id", nil)
		return
	}
	ib, err := parseWireInbound(body)
	if err != nil {
		writeEnvelope(w, false, err.Error(), nil)
		return
	}
	found := false
	err = s.mutateInbound(func() error {
		existing := s.agent.findByIDLocked(id)
		if existing == nil {
			return fmt.Errorf("not found")
		}
		ib.ID = id
		*existing = ib
		found = true
		return nil
	})
	if !found || err != nil {
		// Master falls back to AddInbound when the tag is not found.
		writeEnvelope(w, false, "not found", nil)
		return
	}
	writeEnvelope(w, true, "", nil)
}

func (s *Server) delInbound(w http.ResponseWriter, idStr string) {
	id, err := strconv.Atoi(idStr)
	if err != nil {
		writeEnvelope(w, false, "invalid id", nil)
		return
	}
	err = s.mutateInbound(func() error {
		for i := range s.agent.state.Inbounds {
			if s.agent.state.Inbounds[i].ID == id {
				s.agent.state.Inbounds = append(s.agent.state.Inbounds[:i], s.agent.state.Inbounds[i+1:]...)
				return nil
			}
		}
		return nil // idempotent delete
	})
	if err != nil {
		writeEnvelope(w, false, err.Error(), nil)
		return
	}
	writeEnvelope(w, true, "", nil)
}

func (s *Server) setSubSortIndex(w http.ResponseWriter, idStr string, body []byte) {
	id, err := strconv.Atoi(idStr)
	if err != nil {
		writeEnvelope(w, false, "invalid id", nil)
		return
	}
	vals, _ := url.ParseQuery(string(body))
	idx := parseInt(vals.Get("subSortIndex"), 1)
	err = s.mutateInbound(func() error {
		if ib := s.agent.findByIDLocked(id); ib != nil {
			ib.SubSortIndex = idx
		}
		return nil
	})
	if err != nil {
		writeEnvelope(w, false, err.Error(), nil)
		return
	}
	writeEnvelope(w, true, "", nil)
}

func (s *Server) resetInboundTraffic(w http.ResponseWriter, idStr string) {
	id, err := strconv.Atoi(idStr)
	if err != nil {
		writeEnvelope(w, false, "invalid id", nil)
		return
	}
	s.agent.refreshStats()
	s.agent.mu.Lock()
	if ib := s.agent.findByIDLocked(id); ib != nil {
		s.agent.zeroTrafficLocked(clientEmails(*ib))
		ib.Up, ib.Down = 0, 0
	}
	_ = s.agent.saveStateLocked()
	s.agent.mu.Unlock()
	writeEnvelope(w, true, "", nil)
}

// --- client ops: all implemented as "edit the stored inbound's
// client list, then regenerate config + restart Xray", reusing the
// same code path as inbound pushes. ---

func (s *Server) addClient(w http.ResponseWriter, body []byte) {
	var payload struct {
		Client     map[string]any `json:"client"`
		InboundIDs []int          `json:"inboundIds"`
	}
	if err := json.Unmarshal(body, &payload); err != nil || payload.Client == nil {
		writeEnvelope(w, false, "invalid client payload", nil)
		return
	}
	email := clientEmail(payload.Client)
	if email == "" {
		writeEnvelope(w, false, "client email is required", nil)
		return
	}
	err := s.mutateInbound(func() error {
		for _, id := range payload.InboundIDs {
			ib := s.agent.findByIDLocked(id)
			if ib == nil {
				continue
			}
			clients := settingsClients(ib.Settings)
			replaced := false
			for i, c := range clients {
				if clientEmail(c) == email {
					clients[i] = payload.Client
					replaced = true
				}
			}
			if !replaced {
				clients = append(clients, payload.Client)
			}
			ib.Settings = setSettingsClients(ib.Settings, clients)
		}
		return nil
	})
	if err != nil {
		writeEnvelope(w, false, err.Error(), nil)
		return
	}
	writeEnvelope(w, true, "", nil)
}

func (s *Server) detachClient(w http.ResponseWriter, email string, body []byte) {
	email, _ = url.PathUnescape(email)
	var payload struct {
		InboundIDs []int `json:"inboundIds"`
	}
	_ = json.Unmarshal(body, &payload)
	found := false
	err := s.mutateInbound(func() error {
		ids := payload.InboundIDs
		for i := range s.agent.state.Inbounds {
			ib := &s.agent.state.Inbounds[i]
			if len(ids) > 0 {
				hit := false
				for _, id := range ids {
					if id == ib.ID {
						hit = true
					}
				}
				if !hit {
					continue
				}
			}
			clients := settingsClients(ib.Settings)
			kept := clients[:0]
			for _, c := range clients {
				if clientEmail(c) == email {
					found = true
					continue
				}
				kept = append(kept, c)
			}
			ib.Settings = setSettingsClients(ib.Settings, kept)
		}
		return nil
	})
	if err != nil {
		writeEnvelope(w, false, err.Error(), nil)
		return
	}
	if !found {
		// Master treats "not found" in msg as success for detach.
		writeEnvelope(w, false, "not found", nil)
		return
	}
	writeEnvelope(w, true, "", nil)
}

func (s *Server) delClient(w http.ResponseWriter, email string) {
	email, _ = url.PathUnescape(email)
	found := false
	err := s.mutateInbound(func() error {
		for i := range s.agent.state.Inbounds {
			ib := &s.agent.state.Inbounds[i]
			clients := settingsClients(ib.Settings)
			kept := clients[:0]
			for _, c := range clients {
				if clientEmail(c) == email {
					found = true
					continue
				}
				kept = append(kept, c)
			}
			ib.Settings = setSettingsClients(ib.Settings, kept)
		}
		return nil
	})
	if err != nil {
		writeEnvelope(w, false, err.Error(), nil)
		return
	}
	if !found {
		writeEnvelope(w, false, "not found", nil)
		return
	}
	writeEnvelope(w, true, "", nil)
}

func (s *Server) updateClient(w http.ResponseWriter, email string, r *http.Request, body []byte) {
	email, _ = url.PathUnescape(email)
	var client map[string]any
	if err := json.Unmarshal(body, &client); err != nil || client == nil {
		writeEnvelope(w, false, "invalid client payload", nil)
		return
	}
	inboundIDs := r.URL.Query()["inboundIds"]
	var ids []int
	for _, s := range inboundIDs {
		if n, err := strconv.Atoi(s); err == nil {
			ids = append(ids, n)
		}
	}
	found := false
	err := s.mutateInbound(func() error {
		for i := range s.agent.state.Inbounds {
			ib := &s.agent.state.Inbounds[i]
			if len(ids) > 0 {
				hit := false
				for _, id := range ids {
					if id == ib.ID {
						hit = true
					}
				}
				if !hit {
					continue
				}
			}
			clients := settingsClients(ib.Settings)
			for j, c := range clients {
				if clientEmail(c) == email {
					clients[j] = client
					found = true
				}
			}
			ib.Settings = setSettingsClients(ib.Settings, clients)
		}
		return nil
	})
	if err != nil {
		writeEnvelope(w, false, err.Error(), nil)
		return
	}
	if !found {
		writeEnvelope(w, false, "not found", nil)
		return
	}
	writeEnvelope(w, true, "", nil)
}
