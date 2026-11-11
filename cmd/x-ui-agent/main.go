// Command x-ui-agent is the mini node agent for 3x-ui.
//
// It is a drop-in Node for a master 3x-ui panel, without running the
// full panel. See docs/node-agent.md for pairing and operations.
//
// Build (from the fork root):
//
//	go build -trimpath -ldflags "-s -w" -o x-ui-agent ./cmd/x-ui-agent
//
// Run:
//
//	x-ui-agent -listen :2053 -state-dir /etc/x-ui-agent \
//	  -xray-bin /usr/local/x-ui-agent/bin/xray-linux-amd64
//
// The node-sync token is read from <state-dir>/token (0600). If the
// file does not exist, a random token is generated once and printed
// to stdout — copy it to the master panel as the node's API token.
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"syscall"
	"time"

	"github.com/mhsanaei/3x-ui/v3/internal/agent"
)

func main() {
	listen := flag.String("listen", ":2053", "listen address, e.g. :2053 or 127.0.0.1:2053")
	stateDir := flag.String("state-dir", "/etc/x-ui-agent", "state directory (state.json, config.json, token)")
	tokenFile := flag.String("token-file", "", "node-sync token file (default <state-dir>/token)")
	xrayBin := flag.String("xray-bin", "/usr/local/x-ui-agent/bin/xray-linux-amd64", "xray-core binary path (empty = no xray)")
	basePath := flag.String("base-path", "/", "panel base path, e.g. /")
	flag.Parse()

	// Memory knobs for a 93 MB box. Defaults are deliberately low;
	// override with GOGC / GOMEMLIMIT env in the OpenRC service if
	// the agent GC-thrashes or the box has more RAM.
	debug.SetGCPercent(50)
	debug.SetMemoryLimit(32 << 20)
	if v := os.Getenv("GOGC"); v != "" {
		// GOGC is honoured by the runtime automatically; the
		// SetGCPercent(50) above is the default when unset.
		_ = v
	}

	if *tokenFile == "" {
		*tokenFile = filepath.Join(*stateDir, "token")
	}
	ag, err := agent.New(*stateDir, *tokenFile, *xrayBin)
	if err != nil {
		log.Fatalf("agent init: %v", err)
	}
	// If a token was just generated, print it once so the operator
	// can pair the node on the master. Never log a pre-existing token.
	if ag.TokenGenerated() {
		fmt.Printf("node token (save it as the node API token on the master): %s\n", ag.Token())
	}

	// Start Xray from the stored inbounds (if any). A missing xray
	// binary is not fatal: the agent still serves the API with
	// xray.state "stop".
	if err := ag.Apply(); err != nil {
		log.Printf("xray start: %v (agent still serving API)", err)
	}

	srv := &http.Server{
		Addr:         *listen,
		Handler:      agent.NewServer(ag, *basePath),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatalf("listen %s: %v", *listen, err)
	}
	// Clean shutdown: stop the xray child on SIGTERM/SIGINT so the
	// agent does not orphan it (an orphan would keep the inbound
	// ports and split traffic with the next agent instance).
	go func() {
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, syscall.SIGTERM, syscall.SIGINT)
		<-ch
		log.Print("shutting down, stopping xray")
		ag.Shutdown()
		os.Exit(0)
	}()
	// Report the actual bound address: Go's "tcp" listener on ":2053"
	// is dual-stack ([::]:2053) on Linux, so 127.0.0.1 clients work
	// too — verify this in tests, it is the IPv6-only trap the full
	// panel hit on sgnat.
	log.Printf("x-ui-agent %s listening on %s (panelGuid %s)", agent.Version, ln.Addr(), ag.PanelGuid())
	log.Fatal(srv.Serve(ln))
}
