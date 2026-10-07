package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"sync"
	"time"

	"macos-advance-ip-scanner/pkg/scanner"
)

// HostAlias represents a user-assigned alias and note for a device
type HostAlias struct {
	Alias string `json:"alias"`
	Notes string `json:"notes"`
}

// Server coordinates HTTP API, SSE streaming, and static files
type Server struct {
	engine     *scanner.Engine
	mux        *http.ServeMux
	clients    map[chan string]bool
	clientsMu  sync.Mutex
	staticFS   fs.FS
	httpServer *http.Server
	port       int
	aliasesMu  sync.RWMutex
	aliases    map[string]HostAlias
}

// NewServer initializes a new Server
func NewServer(port int, staticFS fs.FS) *Server {
	s := &Server{
		engine:   scanner.NewEngine(),
		mux:      http.NewServeMux(),
		clients:  make(map[chan string]bool),
		staticFS: staticFS,
		port:     port,
		aliases:  make(map[string]HostAlias),
	}

	s.loadAliases()
	s.registerRoutes()
	return s
}

// Engine returns the underlying scanning engine
func (s *Server) Engine() *scanner.Engine {
	return s.engine
}

// Start begins listening on the configured port
func (s *Server) Start() error {
	addr := fmt.Sprintf("127.0.0.1:%d", s.port)
	s.httpServer = &http.Server{
		Addr:         addr,
		Handler:      s.corsMiddleware(s.mux),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 0, // SSE streaming requires no write deadline
	}

	return s.httpServer.ListenAndServe()
}

// Shutdown gracefully stops the server
func (s *Server) Shutdown(ctx context.Context) error {
	s.engine.Stop()
	if s.httpServer != nil {
		return s.httpServer.Shutdown(ctx)
	}
	return nil
}

// BroadcastSSE sends an event to all connected web clients
func (s *Server) BroadcastSSE(eventType string, data interface{}) {
	payload, err := json.Marshal(data)
	if err != nil {
		return
	}

	msg := fmt.Sprintf("event: %s\ndata: %s\n\n", eventType, string(payload))

	s.clientsMu.Lock()
	defer s.clientsMu.Unlock()

	for ch := range s.clients {
		if eventType == "host_found" || eventType == "finished" || eventType == "alias_updated" {
			select {
			case ch <- msg:
			case <-time.After(30 * time.Millisecond):
			}
		} else {
			select {
			case ch <- msg:
			default:
				// Only drop high-frequency progress ticks if consumer is slow
			}
		}
	}
}

// registerRoutes sets up all REST and SSE endpoints
func (s *Server) registerRoutes() {
	s.mux.HandleFunc("/api/interfaces", s.handleInterfaces)
	s.mux.HandleFunc("/api/scan/start", s.handleScanStart)
	s.mux.HandleFunc("/api/scan/stop", s.handleScanStop)
	s.mux.HandleFunc("/api/scan/status", s.handleScanStatus)
	s.mux.HandleFunc("/api/hosts", s.handleScanStatus)
	s.mux.HandleFunc("/api/scan/events", s.handleSSE)
	s.mux.HandleFunc("/api/action/wol", s.handleWakeOnLAN)
	s.mux.HandleFunc("/api/action/ping", s.handlePing)
	s.mux.HandleFunc("/api/action/ports", s.handlePortScan)
	s.mux.HandleFunc("/api/export", s.handleExport)
	s.mux.HandleFunc("/api/hosts/alias", s.handleAliases)

	// Static UI file server
	if s.staticFS != nil {
		fileServer := http.FileServer(http.FS(s.staticFS))
		s.mux.Handle("/", fileServer)
	} else {
		s.mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("macOS Advanced IP Scanner API running."))
		})
	}
}

func (s *Server) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (s *Server) loadAliases() {
	s.aliasesMu.Lock()
	defer s.aliasesMu.Unlock()
	s.aliases = make(map[string]HostAlias)
	data, err := os.ReadFile("aliases.json")
	if err == nil {
		_ = json.Unmarshal(data, &s.aliases)
	}
}

func (s *Server) saveAliases() {
	s.aliasesMu.RLock()
	data, err := json.MarshalIndent(s.aliases, "", "  ")
	s.aliasesMu.RUnlock()
	if err == nil {
		_ = os.WriteFile("aliases.json", data, 0644)
	}
}

func (s *Server) enrichHostWithAlias(h *scanner.Host) {
	if h == nil {
		return
	}
	s.aliasesMu.RLock()
	defer s.aliasesMu.RUnlock()

	// Check MAC first, then IP
	if h.MAC != "" {
		if entry, ok := s.aliases[h.MAC]; ok {
			h.CustomName = entry.Alias
			h.Comments = entry.Notes
			return
		}
	}
	if entry, ok := s.aliases[h.IP]; ok {
		h.CustomName = entry.Alias
		h.Comments = entry.Notes
	}
}

