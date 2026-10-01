package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"macos-advance-ip-scanner/pkg/scanner"
)

type scanStartRequest struct {
	IPRange      string `json:"ipRange"`
	TimeoutMs    int    `json:"timeoutMs"`
	Concurrency  int    `json:"concurrency"`
	ScanPorts    bool   `json:"scanPorts"`
	DeepScan     bool   `json:"deepScan"`
	ExtraPorts   string `json:"extraPorts"`
	ResolveNames bool   `json:"resolveNames"`
}

type wolRequest struct {
	MAC         string `json:"mac"`
	BroadcastIP string `json:"broadcastIp"`
}

type pingRequest struct {
	IP string `json:"ip"`
}

type portScanRequest struct {
	IP         string `json:"ip"`
	Ports      string `json:"ports"` // e.g. "80,443,8080-8090"
	TimeoutMs  int    `json:"timeoutMs"`
}

func (s *Server) handleInterfaces(w http.ResponseWriter, r *http.Request) {
	ifaces, err := scanner.DetectInterfaces()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(ifaces)
}

func (s *Server) handleScanStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req scanStartRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON payload: "+err.Error(), http.StatusBadRequest)
		return
	}

	if req.IPRange == "" {
		http.Error(w, "ipRange is required", http.StatusBadRequest)
		return
	}

	timeout := time.Duration(req.TimeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = 350 * time.Millisecond
	}

	concurrency := req.Concurrency
	if concurrency <= 0 {
		concurrency = 40
	}

	var extraPorts []int
	if req.ExtraPorts != "" {
		parsed, err := scanner.ParseCustomPorts(req.ExtraPorts)
		if err == nil {
			extraPorts = parsed
		}
	}

	opts := scanner.ScanOptions{
		IPRange:      req.IPRange,
		Timeout:      timeout,
		Concurrency:  concurrency,
		ScanPorts:    req.ScanPorts,
		DeepScan:     req.DeepScan,
		ExtraPorts:   extraPorts,
		ResolveNames: req.ResolveNames,
	}

	err := s.engine.Start(context.Background(), opts, func(p scanner.ScanProgress) {
		if p.Discovered != nil {
			s.BroadcastSSE("host_found", p.Discovered)
		}
		s.BroadcastSSE("progress", p)
		if p.IsFinished {
			s.BroadcastSSE("finished", p)
		}
	})

	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "Scan started",
	})
}

func (s *Server) handleScanStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.engine.Stop()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "Scan stopped",
	})
}

func (s *Server) handleScanStatus(w http.ResponseWriter, r *http.Request) {
	hosts := s.engine.GetHosts()
	isScanning := s.engine.IsScanning()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"isScanning": isScanning,
		"count":      len(hosts),
		"hosts":      hosts,
	})
}

func (s *Server) handleSSE(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	msgChan := make(chan string, 32)
	s.clientsMu.Lock()
	s.clients[msgChan] = true
	s.clientsMu.Unlock()

	defer func() {
		s.clientsMu.Lock()
		delete(s.clients, msgChan)
		close(msgChan)
		s.clientsMu.Unlock()
	}()

	// Send initial status ping
	initialStatus := map[string]interface{}{
		"isScanning": s.engine.IsScanning(),
		"hosts":      s.engine.GetHosts(),
	}
	initialBytes, _ := json.Marshal(initialStatus)
	_, _ = fmt.Fprintf(w, "event: initial_state\ndata: %s\n\n", string(initialBytes))
	flusher.Flush()

	notify := r.Context().Done()
	for {
		select {
		case <-notify:
			return
		case msg, ok := <-msgChan:
			if !ok {
				return
			}
			_, err := fmt.Fprint(w, msg)
			if err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

func (s *Server) handleWakeOnLAN(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req wolRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
		return
	}

	err := scanner.SendWakeOnLAN(req.MAC, req.BroadcastIP)
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   err.Error(),
		})
		return
	}

	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": fmt.Sprintf("Magic packet sent to %s", req.MAC),
	})
}

func (s *Server) handlePing(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req pingRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	probe := scanner.ProbeHost(ctx, req.IP, 600*time.Millisecond, nil)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"ip":        req.IP,
		"alive":     probe.Alive,
		"latencyMs": probe.LatencyMs,
		"method":    probe.Method,
	})
}

func (s *Server) handlePortScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req portScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
		return
	}

	var ports []int
	if req.Ports != "" {
		parsed, err := scanner.ParseCustomPorts(req.Ports)
		if err != nil {
			http.Error(w, "Invalid port specification: "+err.Error(), http.StatusBadRequest)
			return
		}
		ports = parsed
	} else {
		ports = scanner.DeepScanPorts
	}

	timeout := time.Duration(req.TimeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = 400 * time.Millisecond
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	results := scanner.ScanPorts(ctx, req.IP, ports, timeout, 30)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"ip":        req.IP,
		"openPorts": results,
		"total":     len(results),
	})
}

func (s *Server) handleExport(w http.ResponseWriter, r *http.Request) {
	format := strings.ToLower(r.URL.Query().Get("format"))
	if format == "" {
		format = "csv"
	}

	hosts := s.engine.GetHosts()
	timestamp := time.Now().Format("20060102-150405")

	switch format {
	case "csv":
		data, err := scanner.ExportCSV(hosts)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"scan-%s.csv\"", timestamp))
		_, _ = w.Write(data)

	case "json":
		data, err := scanner.ExportJSON(hosts)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"scan-%s.json\"", timestamp))
		_, _ = w.Write(data)

	case "txt":
		data := scanner.ExportTXT(hosts)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"scan-%s.txt\"", timestamp))
		_, _ = w.Write(data)

	default:
		http.Error(w, "Unsupported format. Use csv, json, or txt", http.StatusBadRequest)
	}
}
