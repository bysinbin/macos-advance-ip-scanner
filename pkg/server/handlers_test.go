package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHandleAliases(t *testing.T) {
	srv := NewServer(7799, nil)

	// Test POST /api/hosts/alias
	payload := map[string]string{
		"id":    "192.168.1.100",
		"alias": "Office Workstation",
		"notes": "Primary development desktop",
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/api/hosts/alias", bytes.NewReader(body))
	w := httptest.NewRecorder()

	srv.handleAliases(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}

	// Test GET /api/hosts/alias
	getReq := httptest.NewRequest(http.MethodGet, "/api/hosts/alias", nil)
	getW := httptest.NewRecorder()
	srv.handleAliases(getW, getReq)

	if getW.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", getW.Code)
	}

	var aliases map[string]HostAlias
	if err := json.Unmarshal(getW.Body.Bytes(), &aliases); err != nil {
		t.Fatalf("failed to decode aliases response: %v", err)
	}

	if val, ok := aliases["192.168.1.100"]; !ok || val.Alias != "Office Workstation" {
		t.Errorf("expected alias 'Office Workstation', got %+v", val)
	}
}

func TestHandleScanStatus(t *testing.T) {
	srv := NewServer(7799, nil)
	req := httptest.NewRequest(http.MethodGet, "/api/scan/status", nil)
	w := httptest.NewRecorder()

	srv.handleScanStatus(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if _, ok := resp["isScanning"]; !ok {
		t.Errorf("expected isScanning field in response")
	}
}
