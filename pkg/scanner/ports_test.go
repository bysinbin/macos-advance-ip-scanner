package scanner

import (
	"reflect"
	"testing"
)

func TestParseCustomPorts(t *testing.T) {
	tests := []struct {
		input    string
		expected []int
		wantErr  bool
	}{
		{"80,443,22", []int{22, 80, 443}, false},
		{"8000-8003", []int{8000, 8001, 8002, 8003}, false},
		{"80, 8080-8082, 443", []int{80, 443, 8080, 8081, 8082}, false},
		{"80,80", []int{80}, false}, // Deduplication
		{"", nil, false},
		{"invalid", nil, true},
		{"70000", nil, true},       // Out of range > 65535
		{"8080-8070", nil, true},   // Start > End
	}

	for _, tt := range tests {
		got, err := ParseCustomPorts(tt.input)
		if (err != nil) != tt.wantErr {
			t.Errorf("ParseCustomPorts(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			continue
		}
		if !tt.wantErr && !reflect.DeepEqual(got, tt.expected) {
			t.Errorf("ParseCustomPorts(%q) = %v, expected %v", tt.input, got, tt.expected)
		}
	}
}

func TestClassifyDevice(t *testing.T) {
	// Test Gateway
	gwHost := &Host{IsGateway: true}
	if ClassifyDevice(gwHost) != DeviceRouter {
		t.Errorf("expected DeviceRouter for gateway, got %v", ClassifyDevice(gwHost))
	}

	// Test Printer
	printerHost := &Host{
		Vendor:    "Canon, Inc.",
		OpenPorts: []PortInfo{{Port: 9100, IsOpen: true}},
	}
	if ClassifyDevice(printerHost) != DevicePrinter {
		t.Errorf("expected DevicePrinter, got %v", ClassifyDevice(printerHost))
	}

	// Test Apple Computer vs Mobile
	macHost := &Host{
		Vendor:   "Apple, Inc.",
		Hostname: "MacBook-Pro.local",
	}
	if ClassifyDevice(macHost) != DeviceComputer {
		t.Errorf("expected DeviceComputer for Mac, got %v", ClassifyDevice(macHost))
	}

	iphoneHost := &Host{
		Vendor:   "Apple, Inc.",
		Hostname: "Ferit-iPhone.local",
	}
	if ClassifyDevice(iphoneHost) != DeviceMobile {
		t.Errorf("expected DeviceMobile for iPhone, got %v", ClassifyDevice(iphoneHost))
	}

	// Test IoT / Smart TV via SSDP model
	tvHost := &Host{
		Vendor: "Samsung Electronics Co.,Ltd",
		Model:  "Samsung Smart TV",
	}
	if ClassifyDevice(tvHost) != DeviceIoT {
		t.Errorf("expected DeviceIoT for Smart TV, got %v", ClassifyDevice(tvHost))
	}

	// Test Server / NAS
	nasHost := &Host{
		Vendor:    "Synology Incorporated",
		OpenPorts: []PortInfo{{Port: 5000, IsOpen: true}},
	}
	if ClassifyDevice(nasHost) != DeviceServer {
		t.Errorf("expected DeviceServer for Synology NAS, got %v", ClassifyDevice(nasHost))
	}
}
