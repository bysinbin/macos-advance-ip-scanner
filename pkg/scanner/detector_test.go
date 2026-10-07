package scanner

import (
	"net"
	"testing"
)

func TestParseIPRangeCIDR(t *testing.T) {
	ips, err := ParseIPRange("192.168.1.0/29")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// /29 has 6 usable hosts (1 to 6)
	if len(ips) != 6 {
		t.Fatalf("expected 6 IPs, got %d", len(ips))
	}
	if ips[0] != "192.168.1.1" || ips[5] != "192.168.1.6" {
		t.Errorf("unexpected IP range: %v", ips)
	}
}

func TestParseIPRangeHyphen(t *testing.T) {
	tests := []struct {
		input       string
		expectedLen int
		first       string
		last        string
	}{
		{"192.168.1.10-192.168.1.20", 11, "192.168.1.10", "192.168.1.20"},
		{"192.168.1.5-10", 6, "192.168.1.5", "192.168.1.10"},
		{"10.0.0.1", 1, "10.0.0.1", "10.0.0.1"},
	}

	for _, tt := range tests {
		ips, err := ParseIPRange(tt.input)
		if err != nil {
			t.Fatalf("ParseIPRange(%q) failed: %v", tt.input, err)
		}
		if len(ips) != tt.expectedLen {
			t.Errorf("ParseIPRange(%q) length = %d, expected %d", tt.input, len(ips), tt.expectedLen)
		}
		if ips[0] != tt.first || ips[len(ips)-1] != tt.last {
			t.Errorf("ParseIPRange(%q) bounds = (%s, %s), expected (%s, %s)", tt.input, ips[0], ips[len(ips)-1], tt.first, tt.last)
		}
	}
}

func TestParseIPRangeErrors(t *testing.T) {
	invalidInputs := []string{
		"",
		"invalid-ip",
		"192.168.1.50-192.168.1.10", // start > end
		"192.168.1.300",             // out of bounds
		"192.168.1.0/15",            // too large (> 65536)
	}

	for _, input := range invalidInputs {
		_, err := ParseIPRange(input)
		if err == nil {
			t.Errorf("expected error for input %q, got nil", input)
		}
	}
}

func TestCalculateSubnetRange(t *testing.T) {
	ip := net.ParseIP("192.168.1.100").To4()
	mask := net.CIDRMask(24, 32)

	start, end := calculateSubnetRange(ip, mask)
	if start != "192.168.1.1" {
		t.Errorf("expected start 192.168.1.1, got %s", start)
	}
	if end != "192.168.1.254" {
		t.Errorf("expected end 192.168.1.254, got %s", end)
	}
}
