package scanner

import (
	"testing"
)

func TestNormalizeMAC(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"0:11:22:33:44:55", "00:11:22:33:44:55"},
		{"a:b:c:d:e:f", "0A:0B:0C:0D:0E:0F"},
		{"AA:BB:CC:DD:EE:FF", "AA:BB:CC:DD:EE:FF"},
		{"1:2:3:4:5:6", "01:02:03:04:05:06"},
	}

	for _, tt := range tests {
		got := NormalizeMAC(tt.input)
		if got != tt.expected {
			t.Errorf("NormalizeMAC(%q) = %q, expected %q", tt.input, got, tt.expected)
		}
	}
}

func TestARPCache(t *testing.T) {
	cache := NewARPCache()
	cache.Set("192.168.1.50", "AA:BB:CC:DD:EE:FF")

	mac, ok := cache.Get("192.168.1.50")
	if !ok || mac != "AA:BB:CC:DD:EE:FF" {
		t.Errorf("cache Get failed: got %q, %v", mac, ok)
	}

	_, ok = cache.Get("192.168.1.99")
	if ok {
		t.Errorf("expected false for missing key, got true")
	}
}
