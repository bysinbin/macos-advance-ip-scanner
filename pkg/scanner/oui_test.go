package scanner

import (
	"strings"
	"testing"
)

func TestLookupVendor(t *testing.T) {
	tests := []struct {
		mac            string
		expectedVendor string
	}{
		{"00:03:93:11:22:33", "Apple, Inc."},
		{"B8:27:EB:11:22:33", "Raspberry Pi Foundation"},
		{"00:00:0C:11:22:33", "Cisco Systems"},
		{"00:1A:11:22:33:44", "Google, Inc."},
		{"XX:YY:ZZ:11:22:33", "Unknown Manufacturer"},
		{"00", "Unknown"},
	}

	for _, tt := range tests {
		got := LookupVendor(tt.mac)
		if !strings.EqualFold(got, tt.expectedVendor) {
			t.Errorf("LookupVendor(%q) = %q, expected %q", tt.mac, got, tt.expectedVendor)
		}
	}
}
