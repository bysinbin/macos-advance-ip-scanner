//go:build windows

package scanner

import (
	"testing"
)

func TestDetectDefaultRouteWindows(t *testing.T) {
	ifaceIP, gw := detectDefaultRouteWindows()
	t.Logf("Detected interface IP: %s, Gateway: %s", ifaceIP, gw)
	if ifaceIP == "" {
		t.Logf("Warning: no default route detected (might be offline)")
	}
}
