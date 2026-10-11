//go:build !windows

package scanner

import (
	"fmt"
)

// queryARPSingle fallback for non-Windows systems
func queryARPSingle(ip string) (string, error) {
	return "", fmt.Errorf("native direct ARP query is only supported on Windows")
}
