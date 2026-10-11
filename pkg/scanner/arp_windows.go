//go:build windows

package scanner

import (
	"encoding/binary"
	"fmt"
	"net"
	"syscall"
	"unsafe"
)

var (
	modiphlpapi = syscall.NewLazyDLL("iphlpapi.dll")
	procSendARP = modiphlpapi.NewProc("SendARP")
)

// queryARPSingle uses the Win32 SendARP API to instantly resolve MAC for a target IP
func queryARPSingle(ip string) (string, error) {
	parsed := net.ParseIP(ip).To4()
	if parsed == nil {
		return "", fmt.Errorf("invalid IPv4 address: %s", ip)
	}

	// SendARP takes IPv4 in network byte order
	ipInt := binary.LittleEndian.Uint32(parsed)
	var mac [8]byte
	macLen := uint32(6)

	r1, _, err := procSendARP.Call(
		uintptr(ipInt),
		0,
		uintptr(unsafe.Pointer(&mac[0])),
		uintptr(unsafe.Pointer(&macLen)),
	)

	if r1 != 0 {
		return "", fmt.Errorf("SendARP returned %d: %w", r1, err)
	}

	macStr := fmt.Sprintf("%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
	return macStr, nil
}
