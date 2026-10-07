package scanner

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"strings"
	"sync"
	"time"
)

// NameResolutionResult contains discovered names for a host
type NameResolutionResult struct {
	PrimaryName string
	ReverseDNS  string
	NetBIOS     string
	MDNS        string
}

// ResolveNames queries DNS, NetBIOS (port 137), and mDNS for hostnames
func ResolveNames(ctx context.Context, ip string, timeout time.Duration) NameResolutionResult {
	if timeout <= 0 {
		timeout = 400 * time.Millisecond
	}

	var (
		mu         sync.Mutex
		reverseDNS string
		mdnsName   string
		netbios    string
	)

	var wg sync.WaitGroup
	lookupCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// 1. Reverse DNS
	wg.Add(1)
	go func() {
		defer wg.Done()
		resolver := &net.Resolver{
			PreferGo: false, // On macOS, use C library/mDNSResponder for .local support
		}
		names, err := resolver.LookupAddr(lookupCtx, ip)
		if err == nil && len(names) > 0 {
			clean := strings.TrimSuffix(names[0], ".")
			mu.Lock()
			reverseDNS = clean
			if strings.HasSuffix(clean, ".local") {
				mdnsName = strings.TrimSuffix(clean, ".local")
			}
			mu.Unlock()
		}
	}()

	// 2. NetBIOS Node Status Query (UDP 137)
	wg.Add(1)
	go func() {
		defer wg.Done()
		nbName := queryNetBIOS(ip, timeout)
		if nbName != "" {
			mu.Lock()
			netbios = nbName
			mu.Unlock()
		}
	}()

	// Wait for both or context timeout
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-lookupCtx.Done():
	}

	mu.Lock()
	defer mu.Unlock()

	result := NameResolutionResult{
		ReverseDNS: reverseDNS,
		MDNS:        mdnsName,
		NetBIOS:     netbios,
	}

	// Select best primary name
	if result.NetBIOS != "" {
		result.PrimaryName = result.NetBIOS
	} else if result.MDNS != "" {
		result.PrimaryName = result.MDNS
	} else if result.ReverseDNS != "" {
		result.PrimaryName = result.ReverseDNS
	}

	return result
}

// queryNetBIOS sends a NetBIOS Node Status request (NBSTAT) to target IP port 137 UDP
func queryNetBIOS(ip string, timeout time.Duration) string {
	conn, err := net.DialTimeout("udp", net.JoinHostPort(ip, "137"), timeout)
	if err != nil {
		return ""
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	// NetBIOS Node Status request packet
	// Transaction ID: 0x8014, Flags: 0x0000 (Query), Questions: 1
	var buf bytes.Buffer
	// Header
	buf.Write([]byte{0x80, 0x14, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	// Question Name: 0x20 + 32-byte representation of '*' (CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA) + 0x00
	buf.WriteByte(0x20)
	buf.WriteString("CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	buf.WriteByte(0x00)
	// Type: NBSTAT (0x0021), Class: IN (0x0001)
	buf.Write([]byte{0x00, 0x21, 0x00, 0x01})

	if _, err := conn.Write(buf.Bytes()); err != nil {
		return ""
	}

	reply := make([]byte, 1024)
	n, err := conn.Read(reply)
	if err != nil || n < 57 {
		return ""
	}

	// The reply contains the answers.
	// Offset 56 is typically the number of names (1 byte).
	numNames := int(reply[56])
	if numNames <= 0 || 57+numNames*18 > n {
		return ""
	}

	var computerName string
	var serverName string

	for i := 0; i < numNames; i++ {
		offset := 57 + (i * 18)
		nameBytes := reply[offset : offset+15]
		nameType := reply[offset+15]
		flags := binary.BigEndian.Uint16(reply[offset+16 : offset+18])

		isGroup := (flags & 0x8000) != 0
		rawName := strings.TrimSpace(string(nameBytes))

		// nameType 0x00 is Workstation / Computer name
		if !isGroup && nameType == 0x00 && computerName == "" {
			computerName = cleanNetBIOSString(rawName)
		}
		// nameType 0x20 is File Server Service
		if !isGroup && nameType == 0x20 && serverName == "" {
			serverName = cleanNetBIOSString(rawName)
		}
	}

	if computerName != "" {
		return computerName
	}
	return serverName
}

func cleanNetBIOSString(s string) string {
	var sb strings.Builder
	for _, r := range s {
		if r >= 32 && r <= 126 {
			sb.WriteRune(r)
		}
	}
	return strings.TrimSpace(sb.String())
}
