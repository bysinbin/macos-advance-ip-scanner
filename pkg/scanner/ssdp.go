package scanner

import (
	"bufio"
	"context"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// SSDPDevice contains discovered UPnP/SSDP metadata
type SSDPDevice struct {
	IP       string
	Server   string
	Location string
	ST       string
	Model    string
}

// DiscoverSSDP broadcasts an SSDP M-SEARCH query and collects device responses
func DiscoverSSDP(ctx context.Context, timeout time.Duration) map[string]SSDPDevice {
	if timeout <= 0 {
		timeout = 1500 * time.Millisecond
	}

	results := make(map[string]SSDPDevice)
	var mu sync.Mutex

	// Bind UDP listener on any local ephemeral port
	laddr, err := net.ResolveUDPAddr("udp4", "0.0.0.0:0")
	if err != nil {
		return results
	}

	conn, err := net.ListenUDP("udp4", laddr)
	if err != nil {
		return results
	}
	defer conn.Close()

	multicastAddr, err := net.ResolveUDPAddr("udp4", "239.255.255.250:1900")
	if err != nil {
		return results
	}

	msg := "M-SEARCH * HTTP/1.1\r\n" +
		"HOST: 239.255.255.250:1900\r\n" +
		"MAN: \"ssdp:discover\"\r\n" +
		"MX: 1\r\n" +
		"ST: ssdp:all\r\n\r\n"

	_ = conn.SetDeadline(time.Now().Add(timeout))

	// Send multicast probe
	_, _ = conn.WriteToUDP([]byte(msg), multicastAddr)

	buf := make([]byte, 2048)
	done := make(chan struct{})

	go func() {
		defer close(done)
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			n, from, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}

			ip := from.IP.String()
			raw := string(buf[:n])

			resp, err := http.ReadResponse(bufio.NewReader(strings.NewReader(raw)), nil)
			if err != nil {
				continue
			}

			serverHdr := resp.Header.Get("Server")
			locationHdr := resp.Header.Get("Location")
			stHdr := resp.Header.Get("St")
			_ = resp.Body.Close()

			model := extractModelFromSSDP(serverHdr, locationHdr, stHdr)

			mu.Lock()
			existing, exists := results[ip]
			if !exists || (existing.Model == "" && model != "") {
				results[ip] = SSDPDevice{
					IP:       ip,
					Server:   serverHdr,
					Location: locationHdr,
					ST:       stHdr,
					Model:    model,
				}
			}
			mu.Unlock()
		}
	}()

	select {
	case <-done:
	case <-time.After(timeout):
		_ = conn.Close()
	case <-ctx.Done():
		_ = conn.Close()
	}

	return results
}

// extractModelFromSSDP derives clean model/device name from SSDP fields
func extractModelFromSSDP(server, location, st string) string {
	s := strings.TrimSpace(server)
	if s == "" {
		return ""
	}

	// Examples:
	// "Linux/4.4 UPnP/1.0 Sonos/63.2-88120 (ZPS21)" -> "Sonos ZPS21"
	// "KeeneticOS/3.8.5 UPnP/1.0" -> "Keenetic Router"
	// "Synology/DSM 7.1 UPnP/1.0" -> "Synology NAS"
	// "Samsung-TV/1.0 UPnP/1.0" -> "Samsung Smart TV"
	// "LG-WebOS/2.0 UPnP/1.0" -> "LG Smart TV"

	lower := strings.ToLower(s)
	if strings.Contains(lower, "sonos") {
		return "Sonos Speaker"
	}
	if strings.Contains(lower, "samsung") {
		return "Samsung Smart TV / Device"
	}
	if strings.Contains(lower, "lg") || strings.Contains(lower, "webos") {
		return "LG Smart TV / Device"
	}
	if strings.Contains(lower, "philips-hue") || strings.Contains(lower, "hue-bridge") {
		return "Philips Hue Bridge"
	}
	if strings.Contains(lower, "keenetic") {
		return "Keenetic Router"
	}
	if strings.Contains(lower, "synology") {
		return "Synology NAS"
	}
	if strings.Contains(lower, "qnap") {
		return "QNAP NAS"
	}
	if strings.Contains(lower, "printer") || strings.Contains(lower, "epson") || strings.Contains(lower, "canon") || strings.Contains(lower, "hp") {
		return "Network Printer"
	}

	// If server string has something friendly before slash or first word
	parts := strings.Split(s, " ")
	if len(parts) > 0 && !strings.HasPrefix(parts[0], "Linux") && !strings.HasPrefix(parts[0], "Unix") {
		return parts[0]
	}

	return ""
}
