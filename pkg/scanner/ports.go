package scanner

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// WellKnownServices maps standard ports to their protocol/service names
var WellKnownServices = map[int]string{
	21:   "FTP",
	22:   "SSH",
	23:   "Telnet",
	25:   "SMTP",
	53:   "DNS",
	80:   "HTTP",
	110:  "POP3",
	135:  "MS-RPC",
	139:  "NetBIOS-SSN",
	143:  "IMAP",
	443:  "HTTPS",
	445:  "SMB (File Sharing)",
	548:  "AFP (Apple Filing)",
	554:  "RTSP (IP Camera/Stream)",
	631:  "IPP (CUPS Printer)",
	993:  "IMAPS",
	995:  "POP3S",
	1433: "MS-SQL",
	1521: "Oracle DB",
	3000: "Node/Web Dev",
	3306: "MySQL",
	3389: "RDP (Remote Desktop)",
	5000: "UPnP / Synology",
	5432: "PostgreSQL",
	5900: "VNC (Screen Sharing)",
	6379: "Redis",
	8000: "HTTP Alt",
	8080: "HTTP Proxy/Admin",
	8443: "HTTPS Alt",
	9000: "Portainer/PHP",
	9100: "JetDirect (Printer)",
	9200: "Elasticsearch",
}

// PopularFastPorts for everyday quick scans
var PopularFastPorts = []int{
	21, 22, 23, 53, 80, 139, 443, 445, 548, 554, 3389, 5000, 5900, 8080, 9100,
}

// DeepScanPorts for thorough audit
var DeepScanPorts = []int{
	21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 548, 554, 631,
	993, 995, 1433, 1521, 3000, 3306, 3389, 5000, 5432, 5900, 6379,
	8000, 8080, 8443, 9000, 9100, 9200,
}

// ParseCustomPorts parses a comma-separated or range list of ports (e.g. "80,443,8000-8005")
func ParseCustomPorts(raw string) ([]int, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}

	portMap := make(map[int]bool)
	parts := strings.Split(raw, ",")

	for _, p := range parts {
		p = strings.TrimSpace(p)
		if strings.Contains(p, "-") {
			rangeParts := strings.Split(p, "-")
			if len(rangeParts) != 2 {
				return nil, fmt.Errorf("invalid port range: %s", p)
			}
			start, err1 := strconv.Atoi(strings.TrimSpace(rangeParts[0]))
			end, err2 := strconv.Atoi(strings.TrimSpace(rangeParts[1]))
			if err1 != nil || err2 != nil || start < 1 || end > 65535 || start > end {
				return nil, fmt.Errorf("invalid port range: %s", p)
			}
			for port := start; port <= end; port++ {
				portMap[port] = true
			}
		} else {
			port, err := strconv.Atoi(p)
			if err != nil || port < 1 || port > 65535 {
				return nil, fmt.Errorf("invalid port: %s", p)
			}
			portMap[port] = true
		}
	}

	var result []int
	for port := range portMap {
		result = append(result, port)
	}
	sort.Ints(result)
	return result, nil
}

// ScanPorts tests a list of ports on target host concurrently
func ScanPorts(ctx context.Context, ip string, ports []int, timeout time.Duration, concurrency int) []PortInfo {
	if len(ports) == 0 {
		return nil
	}
	if timeout <= 0 {
		timeout = 300 * time.Millisecond
	}
	if concurrency <= 0 || concurrency > 50 {
		concurrency = 25
	}

	var results []PortInfo
	var mu sync.Mutex

	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	for _, p := range ports {
		select {
		case <-ctx.Done():
			return results
		default:
		}

		wg.Add(1)
		sem <- struct{}{}

		go func(port int) {
			defer wg.Done()
			defer func() { <-sem }()

			target := net.JoinHostPort(ip, strconv.Itoa(port))
			dialer := net.Dialer{Timeout: timeout}

			conn, err := dialer.DialContext(ctx, "tcp", target)
			if err == nil {
				service := WellKnownServices[port]
				if service == "" {
					service = "Unknown"
				}

				banner := grabBanner(conn, ip, port, 400*time.Millisecond)
				_ = conn.Close()

				mu.Lock()
				results = append(results, PortInfo{
					Port:     port,
					Service:  service,
					Protocol: "tcp",
					IsOpen:   true,
					Banner:   banner,
				})
				mu.Unlock()
			}
		}(p)
	}

	wg.Wait()

	sort.Slice(results, func(i, j int) bool {
		return results[i].Port < results[j].Port
	})

	return results
}

// grabBanner captures the service identification string or HTTP title
func grabBanner(conn net.Conn, ip string, port int, timeout time.Duration) string {
	_ = conn.SetDeadline(time.Now().Add(timeout))
	reader := bufio.NewReader(conn)

	switch port {
	case 21, 22, 25, 110, 143:
		// Service announces banner immediately upon connect
		line, err := reader.ReadString('\n')
		if err == nil {
			return strings.TrimSpace(line)
		}
	case 80, 8080, 8000, 3000, 5000:
		// Simple HTTP probe
		req := fmt.Sprintf("GET / HTTP/1.0\r\nHost: %s\r\nUser-Agent: Mozilla/5.0 (Macintosh)\r\nConnection: close\r\n\r\n", ip)
		_, _ = conn.Write([]byte(req))

		buf := make([]byte, 1024)
		n, err := reader.Read(buf)
		if err == nil && n > 0 {
			raw := string(buf[:n])
			for _, line := range strings.Split(raw, "\r\n") {
				if strings.HasPrefix(strings.ToLower(line), "server:") {
					return strings.TrimSpace(strings.TrimPrefix(line, "Server:"))
				}
			}
			lower := strings.ToLower(raw)
			if start := strings.Index(lower, "<title>"); start != -1 {
				if end := strings.Index(lower[start:], "</title>"); end != -1 {
					title := raw[start+7 : start+end]
					title = strings.TrimSpace(title)
					if len(title) > 0 && len(title) < 50 {
						return "Title: " + title
					}
				}
			}
		}
	}
	return ""
}

// ClassifyDevice attempts to identify device category based on vendor, open ports, and name
func ClassifyDevice(h *Host) DeviceType {
	if h.IsGateway {
		return DeviceRouter
	}

	v := strings.ToLower(h.Vendor)
	name := strings.ToLower(h.Hostname + " " + h.NetBIOS + " " + h.MDNSName + " " + h.Model)

	// Check model first if SSDP / UPnP found it
	if strings.Contains(name, "smart tv") || strings.Contains(name, "sonos") || strings.Contains(name, "hue") {
		return DeviceIoT
	}
	if strings.Contains(name, "nas") || strings.Contains(name, "synology") || strings.Contains(name, "qnap") {
		return DeviceServer
	}
	if strings.Contains(name, "router") || strings.Contains(name, "gateway") || strings.Contains(name, "access point") {
		return DeviceRouter
	}

	// Check open ports
	openMap := make(map[int]bool)
	for _, p := range h.OpenPorts {
		if p.IsOpen {
			openMap[p.Port] = true
		}
	}

	// Printer check
	if openMap[9100] || openMap[631] || strings.Contains(v, "canon") || strings.Contains(v, "epson") || strings.Contains(v, "brother") || strings.Contains(name, "printer") {
		return DevicePrinter
	}

	// Smart / IoT
	if strings.Contains(v, "espressif") || strings.Contains(v, "tuya") || strings.Contains(v, "philips") || strings.Contains(v, "sonos") || strings.Contains(v, "xiaomi") {
		return DeviceIoT
	}

	// Camera / Streamer
	if openMap[554] || strings.Contains(name, "cam") || strings.Contains(name, "dahua") || strings.Contains(name, "hikvision") {
		return DeviceIoT
	}

	// Server / NAS
	if (openMap[5000] && strings.Contains(v, "synology")) || strings.Contains(v, "qnap") || strings.Contains(name, "nas") || strings.Contains(name, "server") {
		return DeviceServer
	}

	// Router / AP
	if strings.Contains(v, "tp-link") || strings.Contains(v, "mikrotik") || strings.Contains(v, "ubiquiti") || strings.Contains(v, "cisco") || strings.Contains(v, "netgear") {
		return DeviceRouter
	}

	// Apple devices
	if strings.Contains(v, "apple") {
		if strings.Contains(name, "iphone") || strings.Contains(name, "ipad") {
			return DeviceMobile
		}
		if strings.Contains(name, "watch") {
			return DeviceIoT
		}
		if strings.Contains(name, "mac") || openMap[548] || openMap[5900] {
			return DeviceComputer
		}
		return DeviceMobile
	}

	// Windows or Linux PC
	if openMap[3389] || openMap[445] || openMap[139] || openMap[22] {
		return DeviceComputer
	}

	return DeviceUnknown
}
