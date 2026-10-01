package scanner

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// ExportCSV exports a slice of hosts into CSV format
func ExportCSV(hosts []Host) ([]byte, error) {
	var buf bytes.Buffer
	writer := csv.NewWriter(&buf)

	// Header
	header := []string{
		"IP Address",
		"Status",
		"Hostname",
		"NetBIOS",
		"mDNS",
		"MAC Address",
		"Manufacturer (Vendor)",
		"Device Type",
		"Ping Latency (ms)",
		"Open Ports",
		"Is Gateway",
	}
	if err := writer.Write(header); err != nil {
		return nil, err
	}

	for _, h := range hosts {
		var ports []string
		for _, p := range h.OpenPorts {
			if p.IsOpen {
				ports = append(ports, fmt.Sprintf("%d/%s", p.Port, p.Service))
			}
		}

		row := []string{
			h.IP,
			string(h.Status),
			h.Hostname,
			h.NetBIOS,
			h.MDNSName,
			h.MAC,
			h.Vendor,
			string(h.DeviceType),
			strconv.FormatFloat(h.PingTimeMs, 'f', 2, 64),
			strings.Join(ports, "; "),
			strconv.FormatBool(h.IsGateway),
		}
		if err := writer.Write(row); err != nil {
			return nil, err
		}
	}

	writer.Flush()
	return buf.Bytes(), writer.Error()
}

// ExportJSON exports a slice of hosts into formatted JSON
func ExportJSON(hosts []Host) ([]byte, error) {
	payload := map[string]interface{}{
		"generatedAt": time.Now().Format(time.RFC3339),
		"totalHosts":  len(hosts),
		"hosts":       hosts,
	}
	return json.MarshalIndent(payload, "", "  ")
}

// ExportTXT generates a readable text summary
func ExportTXT(hosts []Host) []byte {
	var sb strings.Builder
	sb.WriteString("========================================================================================\n")
	sb.WriteString(fmt.Sprintf("   macOS Advanced IP Scanner Report - %s\n", time.Now().Format("2006-01-02 15:04:05")))
	sb.WriteString("========================================================================================\n\n")

	sb.WriteString(fmt.Sprintf("%-16s %-8s %-20s %-18s %-22s %-16s\n", "IP Address", "Status", "Hostname", "MAC Address", "Manufacturer", "Open Ports"))
	sb.WriteString(strings.Repeat("-", 106) + "\n")

	for _, h := range hosts {
		var ports []string
		for _, p := range h.OpenPorts {
			if p.IsOpen {
				ports = append(ports, strconv.Itoa(p.Port))
			}
		}
		portsStr := strings.Join(ports, ",")
		if len(portsStr) > 16 {
			portsStr = portsStr[:13] + "..."
		}

		hostName := h.Hostname
		if len(hostName) > 19 {
			hostName = hostName[:16] + "..."
		}

		vendor := h.Vendor
		if len(vendor) > 21 {
			vendor = vendor[:18] + "..."
		}

		sb.WriteString(fmt.Sprintf("%-16s %-8s %-20s %-18s %-22s %-16s\n",
			h.IP,
			h.Status,
			hostName,
			h.MAC,
			vendor,
			portsStr,
		))
	}

	return []byte(sb.String())
}
