package scanner

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
)

// DetectInterfaces discovers all active IPv4 interfaces and calculates scanning ranges
func DetectInterfaces() ([]NetworkInterfaceInfo, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("failed to get network interfaces: %w", err)
	}

	defaultIface, defaultGateway := detectDefaultRoute()

	var results []NetworkInterfaceInfo

	for _, iface := range ifaces {
		// Skip down or loopback interfaces
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}

			// Focus on IPv4
			ipv4 := ipNet.IP.To4()
			if ipv4 == nil {
				continue
			}

			// Skip link-local 169.254.x.x
			if ipv4.IsLinkLocalUnicast() {
				continue
			}

			mask := ipNet.Mask
			netmaskStr := fmt.Sprintf("%d.%d.%d.%d", mask[0], mask[1], mask[2], mask[3])

			startIP, endIP := calculateSubnetRange(ipv4, mask)

			isDefault := (iface.Name == defaultIface) || (strings.HasPrefix(iface.Name, "en") && defaultIface == "")

			gw := ""
			if isDefault && defaultGateway != "" {
				gw = defaultGateway
			}

			info := NetworkInterfaceInfo{
				Name:        iface.Name,
				HardwareMAC: NormalizeMAC(iface.HardwareAddr.String()),
				IP:          ipv4.String(),
				Netmask:     netmaskStr,
				CIDR:        ipNet.String(),
				StartIP:     startIP,
				EndIP:       endIP,
				IsDefault:   isDefault,
				GatewayIP:   gw,
			}

			results = append(results, info)
		}
	}

	return results, nil
}

// detectDefaultRoute runs netstat to identify default physical interface and gateway
func detectDefaultRoute() (string, string) {
	cmd := exec.Command("netstat", "-rn", "-f", "inet")
	out, err := cmd.Output()
	if err != nil {
		return "", ""
	}

	var primaryIface, primaryGw string
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) >= 4 && fields[0] == "default" {
			gw := fields[1]
			iface := fields[len(fields)-1]
			// Prefer physical enX over utun VPN interfaces
			if strings.HasPrefix(iface, "en") {
				return iface, gw
			}
			if primaryIface == "" {
				primaryIface = iface
				primaryGw = gw
			}
		}
	}
	return primaryIface, primaryGw
}

// calculateSubnetRange calculates the usable host IP range for a subnet
func calculateSubnetRange(ip net.IP, mask net.IPMask) (string, string) {
	ipInt := binary.BigEndian.Uint32(ip.To4())
	maskInt := binary.BigEndian.Uint32(mask)

	networkInt := ipInt & maskInt
	broadcastInt := networkInt | ^maskInt

	// For /31 or /32, adjust boundary
	ones, _ := mask.Size()
	if ones >= 31 {
		return ip.String(), ip.String()
	}

	// Usable host range: network + 1 up to broadcast - 1
	firstHostInt := networkInt + 1
	lastHostInt := broadcastInt - 1

	firstIP := make(net.IP, 4)
	binary.BigEndian.PutUint32(firstIP, firstHostInt)

	lastIP := make(net.IP, 4)
	binary.BigEndian.PutUint32(lastIP, lastHostInt)

	return firstIP.String(), lastIP.String()
}

// ParseIPRange parses user input like:
// - "192.168.1.1-192.168.1.254"
// - "192.168.1.1-254"
// - "192.168.1.0/24"
// - "192.168.1.50"
// and returns the ordered list of all target IP strings.
func ParseIPRange(raw string) ([]string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("empty IP range")
	}

	// Case 1: CIDR notation (e.g. 192.168.1.0/24)
	if strings.Contains(raw, "/") {
		_, ipNet, err := net.ParseCIDR(raw)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR: %w", err)
		}
		return enumerateCIDR(ipNet), nil
	}

	// Case 2: Range with hyphen (e.g. 192.168.1.1-192.168.1.254 or 192.168.1.1-254)
	if strings.Contains(raw, "-") {
		parts := strings.Split(raw, "-")
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid IP range format")
		}
		startStr := strings.TrimSpace(parts[0])
		endStr := strings.TrimSpace(parts[1])

		startIP := net.ParseIP(startStr).To4()
		if startIP == nil {
			return nil, fmt.Errorf("invalid start IP: %s", startStr)
		}

		var endIP net.IP
		if !strings.Contains(endStr, ".") {
			// Format like "192.168.1.1-254"
			lastOctet, err := strconv.Atoi(endStr)
			if err != nil || lastOctet < 0 || lastOctet > 255 {
				return nil, fmt.Errorf("invalid end octet: %s", endStr)
			}
			endIP = make(net.IP, 4)
			copy(endIP, startIP)
			endIP[3] = byte(lastOctet)
		} else {
			// Format like "192.168.1.1-192.168.1.254"
			endIP = net.ParseIP(endStr).To4()
			if endIP == nil {
				return nil, fmt.Errorf("invalid end IP: %s", endStr)
			}
		}

		return enumerateRange(startIP, endIP)
	}

	// Case 3: Single IP
	singleIP := net.ParseIP(raw).To4()
	if singleIP != nil {
		return []string{singleIP.String()}, nil
	}

	return nil, fmt.Errorf("unrecognized IP format: %s", raw)
}

func enumerateRange(startIP, endIP net.IP) ([]string, error) {
	startInt := binary.BigEndian.Uint32(startIP)
	endInt := binary.BigEndian.Uint32(endIP)

	if startInt > endInt {
		return nil, fmt.Errorf("start IP %s is greater than end IP %s", startIP, endIP)
	}

	// Safety limit (e.g. max 65536 IPs at a time)
	count := endInt - startInt + 1
	if count > 65536 {
		return nil, fmt.Errorf("range is too large (%d IPs, maximum supported is 65536)", count)
	}

	var ips []string
	for cur := startInt; cur <= endInt; cur++ {
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, cur)
		ips = append(ips, ip.String())
	}
	return ips, nil
}

func enumerateCIDR(ipNet *net.IPNet) []string {
	var ips []string
	ip := ipNet.IP.To4()
	if ip == nil {
		return nil
	}

	mask := ipNet.Mask
	ipInt := binary.BigEndian.Uint32(ip)
	maskInt := binary.BigEndian.Uint32(mask)

	networkInt := ipInt & maskInt
	broadcastInt := networkInt | ^maskInt

	ones, _ := mask.Size()
	var start, end uint32
	if ones >= 31 {
		start = networkInt
		end = broadcastInt
	} else {
		// usable host range
		start = networkInt + 1
		end = broadcastInt - 1
	}

	for cur := start; cur <= end; cur++ {
		curIP := make(net.IP, 4)
		binary.BigEndian.PutUint32(curIP, cur)
		ips = append(ips, curIP.String())
	}

	return ips
}
