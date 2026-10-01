package scanner

import (
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"
)

var (
	// Matches `? (192.168.1.1) at 0:11:22:33:44:55 on en0...`
	arpRegexDarwin = regexp.MustCompile(`\?\s*\(([0-9.]+)\)\s+at\s+([0-9a-fA-F:]+)\s+on\s+([a-zA-Z0-9]+)`)
	// Linux fallback regex
	arpRegexLinux  = regexp.MustCompile(`([0-9.]+)\s+.*?([0-9a-fA-F:]{11,17})`)
)

// ARPCache stores in-memory IP to MAC associations
type ARPCache struct {
	mu    sync.RWMutex
	cache map[string]string
}

// NewARPCache creates a new thread-safe ARP cache
func NewARPCache() *ARPCache {
	return &ARPCache{
		cache: make(map[string]string),
	}
}

// NormalizeMAC formats MAC into standard XX:XX:XX:XX:XX:XX uppercase format
func NormalizeMAC(mac string) string {
	parts := strings.Split(mac, ":")
	if len(parts) != 6 {
		return strings.ToUpper(mac)
	}
	var normalized []string
	for _, p := range parts {
		if len(p) == 1 {
			normalized = append(normalized, fmt.Sprintf("0%s", strings.ToUpper(p)))
		} else {
			normalized = append(normalized, strings.ToUpper(p))
		}
	}
	return strings.Join(normalized, ":")
}

// Refresh reads system ARP table and updates the internal cache
func (c *ARPCache) Refresh() (map[string]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "arp", "-an")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to run arp -an: %w", err)
	}

	result := make(map[string]string)
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "(incomplete)") || strings.Contains(line, "ff:ff:ff:ff:ff:ff") {
			continue
		}

		matches := arpRegexDarwin.FindStringSubmatch(line)
		if len(matches) >= 3 {
			ip := matches[1]
			rawMac := matches[2]
			if rawMac != "(incomplete)" && !strings.Contains(rawMac, "incomplete") {
				normMac := NormalizeMAC(rawMac)
				result[ip] = normMac
			}
		}
	}

	c.mu.Lock()
	for ip, mac := range result {
		c.cache[ip] = mac
	}
	c.mu.Unlock()

	return result, nil
}

// Get returns the MAC address for a given IP if known
func (c *ARPCache) Get(ip string) (string, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	mac, ok := c.cache[ip]
	return mac, ok
}

// Set manual or discovered IP to MAC mapping
func (c *ARPCache) Set(ip, mac string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache[ip] = NormalizeMAC(mac)
}
