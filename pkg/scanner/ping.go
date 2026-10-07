package scanner

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

var pingTimeRegex = regexp.MustCompile(`time=([0-9.]+)\s*ms`)

// ProbeResult contains status and latency of a host reachability check
type ProbeResult struct {
	Alive      bool
	LatencyMs  float64
	Method     string // "icmp", "tcp", "arp"
}

// Limit concurrent external ping processes to prevent macOS process starvation
var pingProcessSem = make(chan struct{}, 16)

// FastTCPPorts to check if host is alive via TCP SYN / RST
var fastTCPProbePorts = []int{80, 443, 22, 445, 135, 139, 8080, 53, 3389, 5900}

// ProbeHost checks if a host is reachable using TCP probe, ARP, and fallback ICMP ping
func ProbeHost(ctx context.Context, ip string, timeout time.Duration, arpCache *ARPCache) ProbeResult {
	if timeout <= 0 {
		timeout = 350 * time.Millisecond
	}

	// 1. Rapid TCP probe on common ports first (Pure Go sockets, zero child process overhead)
	tcpRes := probeTCP(ctx, ip, timeout)
	if tcpRes.Alive {
		return tcpRes
	}

	// 2. Check if ARP table has a confirmed valid MAC address for this IP
	if arpCache != nil {
		if mac, ok := arpCache.Get(ip); ok && mac != "" && !strings.Contains(mac, "INCOMPLETE") {
			return ProbeResult{
				Alive:     true,
				LatencyMs: 1.0,
				Method:    "arp",
			}
		}
	}

	// 3. Fallback to ICMP ping for hosts that have all TCP ports stealth/firewalled
	icmpRes, err := pingICMP(ctx, ip, timeout)
	if err == nil && icmpRes.Alive {
		return icmpRes
	}

	return ProbeResult{Alive: false}
}

// pingICMP executes macOS /sbin/ping with process throttling
func pingICMP(ctx context.Context, ip string, timeout time.Duration) (ProbeResult, error) {
	select {
	case pingProcessSem <- struct{}{}:
		defer func() { <-pingProcessSem }()
	case <-ctx.Done():
		return ProbeResult{Alive: false}, ctx.Err()
	}

	timeoutMs := int(timeout.Milliseconds())
	if timeoutMs < 100 {
		timeoutMs = 100
	}

	// macOS ping: -c 1 (1 packet), -W <timeout in ms>
	cmd := exec.CommandContext(ctx, "/sbin/ping", "-c", "1", "-W", strconv.Itoa(timeoutMs), ip)
	start := time.Now()
	out, err := cmd.Output()
	elapsed := time.Since(start)

	if err != nil {
		return ProbeResult{Alive: false}, err
	}

	outStr := string(out)
	if strings.Contains(outStr, "1 packets received") || strings.Contains(outStr, "1 received") {
		matches := pingTimeRegex.FindStringSubmatch(outStr)
		latency := float64(elapsed.Microseconds()) / 1000.0
		if len(matches) >= 2 {
			if parsed, err := strconv.ParseFloat(matches[1], 64); err == nil {
				latency = parsed
			}
		}
		return ProbeResult{
			Alive:     true,
			LatencyMs: latency,
			Method:    "icmp",
		}, nil
	}

	return ProbeResult{Alive: false}, fmt.Errorf("no packet received")
}

// probeTCP tests a set of standard ports concurrently with very short deadline
func probeTCP(ctx context.Context, ip string, timeout time.Duration) ProbeResult {
	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	resultChan := make(chan ProbeResult, 1)
	var wg sync.WaitGroup

	for _, port := range fastTCPProbePorts {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			target := net.JoinHostPort(ip, strconv.Itoa(p))
			start := time.Now()

			var d net.Dialer
			conn, err := d.DialContext(probeCtx, "tcp", target)
			elapsed := float64(time.Since(start).Microseconds()) / 1000.0

			if err == nil {
				_ = conn.Close()
				select {
				case resultChan <- ProbeResult{Alive: true, LatencyMs: elapsed, Method: "tcp"}:
				default:
				}
				return
			}

			// In TCP, if we get "connection refused" (RST packet), the host is definitively ALIVE!
			if strings.Contains(err.Error(), "connection refused") {
				select {
				case resultChan <- ProbeResult{Alive: true, LatencyMs: elapsed, Method: "tcp-rst"}:
				default:
				}
			}
		}(port)
	}

	// Closer goroutine
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case res := <-resultChan:
		return res
	case <-done:
		return ProbeResult{Alive: false}
	case <-probeCtx.Done():
		return ProbeResult{Alive: false}
	}
}
