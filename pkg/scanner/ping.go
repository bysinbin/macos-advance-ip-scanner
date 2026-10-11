package scanner

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	pingTimeRegex = regexp.MustCompile(`time=([0-9.]+)\s*ms`)
	winPingRegex  = regexp.MustCompile(`(?:time|süre)[=<]([0-9.]+)\s*ms`)
)

// ProbeResult contains status and latency of a host reachability check
type ProbeResult struct {
	Alive      bool
	LatencyMs  float64
	Method     string // "icmp", "tcp", "arp"
}

// Limit concurrent external ping processes to prevent macOS/Windows process starvation
var pingProcessSem = make(chan struct{}, 64)

// FastTCPPorts to check if host is alive via TCP SYN / RST
var fastTCPProbePorts = []int{80, 443, 22, 445, 135, 139, 8080, 53, 3389, 5900}

// TriggerFastUDPSweep sends rapid unprivileged UDP probes to all target IPs.
// This triggers the OS kernel to broadcast ARP requests for all target IPs on the local network.
func TriggerFastUDPSweep(ctx context.Context, targetIPs []string) {
	var wg sync.WaitGroup
	sem := make(chan struct{}, 64)

	for _, ip := range targetIPs {
		select {
		case <-ctx.Done():
			return
		case sem <- struct{}{}:
		}

		wg.Add(1)
		go func(target string) {
			defer func() {
				<-sem
				wg.Done()
			}()

			d := net.Dialer{Timeout: 30 * time.Millisecond}
			conn, err := d.DialContext(ctx, "udp", net.JoinHostPort(target, "137"))
			if err == nil {
				_, _ = conn.Write([]byte{0x00})
				_ = conn.Close()
			}
		}(ip)
	}

	wg.Wait()
}

// ProbeHost checks if a host is reachable using ARP, TCP probe, and fallback ICMP ping.
// isLocalSubnet controls whether to skip external ICMP ping on ARP misses.
func ProbeHost(ctx context.Context, ip string, timeout time.Duration, arpCache *ARPCache, isLocalSubnet ...bool) ProbeResult {
	if timeout <= 0 {
		timeout = 250 * time.Millisecond
	}

	isLocal := false
	if len(isLocalSubnet) > 0 {
		isLocal = isLocalSubnet[0]
	}

	// 1. Check if ARP table already has a confirmed valid MAC address for this IP
	if arpCache != nil {
		if mac, ok := arpCache.Get(ip); ok && mac != "" && !strings.Contains(strings.ToUpper(mac), "INCOMPLETE") {
			return ProbeResult{
				Alive:     true,
				LatencyMs: 1.0,
				Method:    "arp",
			}
		}
	}

	// 2. Rapid TCP probe on common ports (Pure Go sockets, zero child process overhead)
	tcpRes := probeTCP(ctx, ip, timeout)
	if tcpRes.Alive {
		if isLocal && arpCache != nil {
			if _, ok := arpCache.Get(ip); !ok {
				_, _ = arpCache.QuerySingle(ip)
			}
		}
		return tcpRes
	}

	// 3. If on a local subnet and neither ARP nor TCP responded:
	// Check ARP one more time in case the TCP probe attempt triggered kernel ARP resolution.
	if isLocal {
		if arpCache != nil {
			if mac, ok := arpCache.Get(ip); ok && mac != "" && !strings.Contains(strings.ToUpper(mac), "INCOMPLETE") {
				return ProbeResult{
					Alive:     true,
					LatencyMs: 1.0,
					Method:    "arp",
				}
			}
		}
		return ProbeResult{Alive: false}
	}

	// 4. Fallback to ICMP ping for routed subnets or remote targets
	icmpRes, err := pingICMP(ctx, ip, timeout)
	if err == nil && icmpRes.Alive {
		return icmpRes
	}

	return ProbeResult{Alive: false}
}

// pingICMP executes platform-specific ping with process throttling
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

	// Hard context deadline to prevent child process from lingering
	cmdCtx, cancel := context.WithTimeout(ctx, timeout+300*time.Millisecond)
	defer cancel()

	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.CommandContext(cmdCtx, "ping", "-n", "1", "-w", strconv.Itoa(timeoutMs), ip)
	case "linux":
		timeoutSec := timeoutMs / 1000
		if timeoutSec < 1 {
			timeoutSec = 1
		}
		cmd = exec.CommandContext(cmdCtx, "ping", "-c", "1", "-W", strconv.Itoa(timeoutSec), "-n", ip)
	default: // darwin / macos / bsd
		cmd = exec.CommandContext(cmdCtx, "/sbin/ping", "-c", "1", "-W", strconv.Itoa(timeoutMs), "-n", ip)
	}

	start := time.Now()
	out, err := cmd.Output()
	elapsed := time.Since(start)

	outStr := string(out)

	if runtime.GOOS == "windows" {
		if err == nil && (strings.Contains(outStr, "TTL=") || (strings.Contains(outStr, "Reply from") && !strings.Contains(outStr, "unreachable") && !strings.Contains(outStr, "timed out"))) {
			latency := float64(elapsed.Microseconds()) / 1000.0
			matches := winPingRegex.FindStringSubmatch(outStr)
			if len(matches) >= 2 {
				if parsed, parseErr := strconv.ParseFloat(matches[1], 64); parseErr == nil {
					latency = parsed
				}
			} else if strings.Contains(outStr, "time<1ms") || strings.Contains(outStr, "süre<1ms") {
				latency = 0.5
			}
			return ProbeResult{
				Alive:     true,
				LatencyMs: latency,
				Method:    "icmp",
			}, nil
		}
		return ProbeResult{Alive: false}, fmt.Errorf("no packet received")
	}

	if err != nil {
		return ProbeResult{Alive: false}, err
	}

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
	if timeout > 150*time.Millisecond {
		timeout = 150 * time.Millisecond
	}
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
