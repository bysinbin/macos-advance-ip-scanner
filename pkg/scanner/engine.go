package scanner

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Engine is the central network scanning coordinator
type Engine struct {
	mu           sync.RWMutex
	arpCache     *ARPCache
	hosts        map[string]*Host
	isScanning   int32
	cancelFunc   context.CancelFunc
	localIPs     map[string]bool
	localMACs    map[string]string
	localNets    []*net.IPNet
	gatewayIP    string
	lastProgress ScanProgress
	ssdpMap      sync.Map
}

// NewEngine creates a new Engine instance
func NewEngine() *Engine {
	return &Engine{
		arpCache:  NewARPCache(),
		hosts:     make(map[string]*Host),
		localIPs:  make(map[string]bool),
		localMACs: make(map[string]string),
	}
}

// IsScanning checks whether a scan is currently active
func (e *Engine) IsScanning() bool {
	return atomic.LoadInt32(&e.isScanning) == 1
}

// Stop cancels the ongoing scan
func (e *Engine) Stop() {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.cancelFunc != nil {
		e.cancelFunc()
		e.cancelFunc = nil
	}
	atomic.StoreInt32(&e.isScanning, 0)
}

// GetHosts returns a sorted list of discovered hosts
func (e *Engine) GetHosts() []Host {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var result []Host
	for _, h := range e.hosts {
		result = append(result, *h)
	}

	sort.Slice(result, func(i, j int) bool {
		// Sort by IP numerically
		ipA := net.ParseIP(result[i].IP).To4()
		ipB := net.ParseIP(result[j].IP).To4()
		if ipA != nil && ipB != nil {
			for k := 0; k < 4; k++ {
				if ipA[k] != ipB[k] {
					return ipA[k] < ipB[k]
				}
			}
		}
		return result[i].IP < result[j].IP
	})

	return result
}

// Start begins scanning an IP range asynchronously
func (e *Engine) Start(parentCtx context.Context, opts ScanOptions, onProgress func(p ScanProgress)) error {
	if !atomic.CompareAndSwapInt32(&e.isScanning, 0, 1) {
		return fmt.Errorf("a scan is already in progress")
	}

	// Prepare cancellation context
	ctx, cancel := context.WithCancel(parentCtx)
	e.mu.Lock()
	e.cancelFunc = cancel
	e.hosts = make(map[string]*Host)
	e.mu.Unlock()

	// Parse targets
	targetIPs, err := ParseIPRange(opts.IPRange)
	if err != nil {
		atomic.StoreInt32(&e.isScanning, 0)
		return fmt.Errorf("failed to parse IP range: %w", err)
	}

	// Detect local interfaces & gateway
	ifaces, _ := DetectInterfaces()
	localIPMap := make(map[string]bool)
	localMACMap := make(map[string]string)
	var localNets []*net.IPNet
	var defaultGw string
	for _, iface := range ifaces {
		localIPMap[iface.IP] = true
		if iface.HardwareMAC != "" {
			localMACMap[iface.IP] = iface.HardwareMAC
		}
		if _, ipNet, err := net.ParseCIDR(iface.CIDR); err == nil && ipNet != nil {
			localNets = append(localNets, ipNet)
		}
		if iface.IsDefault && iface.GatewayIP != "" {
			defaultGw = iface.GatewayIP
		}
	}
	e.mu.Lock()
	e.localIPs = localIPMap
	e.localMACs = localMACMap
	e.localNets = localNets
	e.gatewayIP = defaultGw
	e.mu.Unlock()

	// High-speed parallel UDP sweep to pre-warm the OS kernel ARP table
	TriggerFastUDPSweep(ctx, targetIPs)

	// Allow kernel to receive and record ARP replies
	select {
	case <-ctx.Done():
		atomic.StoreInt32(&e.isScanning, 0)
		return nil
	case <-time.After(80 * time.Millisecond):
	}

	// Populate fresh ARP cache from kernel table
	_, _ = e.arpCache.Refresh()

	// Setup worker pool
	concurrency := opts.Concurrency
	if concurrency <= 0 {
		concurrency = 40
	}
	if concurrency > 100 {
		concurrency = 100
	}

	total := len(targetIPs)
	var scannedCount int64
	var aliveCount int64
	startTime := time.Now()

	// Determine port list
	var portsToScan []int
	if opts.ScanPorts {
		if opts.DeepScan {
			portsToScan = append(portsToScan, DeepScanPorts...)
		} else {
			portsToScan = append(portsToScan, PopularFastPorts...)
		}
		portsToScan = append(portsToScan, opts.ExtraPorts...)
	}

	// Launch SSDP/UPnP discovery in parallel
	go func() {
		devices := DiscoverSSDP(ctx, 1500*time.Millisecond)
		for ip, dev := range devices {
			e.ssdpMap.Store(ip, dev)
		}
		e.enrichHostsWithARP()
	}()

	// Periodic ARP cache refresh during scan so MACs populate live
	ticker := time.NewTicker(600 * time.Millisecond)
	tickerDone := make(chan struct{})
	go func() {
		for {
			select {
			case <-ticker.C:
				_, _ = e.arpCache.Refresh()
				e.enrichHostsWithARP()
			case <-tickerDone:
				ticker.Stop()
				return
			case <-ctx.Done():
				ticker.Stop()
				return
			}
		}
	}()

	go func() {
		defer func() {
			close(tickerDone)
			atomic.StoreInt32(&e.isScanning, 0)
			// Final ARP refresh to catch any newly populated MAC entries
			_, _ = e.arpCache.Refresh()
			e.enrichHostsWithARP()

			if onProgress != nil {
				onProgress(ScanProgress{
					TotalIPs:   total,
					ScannedIPs: int(atomic.LoadInt64(&scannedCount)),
					AliveIPs:   int(atomic.LoadInt64(&aliveCount)),
					Percent:    100.0,
					ElapsedSec: time.Since(startTime).Seconds(),
					IsFinished: true,
				})
			}
		}()

		jobs := make(chan string, total)
		var wg sync.WaitGroup

		for i := 0; i < concurrency; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for ip := range jobs {
					select {
					case <-ctx.Done():
						return
					default:
					}

					host := e.scanSingleIP(ctx, ip, opts, portsToScan)

					curScanned := atomic.AddInt64(&scannedCount, 1)
					if host != nil {
						atomic.AddInt64(&aliveCount, 1)
						e.mu.Lock()
						e.hosts[host.IP] = host
						e.mu.Unlock()
					}

					// Throttle progress events to prevent SSE buffer overflow:
					// Emit immediately when a host is found, or every 5 dead IPs, or on the final IP.
					if onProgress != nil && (host != nil || curScanned%5 == 0 || curScanned == int64(total)) {
						pct := (float64(curScanned) / float64(total)) * 100.0
						if pct > 100.0 {
							pct = 100.0
						}
						onProgress(ScanProgress{
							TotalIPs:   total,
							ScannedIPs: int(curScanned),
							AliveIPs:   int(atomic.LoadInt64(&aliveCount)),
							Percent:    pct,
							CurrentIP:  ip,
							ElapsedSec: time.Since(startTime).Seconds(),
							IsFinished: false,
							Discovered: host,
						})
					}
				}
			}()
		}

		for _, ip := range targetIPs {
			select {
			case <-ctx.Done():
				break
			case jobs <- ip:
			}
		}
		close(jobs)

		wg.Wait()
	}()

	return nil
}

// isLocalSubnet checks if an IP belongs to any locally configured network interface
func (e *Engine) isLocalSubnet(ipStr string) bool {
	parsed := net.ParseIP(ipStr)
	if parsed == nil {
		return false
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	for _, ipNet := range e.localNets {
		if ipNet.Contains(parsed) {
			return true
		}
	}
	return false
}

// scanSingleIP scans a single IP address
func (e *Engine) scanSingleIP(ctx context.Context, ip string, opts ScanOptions, portsToScan []int) *Host {
	e.mu.RLock()
	isLocalHost := e.localIPs[ip]
	e.mu.RUnlock()

	var probe ProbeResult
	if isLocalHost {
		probe = ProbeResult{Alive: true, LatencyMs: 0.1, Method: "localhost"}
	} else {
		isLocal := e.isLocalSubnet(ip)
		probe = ProbeHost(ctx, ip, opts.Timeout, e.arpCache, isLocal)
	}

	if !probe.Alive {
		return nil
	}

	// Host is alive! Now gather MAC, Hostname, Ports, Vendor
	host := &Host{
		IP:          ip,
		Status:      StatusAlive,
		PingTimeMs:  probe.LatencyMs,
		LastSeen:    time.Now(),
		IsGateway:   (ip == e.gatewayIP),
		IsLocalHost: isLocalHost,
	}

	// Try reading MAC from ARP
	if mac, ok := e.arpCache.Get(ip); ok && mac != "" && !strings.Contains(strings.ToUpper(mac), "INCOMPLETE") {
		host.MAC = mac
		host.Vendor = LookupVendor(mac)
	}

	// If it's localhost and MAC not found in ARP, get it from local interface
	if host.IsLocalHost && host.MAC == "" {
		e.mu.RLock()
		localMAC := e.localMACs[ip]
		e.mu.RUnlock()
		if localMAC != "" {
			host.MAC = localMAC
			host.Vendor = LookupVendor(localMAC)
		} else {
			ifaces, _ := DetectInterfaces()
			for _, iface := range ifaces {
				if iface.IP == ip {
					host.MAC = iface.HardwareMAC
					host.Vendor = LookupVendor(iface.HardwareMAC)
					break
				}
			}
		}
	}

	// Resolve Hostnames (Reverse DNS, NetBIOS, mDNS)
	if opts.ResolveNames {
		names := ResolveNames(ctx, ip, opts.Timeout)
		host.Hostname = names.PrimaryName
		host.NetBIOS = names.NetBIOS
		host.MDNSName = names.MDNS
	}

	// Scan Ports
	if opts.ScanPorts && len(portsToScan) > 0 {
		openPorts := ScanPorts(ctx, ip, portsToScan, opts.Timeout, 15)
		host.OpenPorts = openPorts
	}

	// Attach SSDP model metadata if discovered
	if val, ok := e.ssdpMap.Load(ip); ok {
		if dev, okDev := val.(SSDPDevice); okDev && dev.Model != "" {
			host.Model = dev.Model
		}
	}

	// Classify device type
	host.DeviceType = ClassifyDevice(host)

	return host
}

// enrichHostsWithARP does a pass to fill any MAC addresses and SSDP models that populated late
func (e *Engine) enrichHostsWithARP() {
	e.mu.Lock()
	defer e.mu.Unlock()

	for _, host := range e.hosts {
		updated := false
		if host.MAC == "" {
			if mac, ok := e.arpCache.Get(host.IP); ok && mac != "" {
				host.MAC = mac
				host.Vendor = LookupVendor(mac)
				updated = true
			}
		}
		if host.Model == "" {
			if val, ok := e.ssdpMap.Load(host.IP); ok {
				if dev, okDev := val.(SSDPDevice); okDev && dev.Model != "" {
					host.Model = dev.Model
					updated = true
				}
			}
		}
		if updated {
			host.DeviceType = ClassifyDevice(host)
		}
	}
}

// ScanSingleTarget performs an on-demand detailed scan on a specific IP
func (e *Engine) ScanSingleTarget(ctx context.Context, ip string, customPorts []int) (*Host, error) {
	opts := ScanOptions{
		IPRange:      ip,
		Timeout:      500 * time.Millisecond,
		Concurrency:  1,
		ScanPorts:    true,
		DeepScan:     true,
		ExtraPorts:   customPorts,
		ResolveNames: true,
	}

	host := e.scanSingleIP(ctx, ip, opts, append(DeepScanPorts, customPorts...))
	if host == nil {
		return nil, fmt.Errorf("host %s is not reachable", ip)
	}

	return host, nil
}
