package scanner

import (
	"context"
	"fmt"
	"net"
	"sort"
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
	gatewayIP    string
	lastProgress ScanProgress
}

// NewEngine creates a new Engine instance
func NewEngine() *Engine {
	return &Engine{
		arpCache: NewARPCache(),
		hosts:    make(map[string]*Host),
		localIPs: make(map[string]bool),
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
	var defaultGw string
	for _, iface := range ifaces {
		localIPMap[iface.IP] = true
		if iface.IsDefault && iface.GatewayIP != "" {
			defaultGw = iface.GatewayIP
		}
	}
	e.mu.Lock()
	e.localIPs = localIPMap
	e.gatewayIP = defaultGw
	e.mu.Unlock()

	// Populate initial ARP cache
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

	go func() {
		defer func() {
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

					if onProgress != nil {
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

// scanSingleIP scans a single IP address
func (e *Engine) scanSingleIP(ctx context.Context, ip string, opts ScanOptions, portsToScan []int) *Host {
	probe := ProbeHost(ctx, ip, opts.Timeout, e.arpCache)
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
		IsLocalHost: e.localIPs[ip],
	}

	// Try reading MAC from ARP
	if mac, ok := e.arpCache.Get(ip); ok && mac != "" {
		host.MAC = mac
		host.Vendor = LookupVendor(mac)
	}

	// If it's localhost and MAC not found in ARP, get it from local interface
	if host.IsLocalHost && host.MAC == "" {
		ifaces, _ := DetectInterfaces()
		for _, iface := range ifaces {
			if iface.IP == ip {
				host.MAC = iface.HardwareMAC
				host.Vendor = LookupVendor(iface.HardwareMAC)
				break
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

	// Classify device type
	host.DeviceType = ClassifyDevice(host)

	return host
}

// enrichHostsWithARP does a post-scan pass to fill any MAC addresses that populated late
func (e *Engine) enrichHostsWithARP() {
	e.mu.Lock()
	defer e.mu.Unlock()

	for _, host := range e.hosts {
		if host.MAC == "" {
			if mac, ok := e.arpCache.Get(host.IP); ok && mac != "" {
				host.MAC = mac
				host.Vendor = LookupVendor(mac)
				host.DeviceType = ClassifyDevice(host)
			}
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
