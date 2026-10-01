package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"macos-advance-ip-scanner/pkg/scanner"
	"macos-advance-ip-scanner/pkg/server"
	"macos-advance-ip-scanner/web"
)

const (
	Version   = "1.0.0"
	BannerArt = `
  __  __            ___  ____     ____                                  
 |  \/  | __ _  ___/ _ \/ ___|   / ___|  ___ __ _ _ __  _ __   ___ _ __ 
 | |\/| |/ _` + "`" + ` |/ __| | | \___ \   \___ \ / __/ _` + "`" + ` | '_ \| '_ \ / _ \ '__|
 | |  | | (_| | (__| |_| |___) |   ___) | (_| (_| | | | | | | |  __/ |   
 |_|  |_|\__,_|\___|\___/|____/   |____/ \___\__,_|_| |_|_| |_|\___|_|   
                     Advanced IP Scanner for macOS v%s
`
)

func main() {
	// Flags
	cliMode := flag.Bool("cli", false, "Terminal CLI modunda çalıştır")
	scanRange := flag.String("range", "", "Taranacak IP aralığı veya CIDR (örn: 192.168.1.1-254 veya 192.168.1.0/24)")
	port := flag.Int("port", 7788, "Web arayüzü yerel port numarası")
	noBrowser := flag.Bool("no-browser", false, "Tarayıcıyı otomatik başlatma")
	scanPortsFlag := flag.Bool("scan-ports", true, "Yaygın portları tara")
	extraPortsFlag := flag.String("ports", "", "Taranacak ek veya özel portlar (örn: 80,443,8080-8090)")
	deepScanFlag := flag.Bool("deep", false, "32+ servisi kapsayan derin port taraması yap")
	timeoutMs := flag.Int("timeout", 350, "Cihaz başına zaman aşımı (ms)")
	concurrency := flag.Int("concurrency", 50, "Eşzamanlı worker sayısı")
	formatFlag := flag.String("export", "", "Sonuçları doğrudan dışa aktar (csv, json, txt)")
	versionFlag := flag.Bool("version", false, "Sürüm bilgisini göster")

	flag.Parse()

	if *versionFlag {
		fmt.Printf("macOS Advanced IP Scanner v%s (%s/%s)\n", Version, runtime.GOOS, runtime.GOARCH)
		return
	}

	// If scanRange is provided or cliMode is true, run in CLI mode
	if *cliMode || *scanRange != "" {
		runCLIScan(*scanRange, *scanPortsFlag, *deepScanFlag, *extraPortsFlag, *timeoutMs, *concurrency, *formatFlag)
		return
	}

	// Default: Launch Web Server & Dashboard
	runWebDashboard(*port, !*noBrowser)
}

func runWebDashboard(port int, openBrowser bool) {
	fmt.Printf(BannerArt, Version)
	url := fmt.Sprintf("http://localhost:%d", port)
	fmt.Printf("🚀 Web Arayüzü başlatılıyor: %s\n", url)
	fmt.Printf("   Durdurmak için Ctrl+C tuşlarına basın.\n\n")

	staticFS := web.GetStaticFS()
	srv := server.NewServer(port, staticFS)

	// Auto open browser on macOS
	if openBrowser {
		go func() {
			time.Sleep(400 * time.Millisecond)
			_ = openURL(url)
		}()
	}

	// Graceful shutdown handling
	stopChan := make(chan os.Signal, 1)
	signal.Notify(stopChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-stopChan
		fmt.Println("\n🛑 Sunucu kapatılıyor...")
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
		os.Exit(0)
	}()

	if err := srv.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "Sunucu hatası: %v\n", err)
		os.Exit(1)
	}
}

func runCLIScan(targetRange string, scanPorts, deepScan bool, extraPortsStr string, timeoutMs, concurrency int, exportFormat string) {
	fmt.Printf(BannerArt, Version)

	// If no range specified, auto-detect primary subnet
	if targetRange == "" {
		ifaces, err := scanner.DetectInterfaces()
		if err != nil || len(ifaces) == 0 {
			fmt.Println("❌ Ağ arayüzü tespit edilemedi. Lütfen --range bayrağını kullanın.")
			return
		}

		var selected *scanner.NetworkInterfaceInfo
		for _, iface := range ifaces {
			if iface.IsDefault && iface.StartIP != "" {
				selected = &iface
				break
			}
		}
		if selected == nil {
			selected = &ifaces[0]
		}

		targetRange = fmt.Sprintf("%s-%s", selected.StartIP, selected.EndIP)
		fmt.Printf("🔍 Algılanan Arayüz: %s (%s) -> Alt Ağ: %s\n", selected.Name, selected.IP, targetRange)
		if selected.GatewayIP != "" {
			fmt.Printf("🌐 Ağ Geçidi (Gateway): %s\n", selected.GatewayIP)
		}
	}

	var extraPorts []int
	if extraPortsStr != "" {
		p, err := scanner.ParseCustomPorts(extraPortsStr)
		if err == nil {
			extraPorts = p
		}
	}

	opts := scanner.ScanOptions{
		IPRange:      targetRange,
		Timeout:      time.Duration(timeoutMs) * time.Millisecond,
		Concurrency:  concurrency,
		ScanPorts:    scanPorts,
		DeepScan:     deepScan,
		ExtraPorts:   extraPorts,
		ResolveNames: true,
	}

	engine := scanner.NewEngine()

	fmt.Printf("\n⚡ Tarama başlatıldı: %s (Worker: %d, Timeout: %dms)...\n\n", targetRange, concurrency, timeoutMs)

	// Terminal progress indicator
	startTime := time.Now()
	var lastReportedCount int

	err := engine.Start(context.Background(), opts, func(p scanner.ScanProgress) {
		if p.Discovered != nil {
			// Print discovery inline
			d := p.Discovered
			macStr := d.MAC
			if macStr == "" {
				macStr = "Bilinmiyor"
			}
			vendorStr := d.Vendor
			if len(vendorStr) > 22 {
				vendorStr = vendorStr[:19] + "..."
			}
			fmt.Printf("  [+] Bulundu: %-15s | %-17s | %-22s | %-20s (%.1fms)\n",
				d.IP, macStr, vendorStr, d.Hostname, d.PingTimeMs)
		}

		// Progress line update
		if p.ScannedIPs-lastReportedCount >= 10 || p.IsFinished {
			lastReportedCount = p.ScannedIPs
			fmt.Printf("\r⏳ İlerleme: %%%.1f (%d/%d IP) | Aktif Cihaz: %d | Süre: %.1fs",
				p.Percent, p.ScannedIPs, p.TotalIPs, p.AliveIPs, time.Since(startTime).Seconds())
		}
	})

	if err != nil {
		fmt.Printf("\n❌ Tarama başlatılamadı: %v\n", err)
		return
	}

	// Wait for scan to complete
	for engine.IsScanning() {
		time.Sleep(100 * time.Millisecond)
	}

	hosts := engine.GetHosts()
	fmt.Printf("\n\n✅ Tarama Tamamlandı! %d aktif cihaz bulundu.\n\n", len(hosts))

	// Print Results Table
	fmt.Printf("%-16s %-18s %-22s %-20s %-8s %-16s\n", "IP Adresi", "MAC Adresi", "Üretici", "Cihaz Adı", "Gecikme", "Açık Portlar")
	fmt.Println(strings.Repeat("-", 108))

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
		if portsStr == "" {
			portsStr = "-"
		}

		vendor := h.Vendor
		if len(vendor) > 21 {
			vendor = vendor[:18] + "..."
		}
		hostName := h.Hostname
		if len(hostName) > 19 {
			hostName = hostName[:16] + "..."
		}

		fmt.Printf("%-16s %-18s %-22s %-20s %-8.1f %-16s\n",
			h.IP, h.MAC, vendor, hostName, h.PingTimeMs, portsStr)
	}

	// Direct export if requested
	if exportFormat != "" {
		switch strings.ToLower(exportFormat) {
		case "csv":
			data, _ := scanner.ExportCSV(hosts)
			_ = os.WriteFile("scan-results.csv", data, 0644)
			fmt.Println("\n💾 Sonuçlar scan-results.csv dosyasına kaydedildi.")
		case "json":
			data, _ := scanner.ExportJSON(hosts)
			_ = os.WriteFile("scan-results.json", data, 0644)
			fmt.Println("\n💾 Sonuçlar scan-results.json dosyasına kaydedildi.")
		case "txt":
			data := scanner.ExportTXT(hosts)
			_ = os.WriteFile("scan-results.txt", data, 0644)
			fmt.Println("\n💾 Sonuçlar scan-results.txt dosyasına kaydedildi.")
		}
	}
}

func openURL(url string) error {
	switch runtime.GOOS {
	case "darwin":
		return exec.Command("open", url).Start()
	case "linux":
		return exec.Command("xdg-open", url).Start()
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	default:
		return fmt.Errorf("unsupported platform")
	}
}
