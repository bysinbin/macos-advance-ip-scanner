package scanner

import (
	"time"
)

// Status represents the reachability of a host
type HostStatus string

const (
	StatusAlive   HostStatus = "alive"
	StatusDead    HostStatus = "dead"
	StatusPending HostStatus = "pending"
)

// DeviceType classifies the device based on open ports, vendor and hostname
type DeviceType string

const (
	DeviceRouter    DeviceType = "Router / Gateway"
	DeviceComputer  DeviceType = "Computer"
	DeviceMobile    DeviceType = "Mobile / Tablet"
	DevicePrinter   DeviceType = "Printer"
	DeviceIoT       DeviceType = "Smart / IoT Device"
	DeviceServer    DeviceType = "Server / NAS"
	DeviceUnknown   DeviceType = "Network Device"
)

// PortInfo contains port number, service name, protocol and status
type PortInfo struct {
	Port        int    `json:"port"`
	Service     string `json:"service"`
	Protocol    string `json:"protocol"` // "tcp"
	IsOpen      bool   `json:"isOpen"`
	Description string `json:"description,omitempty"`
	Banner      string `json:"banner,omitempty"`
}

// Host represents a discovered network device
type Host struct {
	IP          string       `json:"ip"`
	Hostname    string       `json:"hostname"`
	NetBIOS     string       `json:"netbios,omitempty"`
	MDNSName    string       `json:"mdnsName,omitempty"`
	MAC         string       `json:"mac"`
	Vendor      string       `json:"vendor"`
	Model       string       `json:"model,omitempty"`
	CustomName  string       `json:"customName,omitempty"`
	Status      HostStatus   `json:"status"`
	PingTimeMs  float64      `json:"pingTimeMs"`
	OpenPorts   []PortInfo   `json:"openPorts"`
	DeviceType  DeviceType   `json:"deviceType"`
	LastSeen    time.Time    `json:"lastSeen"`
	IsGateway   bool         `json:"isGateway"`
	IsLocalHost bool         `json:"isLocalHost"`
	Comments    string       `json:"comments,omitempty"`
}

// NetworkInterfaceInfo contains details about a local network interface
type NetworkInterfaceInfo struct {
	Name        string `json:"name"`
	HardwareMAC string `json:"hardwareMac"`
	IP          string `json:"ip"`
	Netmask     string `json:"netmask"`
	CIDR        string `json:"cidr"`
	StartIP     string `json:"startIp"`
	EndIP       string `json:"endIp"`
	IsDefault   bool   `json:"isDefault"`
	GatewayIP   string `json:"gatewayIp,omitempty"`
}

// ScanOptions configures a network scan
type ScanOptions struct {
	IPRange     string        `json:"ipRange"`     // e.g. "192.168.1.1-192.168.1.254" or "192.168.1.0/24"
	Timeout     time.Duration `json:"timeout"`     // Per-host ping/probe timeout
	Concurrency int           `json:"concurrency"` // Max worker goroutines
	ScanPorts   bool          `json:"scanPorts"`   // Whether to scan common ports
	ExtraPorts  []int         `json:"extraPorts"`  // Additional custom ports to scan
	DeepScan    bool          `json:"deepScan"`    // Scan extended list of 35+ services
	ResolveNames bool         `json:"resolveNames"`// Enable NetBIOS + mDNS + rDNS
}

// ScanProgress tracks real-time scanning progress
type ScanProgress struct {
	TotalIPs   int       `json:"totalIps"`
	ScannedIPs int       `json:"scannedIps"`
	AliveIPs   int       `json:"aliveIps"`
	Percent    float64   `json:"percent"`
	CurrentIP  string    `json:"currentIp"`
	ElapsedSec float64   `json:"elapsedSec"`
	IsFinished bool      `json:"isFinished"`
	Discovered *Host     `json:"discovered,omitempty"`
}
