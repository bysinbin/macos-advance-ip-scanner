package scanner

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
)

// SendWakeOnLAN sends a Magic Packet to wake up a target machine by its MAC address
func SendWakeOnLAN(macStr string, broadcastIP string) error {
	cleanMAC := strings.ReplaceAll(strings.ReplaceAll(macStr, ":", ""), "-", "")
	if len(cleanMAC) != 12 {
		return fmt.Errorf("invalid MAC address: %s", macStr)
	}

	macBytes, err := hex.DecodeString(cleanMAC)
	if err != nil {
		return fmt.Errorf("failed to decode MAC address: %w", err)
	}

	// Magic packet: 6 bytes of 0xFF followed by 16 repetitions of target MAC (102 bytes total)
	var packet bytes.Buffer
	packet.Write(bytes.Repeat([]byte{0xFF}, 6))
	for i := 0; i < 16; i++ {
		packet.Write(macBytes)
	}

	if broadcastIP == "" {
		broadcastIP = "255.255.255.255"
	}

	addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(broadcastIP, "9"))
	if err != nil {
		return fmt.Errorf("failed to resolve broadcast address: %w", err)
	}

	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return fmt.Errorf("failed to dial UDP broadcast: %w", err)
	}
	defer conn.Close()

	_, err = conn.Write(packet.Bytes())
	if err != nil {
		return fmt.Errorf("failed to send magic packet: %w", err)
	}

	return nil
}
