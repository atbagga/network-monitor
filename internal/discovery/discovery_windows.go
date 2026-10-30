package discovery

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var ttlReply = regexp.MustCompile(`(?i)\bTTL[= ]\d+`)

func ping(ctx context.Context, address string) bool {
	probeCtx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
	defer cancel()
	output, err := exec.CommandContext(probeCtx, "ping.exe", "-n", "1", "-w", "500", address).Output()
	return err == nil && ttlReply.Match(output)
}

func readNeighbors(ctx context.Context, network Network) ([]Observation, error) {
	index, _, _ := strings.Cut(network.ID, ":")
	interfaceIndex, err := strconv.Atoi(index)
	if err != nil {
		return nil, err
	}
	command := fmt.Sprintf(
		"$ErrorActionPreference='Stop'; @(Get-NetNeighbor -AddressFamily IPv4 -InterfaceIndex %d | Where-Object { $_.State -in @('Reachable','Stale','Delay','Probe','Permanent') } | Select-Object IPAddress,LinkLayerAddress) | ConvertTo-Json -Compress",
		interfaceIndex,
	)
	readCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	output, err := exec.CommandContext(readCtx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", command).Output()
	if err != nil {
		return nil, fmt.Errorf("Get-NetNeighbor failed: %w", err)
	}
	return parseNeighbors(output)
}

func parseNeighbors(data []byte) ([]Observation, error) {
	type neighbor struct {
		IP  string `json:"IPAddress"`
		MAC string `json:"LinkLayerAddress"`
	}
	entries := make([]neighbor, 0)
	if len(strings.TrimSpace(string(data))) == 0 {
		return nil, nil
	}
	if err := json.Unmarshal(data, &entries); err != nil {
		var single neighbor
		if err := json.Unmarshal(data, &single); err != nil {
			return nil, err
		}
		entries = append(entries, single)
	}
	devices := make([]Observation, 0, len(entries))
	for _, entry := range entries {
		mac, err := net.ParseMAC(entry.MAC)
		if err != nil || len(mac) != 6 || mac[0]&1 != 0 {
			continue
		}
		allZero := true
		for _, b := range mac {
			allZero = allZero && b == 0
		}
		if allZero {
			continue
		}
		devices = append(devices, Observation{IP: entry.IP, MAC: mac.String(), Source: "Neighbor cache (may be stale)"})
	}
	return devices, nil
}
