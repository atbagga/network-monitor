package discovery

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sort"
	"sync"
	"time"
)

type Network struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Address      string `json:"address"`
	CIDR         string `json:"cidr"`
	ScanCIDR     string `json:"scanCidr"`
	Profile      string `json:"profile"`
	Gateway      string `json:"gateway"`
	MAC          string `json:"-"`
	AdapterModel string `json:"-"`
}

type interfaceDetails struct {
	Profile      string
	Key          string
	Gateway      string
	AdapterModel string
}

type Observation struct {
	IP       string  `json:"ip"`
	MAC      string  `json:"mac"`
	Hostname string  `json:"hostname"`
	Source   string  `json:"source"`
	Details  Details `json:"details"`
}

type Result struct {
	Devices  []Observation
	Warnings []string
}

func Networks() ([]Network, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	networks := make([]Network, 0)
	details := platformInterfaces()
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addresses, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, address := range addresses {
			prefix, err := netip.ParsePrefix(address.String())
			if err != nil || !prefix.Addr().Is4() || !prefix.Addr().IsPrivate() {
				continue
			}
			scanPrefix := prefix
			if prefix.Bits() < 24 {
				scanPrefix = netip.PrefixFrom(prefix.Addr(), 24)
			}
			info := details[iface.Index]
			networks = append(networks, Network{
				ID:   networkID(iface.Index, prefix, info.Key),
				Name: iface.Name, Address: prefix.Addr().String(),
				CIDR: prefix.Masked().String(), ScanCIDR: scanPrefix.Masked().String(),
				Profile: info.Profile, Gateway: info.Gateway, MAC: iface.HardwareAddr.String(), AdapterModel: info.AdapterModel,
			})
		}
	}
	sort.Slice(networks, func(i, j int) bool { return networks[i].ID < networks[j].ID })
	return networks, nil
}

func networkID(index int, prefix netip.Prefix, profile string) string {
	id := fmt.Sprintf("%d:%s", index, prefix.Masked())
	if profile != "" {
		hash := sha256.Sum256([]byte(profile))
		id += fmt.Sprintf(":%x", hash[:8])
	}
	return id
}

func Targets(prefix netip.Prefix) ([]netip.Addr, error) {
	if !prefix.IsValid() || !prefix.Addr().Is4() || !prefix.Addr().IsPrivate() || prefix.Bits() < 24 {
		return nil, errors.New("discovery requires a private IPv4 subnet of /24 or smaller")
	}
	prefix = prefix.Masked()
	count := 1 << (32 - prefix.Bits())
	addresses := make([]netip.Addr, 0, count)
	address := prefix.Addr()
	for i := 0; i < count; i++ {
		if count <= 2 || (i != 0 && i != count-1) {
			addresses = append(addresses, address)
		}
		address = address.Next()
	}
	return addresses, nil
}

func Scan(ctx context.Context, network Network) (Result, error) {
	prefix, err := netip.ParsePrefix(network.ScanCIDR)
	if err != nil {
		return Result{}, err
	}
	targets, err := Targets(prefix)
	if err != nil {
		return Result{}, err
	}
	result := Result{Devices: make([]Observation, 0), Warnings: make([]string, 0)}
	hits := make(map[string]Observation)
	var mutex sync.Mutex
	jobs := make(chan netip.Addr)
	var workers sync.WaitGroup
	for i := 0; i < 16; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for address := range jobs {
				if ctx.Err() != nil {
					continue
				}
				if address.String() == network.Address || ping(ctx, address.String()) {
					mutex.Lock()
					hits[address.String()] = Observation{IP: address.String(), Source: "ICMP reply"}
					if address.String() == network.Address {
						hostname, _ := os.Hostname()
						hits[address.String()] = Observation{
							IP: address.String(), MAC: network.MAC, Hostname: hostname, Source: "Local interface",
						}
					}
					mutex.Unlock()
				}
			}
		}()
	}
send:
	for _, address := range targets {
		select {
		case <-ctx.Done():
			break send
		case jobs <- address:
		}
	}
	close(jobs)
	workers.Wait()
	if ctx.Err() != nil {
		return result, ctx.Err()
	}
	neighbors, err := readNeighbors(ctx, network)
	if err != nil {
		result.Warnings = append(result.Warnings, "Neighbor-table discovery unavailable: "+err.Error())
	}
	for _, neighbor := range neighbors {
		address, err := netip.ParseAddr(neighbor.IP)
		if err != nil || !prefix.Contains(address) {
			continue
		}
		if existing, ok := hits[neighbor.IP]; ok {
			neighbor.Source = existing.Source + " + neighbor table"
		}
		hits[neighbor.IP] = neighbor
	}
	enriched, warnings := discoverDetails(ctx, network)
	result.Warnings = append(result.Warnings, warnings...)
	for _, report := range enriched {
		if existing, ok := hits[report.IP]; ok {
			existing.Details = MergeDetails(existing.Details, report.Details)
			if existing.Hostname == "" {
				existing.Hostname = report.Hostname
			}
			existing.Source += " + " + report.Source
			hits[report.IP] = existing
		} else {
			hits[report.IP] = report
		}
	}
	for _, device := range hits {
		result.Devices = append(result.Devices, device)
	}
	sort.Slice(result.Devices, func(i, j int) bool {
		return netip.MustParseAddr(result.Devices[i].IP).Less(netip.MustParseAddr(result.Devices[j].IP))
	})
	// Bound reverse-DNS work independently from the host probes.
	jobsForDNS := make(chan int)
	workers = sync.WaitGroup{}
	for i := 0; i < 8; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for index := range jobsForDNS {
				lookupCtx, cancel := context.WithTimeout(ctx, 600*time.Millisecond)
				names, err := net.DefaultResolver.LookupAddr(lookupCtx, result.Devices[index].IP)
				cancel()
				if err == nil && len(names) > 0 {
					result.Devices[index].Hostname = names[0]
				}
			}
		}()
	}
	for index := range result.Devices {
		jobsForDNS <- index
	}
	close(jobsForDNS)
	workers.Wait()
	for index := range result.Devices {
		identify(&result.Devices[index], network)
	}
	return result, ctx.Err()
}
