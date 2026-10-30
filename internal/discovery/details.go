package discovery

import (
	"context"
	"embed"
	"encoding/csv"
	"io"
	"net"
	"runtime"
	"strings"
	"sync"
)

type Details struct {
	Type          string   `json:"type"`
	TypeEvidence  string   `json:"typeEvidence"`
	Manufacturer  string   `json:"manufacturer"`
	Model         string   `json:"model"`
	FriendlyName  string   `json:"friendlyName"`
	AdapterVendor string   `json:"adapterVendor"`
	AdapterModel  string   `json:"adapterModel"`
	OS            string   `json:"os"`
	PrivateMAC    bool     `json:"privateMac"`
	ReportedAt    string   `json:"reportedAt"`
	Evidence      []string `json:"evidence"`
}

// Public IEEE MA-L, MA-M and MA-S registries. Lookups never send a MAC address
// to an external service. The organization identifies the adapter, not its model.
//
//go:embed vendors/*.csv
var vendorFiles embed.FS
var vendorsOnce sync.Once
var vendors map[string]string

func adapterVendor(address string) (string, bool) {
	mac, err := net.ParseMAC(address)
	if err != nil || len(mac) != 6 {
		return "", false
	}
	if mac[0]&2 != 0 {
		return "", true
	}
	vendorsOnce.Do(func() {
		vendors = make(map[string]string)
		entries, _ := vendorFiles.ReadDir("vendors")
		for _, entry := range entries {
			file, err := vendorFiles.Open("vendors/" + entry.Name())
			if err != nil {
				continue
			}
			reader := csv.NewReader(file)
			for {
				row, err := reader.Read()
				if err == io.EOF {
					break
				}
				if err != nil {
					break
				}
				if len(row) >= 3 && (len(row[1]) == 6 || len(row[1]) == 7 || len(row[1]) == 9) {
					vendors[strings.ToUpper(row[1])] = strings.TrimSpace(row[2])
				}
			}
			file.Close()
		}
	})
	key := strings.ToUpper(strings.ReplaceAll(mac.String(), ":", ""))
	for _, length := range []int{9, 7, 6} {
		if vendor := vendors[key[:length]]; vendor != "" {
			return vendor, false
		}
	}
	return "", false
}

func MergeDetails(previous, next Details) Details {
	if next.Type == "" || typePriority(previous.TypeEvidence) > typePriority(next.TypeEvidence) {
		next.Type, next.TypeEvidence = previous.Type, previous.TypeEvidence
	}
	if next.Manufacturer == "" {
		next.Manufacturer = previous.Manufacturer
	}
	if next.Model == "" {
		next.Model = previous.Model
		next.ReportedAt = previous.ReportedAt
	}
	if next.FriendlyName == "" {
		next.FriendlyName = previous.FriendlyName
	}
	if next.AdapterVendor == "" && !next.PrivateMAC {
		next.AdapterVendor = previous.AdapterVendor
	}
	if next.AdapterModel == "" {
		next.AdapterModel = previous.AdapterModel
	}
	if next.OS == "" {
		next.OS = previous.OS
	}
	if next.ReportedAt == "" {
		next.ReportedAt = previous.ReportedAt
	}
	evidence := make([]string, 0)
	for _, item := range append(append([]string{}, next.Evidence...), previous.Evidence...) {
		found := false
		for _, existing := range evidence {
			found = found || existing == item
		}
		if !found && item != "" && len(evidence) < 12 {
			evidence = append(evidence, item)
		}
	}
	next.Evidence = evidence
	return next
}

func typePriority(evidence string) int {
	switch {
	case strings.Contains(evidence, "local network interface"), strings.Contains(evidence, "default gateway"):
		return 4
	case strings.Contains(evidence, "model identifier"):
		return 3
	case strings.Contains(evidence, "UPnP device type"), strings.Contains(evidence, "mDNS service"):
		return 2
	case strings.Contains(evidence, "Hostname"):
		return 1
	default:
		return 0
	}
}

func identify(device *Observation, network Network) {
	device.Details.AdapterVendor, device.Details.PrivateMAC = adapterVendor(device.MAC)
	if device.Details.AdapterVendor != "" {
		device.Details.Evidence = append(device.Details.Evidence, "Adapter vendor: IEEE MAC registry (not a device model)")
	}
	if device.Details.PrivateMAC {
		device.Details.Evidence = append(device.Details.Evidence, "Locally administered MAC: may be randomized; vendor lookup is unreliable")
	}
	if device.IP == network.Address {
		device.Details.Type = "Computer"
		device.Details.TypeEvidence = "This computer's local network interface"
		device.Details.OS = runtime.GOOS
		device.Details.AdapterModel = network.AdapterModel
		device.Details.Evidence = append(device.Details.Evidence, "Local operating system: adapter description")
	} else if device.IP == network.Gateway {
		device.Details.Type = "Router"
		device.Details.TypeEvidence = "Configured IPv4 default gateway"
	} else if device.Details.Type == "" {
		device.Details.Type = hostnameType(device.Hostname)
		if device.Details.Type != "" {
			device.Details.TypeEvidence = "Hostname hint (unverified)"
		}
	}
}

func hostnameType(hostname string) string {
	name := strings.ToLower(hostname)
	switch {
	case strings.Contains(name, "iphone"), strings.HasPrefix(name, "android-"):
		return "Phone"
	case strings.Contains(name, "ipad"):
		return "Tablet"
	case strings.Contains(name, "macbook"), strings.Contains(name, "imac"),
		strings.HasPrefix(name, "desktop-"), strings.HasPrefix(name, "laptop-"):
		return "Computer"
	default:
		return ""
	}
}

func discoverDetails(ctx context.Context, network Network) ([]Observation, []string) {
	type discoveryResult struct {
		devices []Observation
		err     error
		name    string
	}
	results := make(chan discoveryResult, 2)
	go func() {
		devices, err := discoverUPnP(ctx, network)
		results <- discoveryResult{devices, err, "UPnP"}
	}()
	go func() {
		devices, err := discoverMDNS(ctx, network)
		results <- discoveryResult{devices, err, "mDNS"}
	}()
	devices := make([]Observation, 0)
	warnings := make([]string, 0)
	for i := 0; i < 2; i++ {
		result := <-results
		devices = append(devices, result.devices...)
		if result.err != nil && ctx.Err() == nil {
			warnings = append(warnings, result.name+" identification unavailable: "+result.err.Error())
		}
	}
	return devices, warnings
}
