package discovery

import (
	"net/netip"
	"strings"
	"testing"
)

func TestAdapterVendorDoesNotIdentifyRandomizedMAC(t *testing.T) {
	vendor, private := adapterVendor("00:00:0c:12:34:56")
	if private || !strings.Contains(strings.ToLower(vendor), "cisco") {
		t.Fatalf("registered adapter lookup: %q, private=%v", vendor, private)
	}
	for _, address := range []string{"d2:a6:6d:a9:c9:f5", "8e:10:db:d1:ae:9e", "02:4f:8b:ad:de:d8"} {
		vendor, private := adapterVendor(address)
		if vendor != "" || !private {
			t.Fatalf("locally administered address %s must not be assigned a vendor: %q, %v", address, vendor, private)
		}
	}
}

func TestIdentifyUsesEvidenceInsteadOfVendorGuessing(t *testing.T) {
	network := Network{Address: "192.168.1.10", Gateway: "192.168.1.1"}
	tests := []struct {
		name, ip, mac, hostname, kind, evidence string
	}{
		{"local computer", network.Address, "", "", "Computer", "local network interface"},
		{"gateway", network.Gateway, "00:00:0c:12:34:56", "", "Router", "default gateway"},
		{"hostname hint", "192.168.1.20", "", "iPhone.local", "Phone", "unverified"},
		{"vendor alone", "192.168.1.30", "00:00:0c:12:34:56", "", "", ""},
		{"private unknown", "192.168.1.40", "d2:a6:6d:a9:c9:f5", "", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			device := Observation{IP: tt.ip, MAC: tt.mac, Hostname: tt.hostname}
			identify(&device, network)
			if device.Details.Type != tt.kind || !strings.Contains(device.Details.TypeEvidence, tt.evidence) {
				t.Fatalf("incorrect identification: %+v", device.Details)
			}
		})
	}
}

func TestReportedModelSurvivesWeakerOrMissingAdvertisement(t *testing.T) {
	reported := mdnsDetails("Living room._device-info._tcp.local.", []string{"model=Macmini9,1"})
	weak := mdnsDetails("Living room._airplay._tcp.local.", nil)
	merged := MergeDetails(reported, weak)
	if merged.Type != "Computer" || merged.Model != "Macmini9,1" ||
		merged.Manufacturer != "Apple" || merged.ReportedAt != reported.ReportedAt {
		t.Fatalf("weaker report replaced model details: %+v", merged)
	}
}

func TestNetworkIdentitySeparatesProfilesOnSameSubnet(t *testing.T) {
	prefix := netip.MustParsePrefix("192.168.1.10/24")
	home := networkID(18, prefix, "wifi:Home")
	office := networkID(18, prefix, "wifi:Office")
	if home == office {
		t.Fatal("different Wi-Fi profiles must not share inventory")
	}
	if home != networkID(18, netip.MustParsePrefix("192.168.1.20/24"), "wifi:Home") {
		t.Fatal("DHCP address changes must not discard network history")
	}
}

func TestMDNSReportedModelsAndServices(t *testing.T) {
	tests := []struct {
		instance string
		txt      []string
		kind     string
		model    string
		maker    string
	}{
		{"Phone._device-info._tcp.local.", []string{"model=iPhone15,2"}, "Phone", "iPhone15,2", "Apple"},
		{"Office._ipp._tcp.local.", []string{"usb_MFG=Example", "usb_MDL=Laser 100"}, "Printer", "Laser 100", "Example"},
		{"TV._googlecast._tcp.local.", []string{"md=Chromecast", "fn=Living room"}, "Media device", "Chromecast", ""},
		{"Unknown._companion-link._tcp.local.", nil, "", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.instance, func(t *testing.T) {
			details := mdnsDetails(tt.instance, tt.txt)
			if details.Type != tt.kind || details.Model != tt.model || details.Manufacturer != tt.maker {
				t.Fatalf("incorrect mDNS interpretation: %+v", details)
			}
		})
	}
}
