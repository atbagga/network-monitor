package store

import (
	"path/filepath"
	"testing"

	"network-monitor/internal/discovery"
)

func testStore(t *testing.T) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "monitor.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s, path
}

func save(t *testing.T, s *Store, network string, observations ...discovery.Observation) {
	t.Helper()
	if err := s.SaveScan(Scan{NetworkID: network, CIDR: "192.168.1.0/24", StartedAt: Now(),
		FinishedAt: Now(), Warnings: []string{}}, observations); err != nil {
		t.Fatal(err)
	}
}

func TestInventoryIdentityAndAlertLifecycle(t *testing.T) {
	s, path := testStore(t)
	observation := discovery.Observation{IP: "192.168.1.10", Source: "ICMP reply"}
	save(t, s, "home", observation)
	devices, err := s.Devices()
	if err != nil || len(devices) != 1 {
		t.Fatalf("initial inventory: %v, %v", devices, err)
	}
	id := devices[0].ID
	firstSeen := devices[0].FirstSeen
	if found, err := s.UpdateDevice(id, " My laptop ", true); err != nil || !found {
		t.Fatalf("label device: %v, %v", found, err)
	}
	observation.MAC = "AA-BB-CC-DD-EE-02"
	save(t, s, "home", observation)
	observation.IP = "192.168.1.20"
	save(t, s, "home", observation)
	observation.MAC = ""
	save(t, s, "home", observation)
	devices, err = s.Devices()
	if err != nil || len(devices) != 1 {
		t.Fatalf("MAC upgrade/IP change created duplicates: %v, %v", devices, err)
	}
	device := devices[0]
	if device.ID != id || device.FirstSeen != firstSeen || device.Name != "My laptop" ||
		!device.Known || device.IP != observation.IP || device.MAC != "aa:bb:cc:dd:ee:02" {
		t.Fatalf("identity or labels were not preserved: %+v", device)
	}
	alerts, err := s.Alerts()
	if err != nil || len(alerts) != 1 {
		t.Fatalf("expected one new-device alert: %v, %v", alerts, err)
	}
	if found, err := s.Acknowledge(alerts[0].ID); err != nil || !found {
		t.Fatalf("acknowledge alert: %v, %v", found, err)
	}
	if err := s.SaveSettings(Settings{NetworkID: "home", IntervalMinutes: 5}); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	devices, err = reopened.Devices()
	if err != nil || len(devices) != 1 || devices[0].Name != "My laptop" {
		t.Fatalf("inventory did not persist: %v, %v", devices, err)
	}
	alerts, err = reopened.Alerts()
	if err != nil || !alerts[0].Acknowledged {
		t.Fatalf("acknowledgment did not persist: %v, %v", alerts, err)
	}
	settings, err := reopened.Settings()
	if err != nil || settings.IntervalMinutes != 5 || settings.NetworkID != "home" {
		t.Fatalf("settings did not persist: %+v, %v", settings, err)
	}
}

func TestReusedAddressDoesNotInheritRecognition(t *testing.T) {
	s, _ := testStore(t)
	save(t, s, "home", discovery.Observation{IP: "192.168.1.10", MAC: "aa:bb:cc:dd:ee:02"})
	devices, _ := s.Devices()
	s.UpdateDevice(devices[0].ID, "Laptop", true)
	save(t, s, "home", discovery.Observation{IP: "192.168.1.10", MAC: "aa:bb:cc:dd:ee:04"})
	save(t, s, "other-network", discovery.Observation{IP: "192.168.1.10", MAC: "aa:bb:cc:dd:ee:02"})
	devices, err := s.Devices()
	if err != nil || len(devices) != 3 {
		t.Fatalf("expected distinct devices: %v, %v", devices, err)
	}
	for _, device := range devices {
		if device.ID != 1 && (device.Known || device.Name != "") {
			t.Fatalf("new device inherited another device's recognition: %+v", device)
		}
	}
}

func TestFailedAndEmptyScansPreserveInventory(t *testing.T) {
	s, _ := testStore(t)
	save(t, s, "home", discovery.Observation{IP: "192.168.1.10"})
	before, _ := s.Devices()
	save(t, s, "home")
	if err := s.SaveScan(Scan{NetworkID: "home", CIDR: "192.168.1.0/24",
		StartedAt: Now(), FinishedAt: Now(), Error: "cancelled"},
		[]discovery.Observation{{IP: "192.168.1.99"}}); err != nil {
		t.Fatal(err)
	}
	after, err := s.Devices()
	if err != nil || len(after) != 1 || after[0].ScanID != before[0].ScanID || after[0].LastSeen != before[0].LastSeen {
		t.Fatalf("failed/empty scan changed inventory history: %v, %v", after, err)
	}
	scans, err := s.Scans()
	if err != nil || len(scans) != 3 || scans[0].Error != "cancelled" {
		t.Fatalf("expected scan history including failure: %v, %v", scans, err)
	}
}

func TestScanTransactionRollsBackOnInvalidObservation(t *testing.T) {
	s, _ := testStore(t)
	err := s.SaveScan(Scan{NetworkID: "home", StartedAt: Now(), FinishedAt: Now()},
		[]discovery.Observation{{IP: "192.168.1.1"}, {IP: "192.168.1.2", MAC: "invalid"}})
	if err == nil {
		t.Fatal("expected invalid observation to fail")
	}
	devices, _ := s.Devices()
	scans, _ := s.Scans()
	alerts, _ := s.Alerts()
	if len(devices)+len(scans)+len(alerts) != 0 {
		t.Fatal("partial scan was committed")
	}
}

func TestSavedNetworksRetainTheirOwnLatestSnapshot(t *testing.T) {
	s, path := testStore(t)
	home := discovery.Network{ID: "home", Name: "Wi-Fi", Profile: "Home", Address: "192.168.1.10",
		CIDR: "192.168.1.0/24", ScanCIDR: "192.168.1.0/24"}
	if err := s.RememberNetworks([]discovery.Network{home}); err != nil {
		t.Fatal(err)
	}
	save(t, s, home.ID, discovery.Observation{IP: "192.168.1.1"}, discovery.Observation{IP: "192.168.1.2"})
	save(t, s, home.ID, discovery.Observation{IP: "192.168.1.1"})
	// A busy second network must not push the first one's snapshot out of history.
	for i := 0; i < 55; i++ {
		save(t, s, "office", discovery.Observation{IP: "10.0.0.1"})
	}
	if err := s.SaveScan(Scan{NetworkID: home.ID, CIDR: home.CIDR,
		StartedAt: Now(), FinishedAt: Now(), Error: "network disconnected"}, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	networks, err := reopened.Networks()
	if err != nil || len(networks) != 2 {
		t.Fatalf("networks lost after restart: %v, %v", networks, err)
	}
	var saved Network
	for _, network := range networks {
		if network.ID == home.ID {
			saved = network
		}
	}
	if saved.Profile != "Home" || saved.LatestScan == nil || saved.LatestScan.Count != 1 || saved.LatestScan.ID != 2 {
		t.Fatalf("incorrect saved network snapshot: %+v", saved)
	}
	devices, err := reopened.Devices()
	if err != nil {
		t.Fatal(err)
	}
	snapshotCount, historyCount := 0, 0
	for _, device := range devices {
		if device.NetworkID == home.ID {
			historyCount++
			if device.ScanID == saved.LatestScan.ID {
				snapshotCount++
			}
		}
	}
	if snapshotCount != 1 || historyCount != 2 {
		t.Fatalf("snapshot/history mismatch: %d / %d", snapshotCount, historyCount)
	}
	scans, err := reopened.Scans()
	if err != nil {
		t.Fatal(err)
	}
	homeScans := 0
	for _, scan := range scans {
		if scan.NetworkID == home.ID {
			homeScans++
		}
	}
	if homeScans != 3 {
		t.Fatalf("old network scan history was hidden: got %d", homeScans)
	}
}

func TestMigrationRecoversLegacyNetworksWithoutDroppingLabels(t *testing.T) {
	s, path := testStore(t)
	save(t, s, "18:192.168.31.0/24", discovery.Observation{IP: "192.168.31.1"})
	s.UpdateDevice(1, "Original router", true)
	if _, err := s.db.Exec("ALTER TABLE devices DROP COLUMN details; DROP TABLE networks;"); err != nil {
		t.Fatal(err)
	}
	s.Close()
	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	networks, err := reopened.Networks()
	if err != nil || len(networks) != 1 || networks[0].LatestScan == nil {
		t.Fatalf("legacy network was not recovered: %+v, %v", networks, err)
	}
	devices, err := reopened.Devices()
	if err != nil || len(devices) != 1 || devices[0].Name != "Original router" || !devices[0].Known {
		t.Fatalf("legacy device labels were lost: %+v, %v", devices, err)
	}
}

func TestDeviceIdentificationPersistsAcrossScansAndRestart(t *testing.T) {
	s, path := testStore(t)
	device := discovery.Observation{IP: "192.168.1.1", MAC: "aa:bb:cc:dd:ee:02",
		Details: discovery.Details{Type: "Router", TypeEvidence: "UPnP device type (self-reported)",
			Manufacturer: "Example", Model: "HomeHub", ReportedAt: Now(), PrivateMAC: true}}
	save(t, s, "home", device)
	// A later scan can observe the device without receiving its optional advertisements.
	device.Details = discovery.Details{}
	device.MAC = ""
	save(t, s, "home", device)
	s.Close()
	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	devices, err := reopened.Devices()
	if err != nil || len(devices) != 1 || devices[0].Details.Model != "HomeHub" ||
		devices[0].Details.Manufacturer != "Example" || !devices[0].Details.PrivateMAC {
		t.Fatalf("last-known identification was lost: %+v, %v", devices, err)
	}
}
