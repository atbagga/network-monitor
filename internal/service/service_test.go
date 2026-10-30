package service

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"network-monitor/internal/discovery"
	"network-monitor/internal/store"
)

func testService(t *testing.T) (*Service, http.Handler) {
	t.Helper()
	database, err := store.Open(filepath.Join(t.TempDir(), "monitor.db"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := New(ctx, database)
	s.networks = func() ([]discovery.Network, error) {
		return []discovery.Network{{ID: "home", ScanCIDR: "192.168.1.0/24"}}, nil
	}
	t.Cleanup(func() { cancel(); s.Wait(); database.Close() })
	assets := fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte("<html>Dashboard</html>")}}
	return s, s.Handler(assets)
}

func request(handler http.Handler, method, path, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "http://127.0.0.1:8787"+path, strings.NewReader(body))
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	return w
}

func TestRejectsForeignHostsAndOrigins(t *testing.T) {
	_, handler := testService(t)
	tests := []struct{ name, host, origin, site string }{
		{"DNS rebinding", "attacker.example", "", ""},
		{"foreign origin", "127.0.0.1:8787", "https://attacker.example", ""},
		{"null origin", "127.0.0.1:8787", "null", ""},
		{"cross-site", "127.0.0.1:8787", "", "cross-site"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "http://127.0.0.1:8787/api/devices", nil)
			r.Host = tt.host
			r.Header.Set("Origin", tt.origin)
			r.Header.Set("Sec-Fetch-Site", tt.site)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			if w.Code != http.StatusForbidden {
				t.Fatalf("got %d, want forbidden", w.Code)
			}
		})
	}
	r := httptest.NewRequest("GET", "http://127.0.0.1:8787/api/devices", nil)
	r.Header.Set("Origin", "http://127.0.0.1:8787")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != http.StatusOK || strings.TrimSpace(w.Body.String()) != "[]" {
		t.Fatalf("same-origin request failed: %d %s", w.Code, w.Body)
	}
}

func TestRequestsValidateScopeAndPayload(t *testing.T) {
	_, handler := testService(t)
	tests := []struct {
		method, path, body string
		want               int
	}{
		{"POST", "/api/scans", `{"networkId":"arbitrary-public-network"}`, 409},
		{"POST", "/api/scans", `{"networkId":"home","command":"whoami"}`, 400},
		{"POST", "/api/scans", `{"networkId":"home"} {}`, 400},
		{"PATCH", "/api/devices/1", `null`, 400},
		{"PUT", "/api/settings", `[]`, 400},
		{"POST", "/api/scans", `{"networkId":"` + strings.Repeat("x", 5000) + `"}`, 400},
		{"PUT", "/api/settings", `{"networkId":"home","intervalMinutes":1}`, 400},
		{"PUT", "/api/settings", `{"networkId":"foreign","intervalMinutes":5}`, 400},
		{"PUT", "/api/settings", `{"networkId":"home","intervalMinutes":5}`, 200},
		{"PATCH", "/api/devices/1", `{"name":"` + strings.Repeat("x", 121) + `","known":true}`, 400},
		{"PATCH", "/api/devices/1", `{"name":"Laptop","known":true}`, 404},
		{"POST", "/api/alerts/nope/acknowledge", "", 400},
		{"POST", "/api/alerts/123/acknowledge", "", 404},
		{"GET", "/api/unknown", "", 404},
		{"GET", "/", "", 200},
		{"POST", "/", "", 405},
	}
	for _, tt := range tests {
		t.Run(tt.path+tt.body[:min(len(tt.body), 40)], func(t *testing.T) {
			w := request(handler, tt.method, tt.path, tt.body)
			if w.Code != tt.want {
				t.Fatalf("got %d %s, want %d", w.Code, w.Body, tt.want)
			}
		})
	}
	r := httptest.NewRequest("POST", "http://127.0.0.1:8787/api/scans", strings.NewReader(`{"networkId":"home"}`))
	r.Header.Set("Content-Type", "text/plain")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("simple cross-origin form payload was accepted: %d", w.Code)
	}
}

func TestDeviceLabelsAndAlertsThroughAPI(t *testing.T) {
	s, handler := testService(t)
	err := s.store.SaveScan(store.Scan{
		NetworkID: "home", CIDR: "192.168.1.0/24", StartedAt: store.Now(), FinishedAt: store.Now(),
	}, []discovery.Observation{{IP: "192.168.1.10", MAC: "aa:bb:cc:dd:ee:02"}})
	if err != nil {
		t.Fatal(err)
	}
	w := request(handler, "PATCH", "/api/devices/1", `{"name":"My laptop","known":true}`)
	if w.Code != http.StatusOK {
		t.Fatalf("update label: %d %s", w.Code, w.Body)
	}
	w = request(handler, "GET", "/api/devices", "")
	if !strings.Contains(w.Body.String(), `"name":"My laptop","known":true`) {
		t.Fatalf("label not returned: %s", w.Body)
	}
	w = request(handler, "GET", "/api/alerts", "")
	if !strings.Contains(w.Body.String(), `"acknowledged":false`) {
		t.Fatalf("new-device alert not returned: %s", w.Body)
	}
	w = request(handler, "POST", "/api/alerts/1/acknowledge", "")
	if w.Code != http.StatusOK {
		t.Fatalf("acknowledge: %d %s", w.Code, w.Body)
	}
	w = request(handler, "GET", "/api/alerts", "")
	if !strings.Contains(w.Body.String(), `"acknowledged":true`) {
		t.Fatalf("acknowledgment not returned: %s", w.Body)
	}
}

func TestOnlyOneScanRunsAndResultsPersist(t *testing.T) {
	s, handler := testService(t)
	started := make(chan struct{})
	release := make(chan struct{})
	s.scan = func(ctx context.Context, network discovery.Network) (discovery.Result, error) {
		close(started)
		select {
		case <-ctx.Done():
			return discovery.Result{}, ctx.Err()
		case <-release:
			return discovery.Result{Devices: []discovery.Observation{{IP: "192.168.1.1", Source: "test"}}}, nil
		}

	}
	w := request(handler, "POST", "/api/scans", `{"networkId":"home"}`)
	if w.Code != http.StatusAccepted {
		t.Fatalf("start scan: %d %s", w.Code, w.Body)
	}
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("scan did not start")
	}
	if w := request(handler, "POST", "/api/scans", `{"networkId":"home"}`); w.Code != http.StatusConflict {
		t.Fatalf("concurrent scan was accepted: %d", w.Code)
	}
	if w := request(handler, "GET", "/api/status", ""); !strings.Contains(w.Body.String(), `"running":true`) {
		t.Fatalf("running status not published: %s", w.Body)
	}
	close(release)
	s.Wait()
	devices, err := s.store.Devices()
	if err != nil || len(devices) != 1 {
		t.Fatalf("scan did not persist: %v, %v", devices, err)
	}
	if w := request(handler, "GET", "/api/status", ""); strings.Contains(w.Body.String(), `"running":true`) {
		t.Fatalf("running flag not reset: %s", w.Body)
	}
}

func TestNetworkSwitchPreservesHistoryAndDisablesArchivedScanning(t *testing.T) {
	s, handler := testService(t)
	live := []discovery.Network{{ID: "home", Name: "Wi-Fi", Profile: "Home", CIDR: "192.168.1.0/24",
		ScanCIDR: "192.168.1.0/24"}}
	s.networks = func() ([]discovery.Network, error) { return live, nil }
	first := request(handler, "GET", "/api/networks", "")
	if first.Code != http.StatusOK {
		t.Fatal(first.Body.String())
	}
	if err := s.store.SaveScan(store.Scan{NetworkID: "home", CIDR: "192.168.1.0/24",
		StartedAt: store.Now(), FinishedAt: store.Now()},
		[]discovery.Observation{{IP: "192.168.1.1", Details: discovery.Details{Type: "Router", Model: "HomeHub"}}}); err != nil {
		t.Fatal(err)
	}
	live = []discovery.Network{{ID: "office", Name: "Wi-Fi", Profile: "Office", CIDR: "10.0.0.0/24",
		ScanCIDR: "10.0.0.0/24"}}
	w := request(handler, "GET", "/api/networks", "")
	var networks []store.Network
	if err := json.Unmarshal(w.Body.Bytes(), &networks); err != nil {
		t.Fatal(err)
	}
	if len(networks) != 2 {
		t.Fatalf("old network disappeared after Wi-Fi switch: %s", w.Body)
	}
	for _, network := range networks {
		if network.ID == "home" && (network.Connected || network.LatestScan == nil || network.LatestScan.Count != 1) {
			t.Fatalf("incorrect archived network state: %+v", network)
		}
		if network.ID == "office" && !network.Connected {
			t.Fatal("current network must be marked connected")
		}
	}
	w = request(handler, "GET", "/api/devices", "")
	if !strings.Contains(w.Body.String(), `"model":"HomeHub"`) {
		t.Fatalf("archived device details disappeared: %s", w.Body)
	}
	w = request(handler, "POST", "/api/scans", `{"networkId":"home"}`)
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "disconnected") {
		t.Fatalf("archived scan was not rejected: %d %s", w.Code, w.Body)
	}
	w = request(handler, "PUT", "/api/settings", `{"networkId":"home","intervalMinutes":5}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("scheduling a disconnected network was accepted: %d", w.Code)
	}
	w = request(handler, "PUT", "/api/settings", `{"networkId":"home","intervalMinutes":0}`)
	if w.Code != http.StatusOK {
		t.Fatalf("could not disable a disconnected network's schedule: %d %s", w.Code, w.Body)
	}
	live = nil
	w = request(handler, "GET", "/api/networks", "")
	if w.Code != http.StatusOK || strings.Contains(w.Body.String(), `"connected":true`) {
		t.Fatalf("all saved networks should remain visible offline: %d %s", w.Code, w.Body)
	}
	live = []discovery.Network{{ID: "home", Name: "Wi-Fi", Profile: "Home", CIDR: "192.168.1.0/24",
		ScanCIDR: "192.168.1.0/24"}}
	w = request(handler, "GET", "/api/networks", "")
	if err := json.Unmarshal(w.Body.Bytes(), &networks); err != nil || len(networks) != 2 {
		t.Fatalf("reconnection duplicated network history: %s, %v", w.Body, err)
	}
}
