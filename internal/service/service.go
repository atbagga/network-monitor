package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"log"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"network-monitor/internal/discovery"
	"network-monitor/internal/store"
)

type Status struct {
	Running   bool   `json:"running"`
	NetworkID string `json:"networkId"`
	StartedAt string `json:"startedAt"`
	Error     string `json:"error"`
}

type Service struct {
	store       *store.Store
	ctx         context.Context
	mu          sync.Mutex
	status      Status
	lastStarted time.Time
	workers     sync.WaitGroup
	networks    func() ([]discovery.Network, error)
	scan        func(context.Context, discovery.Network) (discovery.Result, error)
}

func New(ctx context.Context, database *store.Store) *Service {
	return &Service{ctx: ctx, store: database, networks: discovery.Networks, scan: discovery.Scan}
}

func (s *Service) Start(networkID string) error {
	networks, err := s.networks()
	if err != nil {
		return err
	}
	var selected *discovery.Network
	for _, network := range networks {
		if network.ID == networkID {
			network := network
			selected = &network
			break
		}
	}
	if selected == nil {
		return errors.New("network is disconnected; reconnect to it before scanning")
	}
	if err := s.store.RememberNetworks([]discovery.Network{*selected}); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ctx.Err() != nil {
		return errors.New("service is shutting down")
	}
	if s.status.Running {
		return errors.New("a scan is already running")
	}
	s.status = Status{Running: true, NetworkID: networkID, StartedAt: store.Now()}
	s.lastStarted = time.Now()
	startedAt := s.status.StartedAt
	s.workers.Add(1)
	go func() {
		defer s.workers.Done()
		ctx, cancel := context.WithTimeout(s.ctx, 90*time.Second)
		defer cancel()
		result, scanErr := s.scan(ctx, *selected)
		scan := store.Scan{
			NetworkID: networkID, CIDR: selected.ScanCIDR, StartedAt: startedAt,
			FinishedAt: store.Now(), Warnings: result.Warnings,
		}
		if scan.Warnings == nil {
			scan.Warnings = []string{}
		}
		if scanErr != nil {
			scan.Error = scanErr.Error()
			result.Devices = nil
		}
		if err := s.store.SaveScan(scan, result.Devices); err != nil {
			scan.Error = "Could not persist scan: " + err.Error()
			log.Print(scan.Error)
		}
		s.mu.Lock()
		s.status.Running = false
		s.status.Error = scan.Error
		s.mu.Unlock()
	}()
	return nil
}

func (s *Service) Networks() ([]store.Network, error) {
	live, err := s.networks()
	if err != nil {
		return nil, err
	}
	if err := s.store.RememberNetworks(live); err != nil {
		return nil, err
	}
	networks, err := s.store.Networks()
	if err != nil {
		return nil, err
	}
	connected := make(map[string]bool, len(live))
	for _, network := range live {
		connected[network.ID] = true
	}
	for index := range networks {
		networks[index].Connected = connected[networks[index].ID]
	}
	return networks, nil
}

func (s *Service) Wait() { s.workers.Wait() }

func (s *Service) RunScheduler() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	var previous store.Settings
	configuredAt := time.Now()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			settings, err := s.store.Settings()
			if err != nil {
				log.Printf("read schedule: %v", err)
				continue
			}
			if settings != previous {
				previous = settings
				configuredAt = time.Now()
			}
			if settings.IntervalMinutes == 0 || settings.NetworkID == "" {
				continue
			}
			s.mu.Lock()
			last := s.lastStarted
			running := s.status.Running
			s.mu.Unlock()
			if configuredAt.After(last) {
				last = configuredAt
			}
			if !running && time.Since(last) >= time.Duration(settings.IntervalMinutes)*time.Minute {
				if err := s.Start(settings.NetworkID); err != nil {
					log.Printf("scheduled scan: %v", err)
					configuredAt = time.Now()
				}
			}
		}
	}
}

func (s *Service) Handler(assets fs.FS) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/health", func(w http.ResponseWriter, r *http.Request) {
		respond(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("GET /api/networks", func(w http.ResponseWriter, r *http.Request) {
		result, err := s.Networks()
		reply(w, result, err)
	})
	mux.HandleFunc("GET /api/devices", func(w http.ResponseWriter, r *http.Request) {
		result, err := s.store.Devices()
		reply(w, result, err)
	})
	mux.HandleFunc("PATCH /api/devices/{id}", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Name  string `json:"name"`
			Known bool   `json:"known"`
		}
		if !decode(w, r, &body) {
			return
		}
		if len(body.Name) > 120 {
			fail(w, http.StatusBadRequest, "Device name must be at most 120 bytes.")
			return
		}
		id, ok := resourceID(w, r)
		if !ok {
			return
		}
		found, err := s.store.UpdateDevice(id, body.Name, body.Known)
		replyChange(w, found, err)
	})
	mux.HandleFunc("GET /api/alerts", func(w http.ResponseWriter, r *http.Request) {
		result, err := s.store.Alerts()
		reply(w, result, err)
	})
	mux.HandleFunc("POST /api/alerts/{id}/acknowledge", func(w http.ResponseWriter, r *http.Request) {
		id, ok := resourceID(w, r)
		if !ok {
			return
		}
		found, err := s.store.Acknowledge(id)
		replyChange(w, found, err)
	})
	mux.HandleFunc("GET /api/scans", func(w http.ResponseWriter, r *http.Request) {
		result, err := s.store.Scans()
		reply(w, result, err)
	})
	mux.HandleFunc("GET /api/status", func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		status := s.status
		s.mu.Unlock()
		respond(w, http.StatusOK, status)
	})
	mux.HandleFunc("POST /api/scans", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			NetworkID string `json:"networkId"`
		}
		if !decode(w, r, &body) {
			return
		}
		if err := s.Start(body.NetworkID); err != nil {
			fail(w, http.StatusConflict, err.Error())
			return
		}
		respond(w, http.StatusAccepted, map[string]string{"status": "started"})
	})
	mux.HandleFunc("GET /api/settings", func(w http.ResponseWriter, r *http.Request) {
		result, err := s.store.Settings()
		reply(w, result, err)
	})
	mux.HandleFunc("PUT /api/settings", func(w http.ResponseWriter, r *http.Request) {
		var settings store.Settings
		if !decode(w, r, &settings) {
			return
		}
		if settings.IntervalMinutes != 0 && settings.IntervalMinutes != 5 &&
			settings.IntervalMinutes != 15 && settings.IntervalMinutes != 60 {
			fail(w, http.StatusBadRequest, "Choose a schedule of 0, 5, 15, or 60 minutes.")
			return
		}
		networks, err := s.networks()
		if err != nil {
			reply(w, nil, err)
			return
		}
		found := false
		for _, network := range networks {
			found = found || network.ID == settings.NetworkID
		}
		if !found && !(settings.NetworkID == "" && settings.IntervalMinutes == 0) {
			if settings.IntervalMinutes == 0 {
				settings.NetworkID = ""
				reply(w, settings, s.store.SaveSettings(settings))
				return
			}
			fail(w, http.StatusBadRequest, "Select an available local network.")
			return
		}
		reply(w, settings, s.store.SaveSettings(settings))
	})
	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		fail(w, http.StatusNotFound, "Unknown API route or unsupported method.")
	})
	files := http.FileServer(http.FS(assets))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			fail(w, http.StatusMethodNotAllowed, "Unsupported method.")
			return
		}
		files.ServeHTTP(w, r)
	})
	return localOnly(mux)
}

func localOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		w.Header().Set("Cache-Control", "no-store")
		host := r.Host
		if parsed, _, err := net.SplitHostPort(host); err == nil {
			host = parsed
		}
		if host != "127.0.0.1" && host != "localhost" && host != "::1" {
			fail(w, http.StatusForbidden, "Only localhost access is supported.")
			return
		}
		if origin := r.Header.Get("Origin"); origin != "" {
			parsed, err := url.Parse(origin)
			if err != nil || parsed.Scheme != "http" || parsed.Host != r.Host {
				fail(w, http.StatusForbidden, "Cross-origin requests are not allowed.")
				return
			}
		}
		if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
			fail(w, http.StatusForbidden, "Cross-site requests are not allowed.")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func decode(w http.ResponseWriter, r *http.Request, body any) bool {
	contentType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || contentType != "application/json" {
		fail(w, http.StatusUnsupportedMediaType, "Expected application/json.")
		return false
	}
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 4096))
	data = bytes.TrimSpace(data)
	if err != nil || len(data) == 0 || data[0] != '{' {
		fail(w, http.StatusBadRequest, "Expected a JSON object of at most 4096 bytes.")
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(body); err != nil {
		fail(w, http.StatusBadRequest, "Invalid JSON request.")
		return false
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		fail(w, http.StatusBadRequest, "Expected one JSON object.")
		return false
	}
	return true
}

func resourceID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id < 1 {
		fail(w, http.StatusBadRequest, "Invalid resource ID.")
		return 0, false
	}
	return id, true
}

func replyChange(w http.ResponseWriter, found bool, err error) {
	if err != nil {
		reply(w, nil, err)
	} else if !found {
		fail(w, http.StatusNotFound, "Resource not found.")
	} else {
		respond(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func reply(w http.ResponseWriter, value any, err error) {
	if err != nil {
		log.Printf("API database error: %v", err)
		fail(w, http.StatusInternalServerError, "Could not read or save local data.")
		return
	}
	respond(w, http.StatusOK, value)
}

func fail(w http.ResponseWriter, status int, message string) {
	respond(w, status, map[string]string{"error": message})
}

func respond(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(value); err != nil && !strings.Contains(err.Error(), "broken pipe") {
		log.Printf("write response: %v", err)
	}
}
