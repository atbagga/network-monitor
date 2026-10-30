package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"network-monitor/internal/discovery"

	_ "modernc.org/sqlite"
)

type Store struct {
	db *sql.DB
	mu sync.Mutex
}

type Device struct {
	ID        int64             `json:"id"`
	NetworkID string            `json:"networkId"`
	IP        string            `json:"ip"`
	MAC       string            `json:"mac"`
	Hostname  string            `json:"hostname"`
	Name      string            `json:"name"`
	Known     bool              `json:"known"`
	Source    string            `json:"source"`
	FirstSeen string            `json:"firstSeen"`
	LastSeen  string            `json:"lastSeen"`
	ScanID    int64             `json:"scanId"`
	Details   discovery.Details `json:"details"`
}

type Network struct {
	discovery.Network
	Connected  bool   `json:"connected"`
	LastSeen   string `json:"lastSeen"`
	LatestScan *Scan  `json:"latestScan"`
}

type Alert struct {
	ID           int64  `json:"id"`
	DeviceID     int64  `json:"deviceId"`
	IP           string `json:"ip"`
	Name         string `json:"name"`
	CreatedAt    string `json:"createdAt"`
	Acknowledged bool   `json:"acknowledged"`
}

type Scan struct {
	ID         int64    `json:"id"`
	NetworkID  string   `json:"networkId"`
	CIDR       string   `json:"cidr"`
	StartedAt  string   `json:"startedAt"`
	FinishedAt string   `json:"finishedAt"`
	Count      int      `json:"count"`
	Warnings   []string `json:"warnings"`
	Error      string   `json:"error"`
}

type Settings struct {
	NetworkID       string `json:"networkId"`
	IntervalMinutes int    `json:"intervalMinutes"`
}

func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	_, err = db.Exec(`
		PRAGMA journal_mode=WAL;
		PRAGMA foreign_keys=ON;
		PRAGMA busy_timeout=5000;
		CREATE TABLE IF NOT EXISTS scans (
			id INTEGER PRIMARY KEY, network_id TEXT NOT NULL, cidr TEXT NOT NULL,
			started_at TEXT NOT NULL, finished_at TEXT NOT NULL,
			count INTEGER NOT NULL, warnings TEXT NOT NULL, error TEXT NOT NULL
		);
		CREATE TABLE IF NOT EXISTS devices (
			id INTEGER PRIMARY KEY, identity TEXT NOT NULL UNIQUE,
			network_id TEXT NOT NULL, ip TEXT NOT NULL, mac TEXT NOT NULL,
			hostname TEXT NOT NULL, name TEXT NOT NULL DEFAULT '',
			known INTEGER NOT NULL DEFAULT 0, source TEXT NOT NULL,
			first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
			scan_id INTEGER NOT NULL REFERENCES scans(id)
		);
		CREATE TABLE IF NOT EXISTS alerts (
			id INTEGER PRIMARY KEY, device_id INTEGER NOT NULL REFERENCES devices(id),
			created_at TEXT NOT NULL, acknowledged INTEGER NOT NULL DEFAULT 0
		);
		CREATE TABLE IF NOT EXISTS settings (
			id INTEGER PRIMARY KEY CHECK(id=1), network_id TEXT NOT NULL,
			interval_minutes INTEGER NOT NULL
		);
		INSERT OR IGNORE INTO settings VALUES (1,'',0);
		CREATE TABLE IF NOT EXISTS networks (
			id TEXT PRIMARY KEY, name TEXT NOT NULL, address TEXT NOT NULL,
			cidr TEXT NOT NULL, scan_cidr TEXT NOT NULL, profile TEXT NOT NULL,
			gateway TEXT NOT NULL, last_seen TEXT NOT NULL
		);
		CREATE INDEX IF NOT EXISTS scans_network_id ON scans(network_id,id);
		INSERT OR IGNORE INTO networks
			SELECT s.network_id,'Saved network','',s.cidr,s.cidr,'','',s.finished_at
			FROM scans s WHERE s.id=(SELECT max(id) FROM scans WHERE network_id=s.network_id);
	`)
	if err != nil {
		db.Close()
		return nil, err
	}
	rows, err := db.Query("PRAGMA table_info(devices)")
	if err != nil {
		db.Close()
		return nil, err
	}
	hasDetails := false
	for rows.Next() {
		var index, notNull, primaryKey int
		var name, columnType string
		var defaultValue any
		if err := rows.Scan(&index, &name, &columnType, &notNull, &defaultValue, &primaryKey); err != nil {
			rows.Close()
			db.Close()
			return nil, err
		}
		hasDetails = hasDetails || name == "details"
	}
	err = rows.Err()
	rows.Close()
	if err == nil && !hasDetails {
		_, err = db.Exec("ALTER TABLE devices ADD COLUMN details TEXT NOT NULL DEFAULT '{}'")
	}
	if err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) SaveScan(scan Scan, observations []discovery.Observation) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`INSERT OR IGNORE INTO networks VALUES (?,?,?,?,?,?,?,?)`,
		scan.NetworkID, "Saved network", "", scan.CIDR, scan.CIDR, "", "", scan.FinishedAt); err != nil {
		return err
	}
	warnings, err := json.Marshal(scan.Warnings)
	if err != nil {
		return err
	}
	result, err := tx.Exec(`INSERT INTO scans (network_id,cidr,started_at,finished_at,count,warnings,error) VALUES (?,?,?,?,?,?,?)`,
		scan.NetworkID, scan.CIDR, scan.StartedAt, scan.FinishedAt, len(observations), string(warnings), scan.Error)
	if err != nil {
		return err
	}
	scanID, err := result.LastInsertId()
	if err != nil {
		return err
	}
	if scan.Error != "" {
		return tx.Commit()
	}
	for _, observation := range observations {
		identity := scan.NetworkID + "|ip:" + observation.IP
		if observation.MAC != "" {
			mac, err := net.ParseMAC(observation.MAC)
			if err != nil {
				return fmt.Errorf("invalid observed MAC: %w", err)
			}
			observation.MAC = mac.String()
			identity = scan.NetworkID + "|mac:" + observation.MAC
		}
		var id int64
		var previousDetails string
		err := tx.QueryRow("SELECT id,details FROM devices WHERE identity=?", identity).Scan(&id, &previousDetails)
		if err == sql.ErrNoRows && observation.MAC != "" {
			// Upgrade an IP-only observation when its MAC becomes available.
			err = tx.QueryRow("SELECT id,details FROM devices WHERE identity=?", scan.NetworkID+"|ip:"+observation.IP).Scan(&id, &previousDetails)
		}
		if err == sql.ErrNoRows && observation.MAC == "" {
			// Without a MAC, reuse only an unambiguous IP match.
			err = tx.QueryRow(`SELECT min(id),details FROM devices WHERE network_id=? AND ip=?
				HAVING count(*)=1`, scan.NetworkID, observation.IP).Scan(&id, &previousDetails)
		}
		if err != nil && err != sql.ErrNoRows {
			return err
		}
		var previous discovery.Details
		if previousDetails != "" {
			if decodeErr := json.Unmarshal([]byte(previousDetails), &previous); decodeErr != nil {
				return decodeErr
			}
			if observation.MAC == "" {
				observation.Details.PrivateMAC = previous.PrivateMAC
			}
		}
		details, marshalErr := json.Marshal(discovery.MergeDetails(previous, observation.Details))
		if marshalErr != nil {
			return marshalErr
		}
		if err == sql.ErrNoRows {
			result, err := tx.Exec(`INSERT INTO devices
				(identity,network_id,ip,mac,hostname,source,first_seen,last_seen,scan_id,details)
				VALUES (?,?,?,?,?,?,?,?,?,?)`, identity, scan.NetworkID, observation.IP,
				observation.MAC, observation.Hostname, observation.Source, scan.FinishedAt, scan.FinishedAt, scanID, string(details))
			if err != nil {
				return err
			}
			id, err = result.LastInsertId()
			if err != nil {
				return err
			}
			if _, err := tx.Exec("INSERT INTO alerts (device_id,created_at) VALUES (?,?)", id, scan.FinishedAt); err != nil {
				return err
			}
		} else {
			_, err := tx.Exec(`UPDATE devices SET
				identity=CASE WHEN ?='' THEN identity ELSE ? END,
				ip=?,mac=CASE WHEN ?='' THEN mac ELSE ? END,
				hostname=CASE WHEN ?='' THEN hostname ELSE ? END,
				source=?,last_seen=?,scan_id=?,details=? WHERE id=?`,
				observation.MAC, identity, observation.IP, observation.MAC, observation.MAC,
				observation.Hostname, observation.Hostname, observation.Source, scan.FinishedAt, scanID, string(details), id)
			if err != nil {
				return err
			}
		}
	}
	return tx.Commit()
}

func (s *Store) Devices() ([]Device, error) {
	rows, err := s.db.Query(`SELECT id,network_id,ip,mac,hostname,name,known,source,first_seen,last_seen,scan_id,details
		FROM devices ORDER BY last_seen DESC,id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	devices := make([]Device, 0)
	for rows.Next() {
		var d Device
		var details string
		if err := rows.Scan(&d.ID, &d.NetworkID, &d.IP, &d.MAC, &d.Hostname, &d.Name, &d.Known,
			&d.Source, &d.FirstSeen, &d.LastSeen, &d.ScanID, &details); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(details), &d.Details); err != nil {
			return nil, err
		}
		devices = append(devices, d)
	}
	return devices, rows.Err()
}

func (s *Store) UpdateDevice(id int64, name string, known bool) (bool, error) {
	result, err := s.db.Exec("UPDATE devices SET name=?,known=? WHERE id=?", strings.TrimSpace(name), known, id)
	return changed(result, err)
}

func (s *Store) Alerts() ([]Alert, error) {
	rows, err := s.db.Query(`SELECT a.id,a.device_id,d.ip,
		CASE WHEN d.name='' THEN d.hostname ELSE d.name END,a.created_at,a.acknowledged
		FROM alerts a JOIN devices d ON a.device_id=d.id ORDER BY a.id DESC LIMIT 100`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	alerts := make([]Alert, 0)
	for rows.Next() {
		var a Alert
		if err := rows.Scan(&a.ID, &a.DeviceID, &a.IP, &a.Name, &a.CreatedAt, &a.Acknowledged); err != nil {
			return nil, err
		}
		alerts = append(alerts, a)
	}
	return alerts, rows.Err()
}

func (s *Store) Acknowledge(id int64) (bool, error) {
	result, err := s.db.Exec("UPDATE alerts SET acknowledged=1 WHERE id=?", id)
	return changed(result, err)
}

func changed(result sql.Result, err error) (bool, error) {
	if err != nil {
		return false, err
	}
	count, err := result.RowsAffected()
	return count > 0, err
}

func (s *Store) Scans() ([]Scan, error) {
	rows, err := s.db.Query(`SELECT id,network_id,cidr,started_at,finished_at,count,warnings,error
		FROM scans WHERE id IN
			(SELECT id FROM (SELECT id,row_number() OVER (PARTITION BY network_id ORDER BY id DESC) position FROM scans)
			 WHERE position<=5)
		ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	scans := make([]Scan, 0)
	for rows.Next() {
		var scan Scan
		var warnings string
		if err := rows.Scan(&scan.ID, &scan.NetworkID, &scan.CIDR, &scan.StartedAt,
			&scan.FinishedAt, &scan.Count, &warnings, &scan.Error); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(warnings), &scan.Warnings); err != nil {
			return nil, err
		}
		scans = append(scans, scan)
	}
	return scans, rows.Err()
}

func (s *Store) RememberNetworks(networks []discovery.Network) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	observedAt := Now()
	for _, network := range networks {
		_, err := tx.Exec(`INSERT INTO networks VALUES (?,?,?,?,?,?,?,?)
			ON CONFLICT(id) DO UPDATE SET name=excluded.name,address=excluded.address,
			cidr=excluded.cidr,scan_cidr=excluded.scan_cidr,profile=excluded.profile,
			gateway=excluded.gateway,last_seen=excluded.last_seen`, network.ID, network.Name,
			network.Address, network.CIDR, network.ScanCIDR, network.Profile, network.Gateway, observedAt)
		if err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) Networks() ([]Network, error) {
	rows, err := s.db.Query(`SELECT n.id,n.name,n.address,n.cidr,n.scan_cidr,n.profile,n.gateway,n.last_seen,
		s.id,s.cidr,s.started_at,s.finished_at,s.count,s.warnings
		FROM networks n LEFT JOIN scans s
		ON s.id=(SELECT max(id) FROM scans WHERE network_id=n.id AND error='')
		ORDER BY n.last_seen DESC,n.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	networks := make([]Network, 0)
	for rows.Next() {
		var network Network
		var scanID, count sql.NullInt64
		var cidr, started, finished, warnings sql.NullString
		if err := rows.Scan(&network.ID, &network.Name, &network.Address, &network.CIDR, &network.ScanCIDR,
			&network.Profile, &network.Gateway, &network.LastSeen, &scanID, &cidr, &started,
			&finished, &count, &warnings); err != nil {
			return nil, err
		}
		if scanID.Valid {
			scan := &Scan{ID: scanID.Int64, NetworkID: network.ID, CIDR: cidr.String,
				StartedAt: started.String, FinishedAt: finished.String, Count: int(count.Int64)}
			if err := json.Unmarshal([]byte(warnings.String), &scan.Warnings); err != nil {
				return nil, err
			}
			network.LatestScan = scan
		}
		networks = append(networks, network)
	}
	return networks, rows.Err()
}

func (s *Store) Settings() (Settings, error) {
	var settings Settings
	err := s.db.QueryRow("SELECT network_id,interval_minutes FROM settings WHERE id=1").
		Scan(&settings.NetworkID, &settings.IntervalMinutes)
	return settings, err
}

func (s *Store) SaveSettings(settings Settings) error {
	_, err := s.db.Exec("UPDATE settings SET network_id=?,interval_minutes=? WHERE id=1",
		settings.NetworkID, settings.IntervalMinutes)
	return err
}

func Now() string { return time.Now().UTC().Format(time.RFC3339Nano) }
