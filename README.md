# Network Monitor

A local-first network discovery service with a web dashboard. Built with Go,
React/TypeScript, and SQLite. No cloud account is required to run it.

## Features

- Bounded private IPv4 discovery using ICMP and, on Windows, the neighbor table.
- Persistent inventory, device labels, and new-device alerts.
- Saved networks with their latest successful device snapshot and older inventory.
- Device-type hints, offline MAC adapter-vendor lookup, and self-reported
  mDNS/UPnP make/model details where available.
- Manual scans and optional periodic discovery.

Windows is the primary target. Linux builds support ICMP and mDNS/UPnP discovery,
but do not yet have Windows-equivalent neighbor-table and network-profile support.
The dashboard binds to `127.0.0.1`; remote/mobile access is not enabled.

## Build and run

Requirements: Go 1.26 or newer, Node.js 22.12 or newer, and npm.

On Windows, from the project directory:

```powershell
.\build.ps1
.\run.ps1
```

Open <http://127.0.0.1:8787>. Select a connected network and click
**Discover devices**. Automatic scanning is disabled by default.

To build manually on Windows or Linux:

```text
cd web
npm ci
npm run build
cd ..
go build -trimpath -o network-monitor ./cmd/netmon
```

On Windows, use `-o network-monitor.exe`. The dashboard is embedded in the
executable, so it must be built before running Go tests or building the service.

The default database is `data/monitor.db`, relative to the working directory.
Keep the working directory consistent to reuse your inventory. Use `-data` to
choose an explicit database path, and `-port` to change the dashboard port.

## Development

Run the Go service after building the dashboard:

```text
go run ./cmd/netmon
```

In another terminal, run `npm run dev` from `web`. Vite proxies `/api` requests
to the local Go service.

## Checks and CI

After building the dashboard:

```text
go test ./...
go vet ./...
```

GitHub Actions runs on pushes to `main`, pull requests, and manual dispatch.
Both Windows and Linux jobs type-check/build the dashboard, check Go formatting
and dependency integrity, run Go tests and vet, and build a standalone executable.
Download executables from the workflow run's **Artifacts** section.

The frontend currently has TypeScript/build validation, not a component-test suite.
CI tests use local fixtures rather than scanning the runner's network.

## Limitations and responsible use

Scan only networks you own or are authorized to monitor. Discovery is limited
to private IPv4 subnets of /24 or smaller; larger networks use a bounded /24 slice.
Blocked probes and network isolation can hide devices. Neighbor caches may be
stale. An unknown device is not automatically malicious.

Manufacturer and model details are not guaranteed. MAC vendors identify an
adapter organization, not necessarily the device maker. Locally administered
MAC addresses may be randomized. Advertised descriptions and hostname hints
are not authenticated identity claims. This is a discovery foundation, not
malware detection or an intrusion-prevention system.

## License and data sources

Project code is MIT-licensed. See [LICENSE](LICENSE).
Third-party datasets and dependencies retain their respective terms; see
[THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).
