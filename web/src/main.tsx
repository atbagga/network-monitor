import { StrictMode, useCallback, useEffect, useRef, useState } from 'react'
import { createRoot } from 'react-dom/client'
import './style.css'

type Network = {
  id: string; name: string; address: string; cidr: string; scanCidr: string
  profile: string; gateway: string; connected: boolean; lastSeen: string; latestScan: Scan | null
}
type Details = {
  type: string; typeEvidence: string; manufacturer: string; model: string; friendlyName: string
  adapterVendor: string; adapterModel: string; os: string; privateMac: boolean; reportedAt: string; evidence: string[]
}
type Device = {
  id: number; networkId: string; ip: string; mac: string; hostname: string
  name: string; known: boolean; source: string; firstSeen: string; lastSeen: string; scanId: number
  details: Details
}
type Alert = { id: number; deviceId: number; ip: string; name: string; createdAt: string; acknowledged: boolean }
type Scan = {
  id: number; networkId: string; cidr: string; startedAt: string; finishedAt: string
  count: number; warnings: string[]; error: string
}
type Status = { running: boolean; networkId: string; startedAt: string; error: string }
type Settings = { networkId: string; intervalMinutes: number }
type Snapshot = {
  networks: Network[]; devices: Device[]; alerts: Alert[]; scans: Scan[]
  status: Status; settings: Settings
}

async function api<T>(path: string, method = 'GET', body?: unknown): Promise<T> {
  const response = await fetch(`/api/${path}`, {
    method,
    headers: body === undefined ? undefined : { 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
    signal: AbortSignal.timeout(10000),
  })
  if (!response.ok) {
    const data = await response.json().catch(() => null)
    throw new Error(data?.error ?? `Request failed (${response.status})`)
  }
  return response.json() as Promise<T>
}

const date = (value: string) => new Date(value).toLocaleString()

function DeviceRow({ device, latestScan, busy, save }: {
  device: Device; latestScan: number | undefined; busy: boolean
  save: (id: number, name: string, known: boolean) => Promise<void>
}) {
  const [name, setName] = useState(device.name)
  const [known, setKnown] = useState(device.known)
  useEffect(() => { setName(device.name); setKnown(device.known) }, [device.name, device.known])
  const changed = name !== device.name || known !== device.known
  return <tr>
    <td>
      <strong>{device.name || device.details.friendlyName || device.hostname.replace(/\.$/, '') || device.details.manufacturer || device.details.adapterVendor || 'Unidentified device'}</strong>
      <span className="subtext">{device.hostname || 'No hostname available'}</span>
    </td>
    <td className="device-details">
      <strong>{device.details.type || 'Unknown type'}</strong>
      {device.details.typeEvidence && <span className="subtext">{device.details.typeEvidence}</span>}
      <span className="subtext">{device.details.manufacturer ? `Make: ${device.details.manufacturer}` : 'Make: not advertised'}</span>
      <span className="subtext">{device.details.model ? `Model: ${device.details.model}` : 'Model: not advertised'}</span>
      {device.details.os && <span className="subtext">OS: {device.details.os}</span>}
      {device.details.model && device.details.reportedAt && <span className="subtext">Model reported: {date(device.details.reportedAt)}</span>}
    </td>
    <td><code>{device.ip}</code><span className="subtext mono">{device.mac || 'MAC unavailable'}</span>
      {device.details.adapterVendor && <span className="subtext">Adapter: {device.details.adapterVendor}</span>}
      {device.details.adapterModel && <span className="subtext">Card: {device.details.adapterModel}</span>}
      {device.details.privateMac && <span className="subtext amber-text">Private/local MAC: vendor cannot be reliably identified</span>}
    </td>
    <td>
      <span className={`badge ${device.scanId === latestScan ? 'teal' : ''}`}>
        {device.scanId === latestScan ? 'Latest scan' : 'Previously observed'}
      </span>
      <span className="subtext">{device.source}</span>
      {device.details.evidence?.length > 0 && <details className="identification-evidence">
        <summary>Identification evidence</summary>
        {device.details.evidence.map((item) => <span className="subtext" key={item}>{item}</span>)}
      </details>}
    </td>
    <td><span>{date(device.lastSeen)}</span><span className="subtext">First: {date(device.firstSeen)}</span></td>
    <td>
      <form className="device-edit" onSubmit={(event) => {
        event.preventDefault()
        void save(device.id, name, known)
      }}>
        <input aria-label={`Name for ${device.ip}`} value={name} maxLength={120}
          placeholder="Give it a name" onChange={(event) => setName(event.target.value)} />
        <div className="recognition">
          <label><input type="checkbox" checked={known} onChange={(event) => setKnown(event.target.checked)} /> Recognized</label>
          <button className="small secondary" disabled={busy || !changed}>Save</button>
        </div>
      </form>
    </td>
  </tr>
}

function App() {
  const [snapshot, setSnapshot] = useState<Snapshot | null>(null)
  const [networkId, setNetworkId] = useState('')
  const [interval, setIntervalMinutes] = useState(0)
  const [query, setQuery] = useState('')
  const [inventoryMode, setInventoryMode] = useState('auto')
  const [error, setError] = useState('')
  const [connectionError, setConnectionError] = useState('')
  const [busy, setBusy] = useState(false)
  const loading = useRef(false)
  const initialized = useRef(false)
  const refresh = useCallback(async () => {
    if (loading.current) return
    loading.current = true
    try {
      const [networks, devices, alerts, scans, status, settings] = await Promise.all([
        api<Network[]>('networks'), api<Device[]>('devices'), api<Alert[]>('alerts'),
        api<Scan[]>('scans'), api<Status>('status'), api<Settings>('settings'),
      ])
      setSnapshot({ networks, devices, alerts, scans, status, settings })
      setNetworkId((current) => networks.some((network) => network.id === current) ? current
        : (networks.find((network) => network.connected && network.id === settings.networkId)?.id
          ?? networks.find((network) => network.connected)?.id ?? networks[0]?.id ?? ''))
      if (!initialized.current) {
        setIntervalMinutes(settings.intervalMinutes)
        initialized.current = true
      }
      setConnectionError('')
    } catch (reason) {
      setConnectionError(reason instanceof Error ? reason.message : 'Cannot reach the local service.')
    } finally {
      loading.current = false
    }
  }, [])
  useEffect(() => {
    void refresh()
    const timer = window.setInterval(() => { void refresh() }, 3000)
    return () => window.clearInterval(timer)
  }, [refresh])

  async function action(operation: () => Promise<unknown>) {
    if (busy) return
    setBusy(true)
    setError('')
    try {
      await operation()
      await refresh()
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : 'The action failed.')
    } finally {
      setBusy(false)
    }
  }

  const selected = snapshot?.networks.find((network) => network.id === networkId)
  const allDevices = snapshot?.devices.filter((device) => device.networkId === networkId) ?? []
  const latest = selected?.latestScan
  const lastSnapshot = inventoryMode === 'snapshot' || (inventoryMode === 'auto' && selected && !selected.connected)
  const devices = lastSnapshot ? allDevices.filter((device) => device.scanId === latest?.id) : allDevices
  const deviceIDs = new Set(allDevices.map((device) => device.id))
  const alerts = snapshot?.alerts.filter((alert) => !alert.acknowledged && deviceIDs.has(alert.deviceId)) ?? []
  const filtered = devices.filter((device) =>
    [device.name, device.hostname, device.ip, device.mac, device.details.friendlyName,
      device.details.type, device.details.manufacturer, device.details.model, device.details.adapterVendor, device.details.adapterModel]
      .some((value) => (value ?? '').toLowerCase().includes(query.toLowerCase())))
  const networkScans = snapshot?.scans.filter((scan) => scan.networkId === networkId) ?? []
  const schedule = snapshot?.settings
  const scheduledNetwork = snapshot?.networks.find((network) => network.id === schedule?.networkId)
  const running = snapshot?.status.running ?? false

  return <main>
    <header>
      <div className="brand"><div className="brand-icon" aria-hidden="true">N</div><div>NETWORK MONITOR<span>LOCAL NETWORK OBSERVABILITY</span></div></div>
      <span className="badge teal"><span className="dot" /> Local-first / v0.1</span>
    </header>
    <section className="hero">
      <div><p className="eyebrow">KNOW YOUR NETWORK</p><h1>Every device.<br /><span>A clearer picture.</span></h1>
        <p className="intro">Discover devices, recognize what belongs, and keep track of what changes. Your inventory stays on this computer.</p>
      </div>
      <div className="scope-note"><span className="eyebrow">FOUNDATION RELEASE</span>
        <p>IPv4 discovery &amp; device history</p><small>No traffic inspection or automatic blocking. An unfamiliar device is not necessarily a threat.</small>
      </div>
    </section>

    {(error || connectionError) && <div className="notice error" role="alert">{error || connectionError}</div>}
    {!snapshot && !connectionError && <p className="notice" role="status">Connecting to the local service...</p>}

    <section className="panel controls">
      <div className="network-picker">
        <label htmlFor="network">Connected &amp; saved networks</label>
        <select id="network" value={networkId} onChange={(event) => {
          setNetworkId(event.target.value)
          setInventoryMode('auto')
        }} disabled={!snapshot}>
          {!snapshot?.networks.length && <option value="">No connected or saved networks</option>}
          <optgroup label="Connected">
            {snapshot?.networks.filter((network) => network.connected).map((network) => <option key={network.id} value={network.id}>
              {network.profile || network.name} / {network.scanCidr} / Connected
            </option>)}
          </optgroup>
          <optgroup label="Saved history (disconnected)">
            {snapshot?.networks.filter((network) => !network.connected).map((network) => <option key={network.id} value={network.id}>
              {network.profile || network.name} / {network.cidr} / Disconnected
            </option>)}
          </optgroup>
        </select>
        <small>{selected ? (selected.connected
          ? `Probe scope: ${selected.scanCidr}${selected.cidr !== selected.scanCidr ? ` (limited slice of ${selected.cidr})` : ''}`
          : `Saved history / last observed: ${date(selected.lastSeen)}`)
          : 'Connect this computer to a private IPv4 network to discover devices.'}</small>
      </div>
      <button disabled={busy || running || !selected?.connected || !!connectionError}
        onClick={() => { void action(() => api('scans', 'POST', { networkId })) }}>
        {running ? 'Scanning...' : 'Discover devices'}
      </button>
      <div className="schedule">
        <label htmlFor="interval">Periodic discovery</label>
        <div className="inline">
          <select id="interval" value={interval} onChange={(event) => setIntervalMinutes(Number(event.target.value))}>
            <option value={0}>Disabled</option><option value={5}>Every 5 minutes</option>
            <option value={15}>Every 15 minutes</option><option value={60}>Every hour</option>
          </select>
          <button className="secondary" disabled={busy || !snapshot || (interval !== 0 && !selected?.connected) || !!connectionError}
            onClick={() => { void action(() => api('settings', 'PUT', { networkId: interval === 0 ? '' : networkId, intervalMinutes: interval })) }}>Apply</button>
        </div>
        <small>{schedule?.intervalMinutes
          ? `Saved: every ${schedule.intervalMinutes} min on ${scheduledNetwork?.profile || scheduledNetwork?.name || 'unavailable interface'}${scheduledNetwork?.connected ? '' : ' (waiting for reconnection)'}.`
          : 'Saved: automatic scans disabled.'}</small>
      </div>
    </section>
    <p className="scan-help">Scan only networks you own or are authorized to monitor. Each scan probes up to 254 addresses on a /24; larger networks are limited to this computer&apos;s /24 slice.</p>
    {selected && !selected.connected && <div className="notice" role="status">
      Disconnected network: {lastSnapshot ? 'showing its last successful device snapshot' : 'showing its saved device inventory'}
      {latest ? ` from ${date(latest.finishedAt)}` : ' (no successful scan recorded)'}. Reconnect to this network to scan again.
    </div>}
    {running && <div className="notice" role="status">Discovery is running on {snapshot?.networks.find((network) => network.id === snapshot.status.networkId)?.name ?? 'a local interface'}. This can take up to 90 seconds.</div>}
    {snapshot?.status.error && <div className="notice error">Last scan: {snapshot.status.error}</div>}

    <section className="stats">
      <div className="stat"><span>{lastSnapshot ? 'LAST SNAPSHOT' : 'INVENTORY'}</span><strong>{devices.length}</strong><small>{lastSnapshot ? 'Devices in the last successful scan' : 'Devices observed on this network'}</small></div>
      <div className="stat"><span>LATEST SCAN</span><strong>{latest?.count ?? '--'}</strong><small>{latest ? date(latest.finishedAt) : 'No completed scan yet'}</small></div>
      <div className="stat"><span>RECOGNIZED</span><strong>{devices.filter((device) => device.known).length}</strong><small>Labeled by you, not verified safe</small></div>
      <div className="stat"><span>NEW DEVICE ALERTS</span><strong className={alerts.length ? 'amber-text' : ''}>{alerts.length}</strong><small>Unacknowledged in latest 100 alerts</small></div>
    </section>

    <section className="panel">
      <div className="section-heading"><div><h2>{lastSnapshot ? 'Last known device snapshot' : 'Device inventory'}</h2><p>Models are self-reported where available. Adapter vendor alone does not identify a phone or computer.</p></div>
        <div className="inventory-filters">
          <select aria-label="Inventory view" value={lastSnapshot ? 'snapshot' : 'all'} onChange={(event) => setInventoryMode(event.target.value)}>
            <option value="all">All known devices</option><option value="snapshot">Last successful snapshot</option>
          </select>
          <input className="search" aria-label="Search devices" placeholder="Search name, type, make, model..." value={query} onChange={(event) => setQuery(event.target.value)} />
        </div>
      </div>
      <div className="table-scroll"><table>
        <thead><tr><th>DEVICE</th><th>TYPE &amp; DETAILS</th><th>ADDRESSES &amp; ADAPTER</th><th>EVIDENCE</th><th>OBSERVED</th><th>YOUR LABELS</th></tr></thead>
        <tbody>{filtered.map((device) => <DeviceRow key={device.id} device={device} latestScan={latest?.id} busy={busy || !!connectionError}
          save={(id, name, known) => action(() => api(`devices/${id}`, 'PATCH', { name, known }))} />)}</tbody>
      </table></div>
      {filtered.length === 0 && <div className="empty"><strong>{devices.length ? 'No matching devices' : lastSnapshot ? 'No devices in the last successful snapshot' : 'Your network picture starts here'}</strong>
        <p>{devices.length ? 'Try another name, type, make, or address.' : selected && !selected.connected
          ? 'Try All known devices for older observations. Reconnect to refresh discovery.'
          : 'Select a connected network and run discovery. Devices that block probes may not appear.'}</p></div>}
    </section>

    <div className="bottom-grid">
      <section className="panel">
        <div className="section-heading"><div><h2>New-device alerts</h2><p>Informational changes, not malicious-device verdicts.</p></div></div>
        <div className="activity-list">
          {alerts.slice(0, 20).map((alert) => <div className="activity" key={alert.id}>
            <div><strong>{alert.name || alert.ip}</strong><span className="subtext">First discovered / {date(alert.createdAt)}</span></div>
            <button className="small secondary" disabled={busy || !!connectionError} onClick={() => {
              void action(() => api(`alerts/${alert.id}/acknowledge`, 'POST'))
            }}>Acknowledge</button>
          </div>)}
          {!alerts.length && <p className="muted">No pending new-device alerts on this interface.</p>}
          {alerts.length > 20 && <p className="muted">Showing the first 20. Acknowledge these to see more.</p>}
        </div>
      </section>
      <section className="panel">
        <div className="section-heading"><div><h2>Recent discovery</h2><p>Latest 5 scans for this interface.</p></div></div>
        <div className="activity-list">
          {networkScans.slice(0, 5).map((scan) => <div className="scan-item" key={scan.id}>
            <div className="inline spread"><strong>{scan.error ? 'Scan failed' : `${scan.count} devices observed`}</strong><code>{scan.cidr}</code></div>
            <span className="subtext">{date(scan.finishedAt)}</span>
            {scan.error && <p className="amber-text">{scan.error}</p>}
            {scan.warnings.map((warning) => <p className="amber-text" key={warning}>{warning}</p>)}
          </div>)}
          {!networkScans.length && <p className="muted">No scans recorded yet.</p>}
        </div>
      </section>
    </div>
    <footer>LOCAL STORAGE. EXPLICIT SCANS. NO CLOUD REQUIRED.<span>Neighbor-cache entries may be stale. IP and MAC addresses are not proof of identity.</span></footer>
  </main>
}

createRoot(document.getElementById('root')!).render(<StrictMode><App /></StrictMode>)
