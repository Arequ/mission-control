import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../lib/api";
import type { Device } from "../lib/types";
import { ago, displayName, isOnline, osLabel } from "../lib/format";

export function Devices() {
  const [query, setQuery] = useState("");
  const [devices, setDevices] = useState<Device[] | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    let stop = false;
    const load = () => {
      const path = query.trim() ? `/api/v1/devices?q=${encodeURIComponent(query.trim())}` : "/api/v1/devices";
      api<{ devices: Device[] }>(path)
        .then((data) => {
          if (!stop) setDevices(data.devices);
        })
        .catch((err: Error) => {
          if (!stop) setError(err.message);
        });
    };
    load();
    const timer = window.setInterval(load, 8000);
    return () => {
      stop = true;
      window.clearInterval(timer);
    };
  }, [query]);

  return (
    <div className="rise">
      <div style={{ display: "flex", justifyContent: "flex-end", marginBottom: 12 }}>
        <input className="search" placeholder="Search name, serial, user" value={query} onChange={(event) => setQuery(event.target.value)} />
      </div>
      <section className="glass panel">
        {error ? <div className="error">{error}</div> : null}
        <div className="table-head">
          <div>Device</div><div>User</div><div>OS</div><div>Model</div><div>Labels</div><div>Seen</div>
        </div>
        {devices && devices.length === 0 ? (
          <div className="empty">No devices match. Enroll one with the simulate script or a real osquery agent.</div>
        ) : null}
        {devices?.map((device) => (
          <Link key={device.id} to={`/devices/${device.id}`} className="table-row">
            <div>
              <div className="primary">{displayName(device)}</div>
              <div className="secondary">{device.hardwareSerial || device.hostname}</div>
            </div>
            <div>{device.primaryUser || "—"}</div>
            <div>{osLabel(device)}</div>
            <div className="secondary">{device.hardwareModel || "—"}</div>
            <div className="chips">
              {device.labels?.length ? device.labels.map((label) => <span className="badge" key={label}>{label}</span>) : <span className="secondary">—</span>}
              {device.configDrift ? <span className="badge neutral">drift</span> : null}
            </div>
            <div className="secondary" style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <span className={`dot ${isOnline(device.lastSeenAt) ? "on" : ""}`} />
              {ago(device.lastSeenAt)}
            </div>
          </Link>
        ))}
      </section>
    </div>
  );
}
