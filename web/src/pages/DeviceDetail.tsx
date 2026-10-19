import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api } from "../lib/api";
import type { AppItem, Device, QueryResult } from "../lib/types";
import { ago, displayName, formatBytes, isOnline, osLabel } from "../lib/format";

export function DeviceDetail() {
  const { id } = useParams();
  const [data, setData] = useState<{ device: Device; apps: AppItem[]; results: QueryResult[] } | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    if (!id) return;
    let stop = false;
    api<{ device: Device; apps: AppItem[]; results: QueryResult[] }>(`/api/v1/devices/${id}`)
      .then((payload) => {
        if (!stop) setData(payload);
      })
      .catch((err: Error) => {
        if (!stop) setError(err.message);
      });
    return () => {
      stop = true;
    };
  }, [id]);

  if (error) return <div className="error">{error}</div>;
  if (!data) return <div className="muted">Loading device…</div>;
  const { device, apps, results } = data;

  return (
    <div className="rise stack">
      <Link to="/devices" className="secondary">← Devices</Link>
      <section className="glass hero">
        <div>
          <div className="secondary" style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <span className={`dot ${isOnline(device.lastSeenAt) ? "on" : ""}`} />
            {isOnline(device.lastSeenAt) ? "Online" : "Quiet"} · seen {ago(device.lastSeenAt)}
          </div>
          <h2 style={{ margin: "6px 0 4px", fontSize: 30, letterSpacing: "-0.04em" }}>{displayName(device)}</h2>
          <div className="secondary">{device.hostname} · {device.hardwareSerial || "no serial"}</div>
          <div className="chips" style={{ marginTop: 12 }}>
            {device.labels?.map((label) => <span className="badge" key={label}>{label}</span>)}
            {device.configDrift ? <span className="badge neutral">config drift</span> : <span className="badge good">config current</span>}
          </div>
        </div>
        <div className="secondary" style={{ textAlign: "right" }}>
          <div>{osLabel(device)}</div>
          <div>{device.osBuild}</div>
          <div>osquery {device.osqueryVersion || "—"}</div>
        </div>
      </section>
      <div className="split" style={{ marginTop: 0 }}>
        <section className="glass panel">
          <h3>Hardware</h3>
          <div className="kv">
            <span>Model</span><div>{device.hardwareModel || "—"}</div>
            <span>Vendor</span><div>{device.hardwareVendor || "—"}</div>
            <span>CPU</span><div>{device.cpuBrand || "—"}</div>
            <span>Cores</span><div>{device.cpuPhysicalCores || "—"}</div>
            <span>Memory</span><div>{formatBytes(device.physicalMemory)}</div>
            <span>UUID</span><div className="mono">{device.uuid || "—"}</div>
            <span>Primary user</span><div>{device.primaryUser || "—"}</div>
          </div>
        </section>
        <section className="glass panel">
          <h3>Recent results</h3>
          {results.length === 0 ? <div className="empty">No scheduled results yet.</div> : results.slice(0, 8).map((result) => (
            <div className="list-row" key={`${result.name}-${result.collectedAt}`} style={{ gridTemplateColumns: "1fr auto" }}>
              <div className="mono">{result.name}</div>
              <div className="secondary">{ago(result.collectedAt)}</div>
            </div>
          ))}
        </section>
      </div>
      <section className="glass panel">
        <h3>Applications</h3>
        {apps.length === 0 ? <div className="empty">No applications reported.</div> : apps.map((app) => (
          <div className="list-row" key={`${app.bundleId}-${app.path}-${app.name}`} style={{ gridTemplateColumns: "1.2fr 1fr auto" }}>
            <div>
              <div className="primary">{app.name}</div>
              <div className="secondary mono">{app.bundleId || app.path}</div>
            </div>
            <div className="secondary">{app.path}</div>
            <div>{app.version || "—"}</div>
          </div>
        ))}
      </section>
    </div>
  );
}
