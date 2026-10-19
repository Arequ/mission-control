import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../lib/api";
import type { FleetSummary } from "../lib/types";
import { ago, displayName, isOnline, osLabel } from "../lib/format";

export function Dashboard() {
  const [summary, setSummary] = useState<FleetSummary | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    let stop = false;
    const load = () => {
      api<FleetSummary>("/api/v1/fleet/summary")
        .then((data) => {
          if (!stop) setSummary(data);
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
  }, []);

  if (error) return <div className="error">{error}</div>;
  if (!summary) return <div className="muted">Loading fleet…</div>;

  const maxOS = Math.max(1, ...summary.osVersions.map((item) => item.count));

  return (
    <div className="rise">
      <div className="stat-grid">
        <Stat k="Devices" v={summary.devices} h="Enrolled endpoints" />
        <Stat k="Online" v={summary.online} h={`${summary.offline} quiet for 30m+`} />
        <Stat k="Config drift" v={summary.configDrift} h="Not on the latest config" />
        <Stat k="Platforms" v={summary.platforms.length} h={summary.platforms.map((p) => p.name).join(", ") || "None yet"} />
      </div>
      <div className="card-grid">
        <section className="glass panel">
          <h3>OS versions</h3>
          {summary.osVersions.length === 0 ? <div className="empty">No inventory yet.</div> : summary.osVersions.map((item) => (
            <div className="bar-row" key={item.name}>
              <div>{item.name}</div>
              <div className="track"><span style={{ width: `${(item.count / maxOS) * 100}%` }} /></div>
              <div className="secondary">{item.count}</div>
            </div>
          ))}
        </section>
        <section className="glass panel">
          <h3>Apps across the fleet</h3>
          {summary.topApps.length === 0 ? <div className="empty">App inventory arrives with the apps query.</div> : summary.topApps.map((app) => (
            <div className="list-row" key={app.name} style={{ gridTemplateColumns: "1fr auto" }}>
              <div className="primary">{app.name}</div>
              <div className="secondary">{app.devices} {app.devices === 1 ? "device" : "devices"}</div>
            </div>
          ))}
        </section>
      </div>
      <section className="glass panel" style={{ marginTop: 14 }}>
        <h3>Recent enrollments</h3>
        {summary.recent.length === 0 ? (
          <div className="empty">
            Enroll an agent with <span className="mono">python3 scripts/simulate_agent.py</span>
          </div>
        ) : summary.recent.map((device) => (
          <Link className="list-row" key={device.id} to={`/devices/${device.id}`} style={{ gridTemplateColumns: "1.4fr 1fr auto" }}>
            <div>
              <div className="primary">{displayName(device)}</div>
              <div className="secondary">{device.hardwareModel || device.hostname}</div>
            </div>
            <div className="secondary">{osLabel(device)}</div>
            <div className="secondary" style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <span className={`dot ${isOnline(device.lastSeenAt) ? "on" : ""}`} />
              {ago(device.enrolledAt)}
            </div>
          </Link>
        ))}
      </section>
    </div>
  );
}

function Stat({ k, v, h }: { k: string; v: number; h: string }) {
  return (
    <div className="glass stat">
      <div className="k">{k}</div>
      <div className="v">{v}</div>
      <div className="h">{h}</div>
    </div>
  );
}
