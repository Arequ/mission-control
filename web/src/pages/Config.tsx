import { useEffect, useState } from "react";
import { api } from "../lib/api";
import type { Resource, SyncStatus } from "../lib/types";
import { ago } from "../lib/format";

export function ConfigPage() {
  const [resources, setResources] = useState<Resource[]>([]);
  const [status, setStatus] = useState<SyncStatus | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    Promise.all([
      api<{ resources: Resource[] }>("/api/v1/resources"),
      api<SyncStatus>("/api/v1/config/status"),
    ]).then(([list, sync]) => {
      setResources(list.resources);
      setStatus(sync);
    }).catch((err: Error) => setError(err.message));
  }, []);

  return (
    <div className="rise">
      <section className="glass panel" style={{ marginBottom: 14 }}>
        <h3>Source</h3>
        <div className="kv">
          <span>Directory</span><div className="mono">{status?.directory || "not configured"}</div>
          <span>Git pull</span><div>{status?.gitPull ? "on" : "off"}</div>
          <span>Last success</span><div>{ago(status?.lastSuccess)}</div>
          <span>Last plan</span>
          <div>
            {status ? `${status.summary.create} create · ${status.summary.update} update · ${status.summary.delete} delete · ${status.summary.unchanged} unchanged` : "—"}
          </div>
        </div>
        {status?.lastError ? <div className="error" style={{ marginTop: 10 }}>{status.lastError}</div> : null}
      </section>
      {error ? <div className="error">{error}</div> : null}
      <section className="glass panel">
        <h3>Resources</h3>
        <div className="table-head" style={{ gridTemplateColumns: "0.9fr 1.1fr 0.5fr 0.7fr 1.2fr" }}>
          <div>Kind</div><div>Name</div><div>Gen</div><div>Owner</div><div>Hash</div>
        </div>
        {resources.map((item) => (
          <div key={`${item.kind}/${item.metadata.name}`} className="table-row" style={{ gridTemplateColumns: "0.9fr 1.1fr 0.5fr 0.7fr 1.2fr" }}>
            <div>{item.kind}</div>
            <div className="primary">{item.metadata.namespace || "default"}/{item.metadata.name}</div>
            <div>{item.status?.generation ?? "—"}</div>
            <div><span className="badge">{item.status?.managedBy === "config" ? "Managed" : item.status?.managedBy || "—"}</span></div>
            <div className="mono secondary">{item.status?.specHash?.slice(0, 12) || "—"}</div>
          </div>
        ))}
        {resources.length === 0 ? <div className="empty">Apply examples/config to see resources here.</div> : null}
      </section>
    </div>
  );
}
