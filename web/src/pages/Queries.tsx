import { FormEvent, useEffect, useState } from "react";
import { api } from "../lib/api";
import type { LiveQuery, Resource } from "../lib/types";

export function Queries() {
  const [resources, setResources] = useState<Resource[]>([]);
  const [sql, setSql] = useState("SELECT hostname, cpu_brand FROM system_info;");
  const [active, setActive] = useState<LiveQuery | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    api<{ resources: Resource[] }>("/api/v1/resources")
      .then((data) => setResources(data.resources.filter((item) => item.kind === "OsqueryPack" || item.kind === "OsqueryQuery" || item.kind === "Label")))
      .catch((err: Error) => setError(err.message));
  }, []);

  useEffect(() => {
    if (!active || active.targets?.every((target) => target.status !== "pending")) return;
    const timer = window.setInterval(() => {
      api<LiveQuery>(`/api/v1/queries/live/${active.id}`).then(setActive).catch(() => undefined);
    }, 2000);
    return () => window.clearInterval(timer);
  }, [active]);

  async function run(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      const created = await api<LiveQuery>("/api/v1/queries/live", {
        method: "POST",
        body: JSON.stringify({ sql }),
      });
      setActive(created);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not start query");
    } finally {
      setBusy(false);
    }
  }

  const packs = resources.filter((item) => item.kind === "OsqueryPack");
  const queries = resources.filter((item) => item.kind === "OsqueryQuery");
  const labels = resources.filter((item) => item.kind === "Label");

  return (
    <div className="rise split" style={{ marginTop: 0 }}>
      <section className="glass panel">
        <h3>Declared in config</h3>
        <p className="secondary">These are read-only here. Change them in git, then <span className="mono">mcctl apply</span>.</p>
        {error ? <div className="error">{error}</div> : null}
        {[...packs, ...queries, ...labels].map((item) => (
          <div key={`${item.kind}-${item.metadata.name}`} className="list-row" style={{ gridTemplateColumns: "1fr auto" }}>
            <div>
              <div className="primary">{item.metadata.name}</div>
              <div className="secondary">{item.kind}</div>
            </div>
            <span className="badge">Managed</span>
          </div>
        ))}
        {resources.length === 0 ? <div className="empty">No query resources applied yet.</div> : null}
      </section>
      <section className="glass panel">
        <h3>Live query</h3>
        <form className="stack" onSubmit={run}>
          <textarea className="field" value={sql} onChange={(event) => setSql(event.target.value)} />
          <button className="btn primary" disabled={busy}>Run on the fleet</button>
        </form>
        {active ? (
          <div style={{ marginTop: 16 }}>
            <div className="secondary mono">{active.id}</div>
            {(active.targets ?? []).map((target) => (
              <div key={target.deviceId} className="list-row" style={{ gridTemplateColumns: "1fr auto" }}>
                <div className="primary">{target.hostname || target.deviceId}</div>
                <span className={`badge ${target.status === "complete" ? "good" : "neutral"}`}>{target.status}</span>
              </div>
            ))}
            {active.targets?.length === 0 ? <div className="empty">No enrolled devices to target.</div> : null}
          </div>
        ) : null}
      </section>
    </div>
  );
}
