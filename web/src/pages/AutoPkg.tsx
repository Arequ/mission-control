import { useEffect, useState } from "react";
import { api } from "../lib/api";
import type { Job, Resource, Runner } from "../lib/types";
import { ago } from "../lib/format";

export function AutoPkg() {
  const [pipelines, setPipelines] = useState<Resource[]>([]);
  const [runs, setRuns] = useState<Job[]>([]);
  const [runners, setRunners] = useState<Runner[]>([]);
  const [error, setError] = useState("");

  function load() {
    Promise.all([
      api<{ pipelines: Resource[] }>("/api/v1/autopkg/pipelines"),
      api<{ runs: Job[] }>("/api/v1/autopkg/runs"),
      api<{ runners: Runner[] }>("/api/v1/runners"),
    ]).then(([p, r, n]) => {
      setPipelines(p.pipelines);
      setRuns(r.runs);
      setRunners(n.runners);
    }).catch((err: Error) => setError(err.message));
  }

  useEffect(() => {
    load();
  }, []);

  async function queue(name: string) {
    setError("");
    try {
      await api(`/api/v1/autopkg/pipelines/${name}/runs`, { method: "POST" });
      load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not queue run");
    }
  }

  return (
    <div className="rise">
      <div className="phase">
        The server queues runs. A Mac with <span className="mono">mc-runner</span> claims them and executes autopkg. Trust checks and catalog promotion are phase 3 — this build records the attempt and stops there.
      </div>
      {error ? <div className="error" style={{ marginBottom: 12 }}>{error}</div> : null}
      <div className="split" style={{ marginTop: 0 }}>
        <section className="glass panel">
          <h3>Pipelines</h3>
          {pipelines.map((item) => (
            <div key={item.metadata.name} className="list-row" style={{ gridTemplateColumns: "1fr auto" }}>
              <div>
                <div className="primary">{item.metadata.name}</div>
                <div className="secondary">{String(item.spec.recipe ?? "")} · {String(item.spec.schedule ?? "manual")}</div>
              </div>
              <button className="btn" onClick={() => queue(item.metadata.name)}>Queue</button>
            </div>
          ))}
          {pipelines.length === 0 ? <div className="empty">No pipelines declared.</div> : null}
        </section>
        <section className="glass panel">
          <h3>Runners</h3>
          {runners.length === 0 ? <div className="empty">No runners registered. Create one with POST /api/v1/runners.</div> : runners.map((runner) => (
            <div key={runner.id} className="list-row" style={{ gridTemplateColumns: "1fr auto" }}>
              <div>
                <div className="primary">{runner.name}</div>
                <div className="secondary">{runner.osVersion || "os unknown"} · autopkg {runner.autopkgVersion || "—"}</div>
              </div>
              <div className="secondary">{ago(runner.lastSeenAt)}</div>
            </div>
          ))}
        </section>
      </div>
      <section className="glass panel" style={{ marginTop: 14 }}>
        <h3>Runs</h3>
        {runs.length === 0 ? <div className="empty">No runs yet.</div> : runs.map((run) => (
          <div key={run.id} className="list-row" style={{ gridTemplateColumns: "1fr auto auto" }}>
            <div>
              <div className="primary">{run.pipelineName}</div>
              <div className="secondary mono">{run.id}</div>
            </div>
            <span className={`badge ${run.status === "succeeded" ? "good" : "neutral"}`}>{run.status}</span>
            <div className="secondary">{ago(run.createdAt)}</div>
          </div>
        ))}
      </section>
    </div>
  );
}
