import { useEffect, useState } from "react";
import { api, type Runner } from "../api";
import { Empty, StatusPill, when } from "../ui";

export function RunnersPage() {
  const [runners, setRunners] = useState<Runner[]>([]);
  const [error, setError] = useState("");
  useEffect(() => {
    let stop = false;
    const load = () => {
      api.runners()
        .then((res) => {
          if (!stop) setRunners(res.runners);
        })
        .catch((err: Error) => {
          if (!stop) setError(err.message);
        });
    };
    load();
    const t = setInterval(load, 4000);
    return () => {
      stop = true;
      clearInterval(t);
    };
  }, []);
  return (
    <>
      <h1>Runners</h1>
      <p className="lede">mc-runner processes on Mac hosts. They call out to lease work. Nothing listens on the Mac.</p>
      {error && <p className="lede">{error}</p>}
      <div className="panel">
        {runners.length === 0 ? (
          <Empty>No runners registered.</Empty>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Runner</th>
                <th>Pool</th>
                <th>Labels</th>
                <th>Heartbeat</th>
                <th>Jobs</th>
              </tr>
            </thead>
            <tbody>
              {runners.map((runner) => (
                <tr key={runner.id}>
                  <td>
                    <div className="name">{runner.name}</div>
                    <div className="sub">{runner.hostname} · {runner.autopkg_version}</div>
                  </td>
                  <td className="sub">{runner.pool_name || "—"}</td>
                  <td className="sub">{runner.labels.join(", ") || "—"}</td>
                  <td>
                    <StatusPill status={runner.status} />
                    <div className="sub">{when(runner.last_heartbeat_at)}</div>
                  </td>
                  <td>{runner.active_jobs}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </>
  );
}
