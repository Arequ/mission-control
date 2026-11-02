import { useEffect, useState } from "react";
import { api, type Runner } from "../api";
import { Icon } from "../icons";
import { AutopkgSeg, Empty, Page, StatusPill, Toolbar, enterStyle, match, useSearch, when } from "../ui";

export function RunnersPage() {
  const { q } = useSearch();
  const [runners, setRunners] = useState<Runner[]>([]);
  const [error, setError] = useState("");
  useEffect(() => {
    let stop = false;
    const load = () => {
      api.runners()
        .then((res) => { if (!stop) setRunners(res.runners); })
        .catch((err: Error) => { if (!stop) setError(err.message); });
    };
    load();
    const t = setInterval(load, 4000);
    return () => { stop = true; clearInterval(t); };
  }, []);
  const shown = runners.filter((runner) => match(q, runner.name, runner.hostname, runner.pool_name, runner.labels.join(" "), runner.status));
  const online = runners.filter((runner) => runner.status === "online").length;
  return (
    <Page>
      <Toolbar
        title="Runners"
        lede={`${online} online. mc-runner calls out to lease work. Nothing listens on the Mac.`}
        extra={<AutopkgSeg />}
      />
      <div className="content">
        {error ? <p className="note">{error}</p> : null}
        {shown.length === 0 ? (
          <section className="card"><Empty>{runners.length === 0 ? "No runners registered." : "Nothing matches."}</Empty></section>
        ) : (
          <div className="stack">
            {shown.map((runner, index) => (
              <article key={runner.id} className="card runner enter" style={enterStyle(index)}>
                <span className="ic" style={{ background: runner.status === "online" ? "var(--green-bg)" : "var(--field)", color: runner.status === "online" ? "var(--green)" : "var(--text-2)" }}>
                  <Icon name="server" size={15} />
                </span>
                <div className="body">
                  <div className="name mono">{runner.name}</div>
                  <div className="subline">{runner.hostname} · {runner.autopkg_version}{runner.os_version ? ` · ${runner.os_version}` : ""}</div>
                  <div className="chips">
                    {runner.pool_name ? <span className="chip">{runner.pool_name}</span> : null}
                    {runner.labels.map((label) => <span key={label} className="chip">{label}</span>)}
                  </div>
                </div>
                <div style={{ textAlign: "right" }}>
                  <StatusPill status={runner.status} />
                  <div className="subline">{when(runner.last_heartbeat_at)} · {runner.active_jobs} {runner.active_jobs === 1 ? "job" : "jobs"}</div>
                </div>
              </article>
            ))}
          </div>
        )}
      </div>
    </Page>
  );
}
