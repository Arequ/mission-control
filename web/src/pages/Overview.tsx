import { useEffect, useState, type CSSProperties } from "react";
import { Link } from "react-router-dom";
import { api, type FleetSummary } from "../api";
import { Page, StatusPill, Toolbar, ago, enterStyle } from "../ui";

export function OverviewPage() {
  const [summary, setSummary] = useState<FleetSummary | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    let stop = false;
    const load = () => {
      api.summary()
        .then((next) => { if (!stop) { setSummary(next); setError(""); } })
        .catch((err: Error) => { if (!stop) setError(err.message); });
    };
    load();
    const t = setInterval(load, 8000);
    return () => { stop = true; clearInterval(t); };
  }, []);

  const versions = summary?.macos_versions ?? [];
  const max = Math.max(1, ...versions.map((v) => v.count));
  const onlinePct = summary && summary.total_devices
    ? Math.round((summary.online_devices / summary.total_devices) * 1000) / 10
    : 0;

  return (
    <Page>
      <Toolbar
        title="Overview"
        lede={summary ? `${summary.total_devices.toLocaleString()} devices` : "Fleet inventory"}
      />
      <div className="content fleet">
        {error ? <p className="note">{error}</p> : null}
        <div className="kpis">
          <section className="card kpi enter" style={enterStyle(0)}>
            <div className="kpi-k">Total devices</div>
            <div className="kpi-n tnum">{summary ? summary.total_devices.toLocaleString() : "—"}</div>
            <div className="kpi-s">
              {summary ? `${summary.enrolled_this_week} enrolled this week` : "Waiting for inventory"}
            </div>
          </section>
          <section className="card kpi enter" style={enterStyle(1)}>
            <div className="kpi-k">Online</div>
            <div className="kpi-n tnum">{summary ? summary.online_devices.toLocaleString() : "—"}</div>
            <div className="kpi-s">{summary ? `${onlinePct}% checked in` : "—"}</div>
          </section>
          <section className="card kpi enter" style={enterStyle(2)}>
            <div className="kpi-k">macOS</div>
            {versions.length === 0 ? <div className="kpi-s">No Macs enrolled yet</div> : (
              <div className="vers">
                {versions.slice(0, 5).map((v) => (
                  <div className="ver" key={v.version}>
                    <div>
                      <div className="name">{v.name || "macOS"} {v.version}</div>
                    </div>
                    <div className="bar os" style={{ "--p": v.count / max } as CSSProperties}><i /></div>
                    <span className="tnum faint">{v.count}</span>
                  </div>
                ))}
              </div>
            )}
          </section>
          <section className="card kpi enter" style={enterStyle(3)}>
            <div className="kpi-k">AutoPKG</div>
            <div className="kpi-n tnum">{summary ? summary.autopkg.enabled : "—"}</div>
            <div className="kpi-s">
              {summary
                ? `${summary.autopkg.enabled} of ${summary.autopkg.recipes} recipes enabled`
                : "—"}
            </div>
            {summary?.autopkg.last_recipe ? (
              <div className="kpi-last">
                <StatusPill result={summary.autopkg.last_result} />
                <span className="faint">{summary.autopkg.last_recipe}</span>
                <span className="faint">{ago(summary.autopkg.last_finished_at)}</span>
              </div>
            ) : null}
            <Link className="textlink" to="/autopkg">Open AutoPKG</Link>
          </section>
        </div>
      </div>
    </Page>
  );
}
