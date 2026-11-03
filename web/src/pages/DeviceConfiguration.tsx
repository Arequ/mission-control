import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { api, type KeelDeviceDetail, type KeelResource, type KeelRun } from "../api";
import { RoleChain, Scalar, SettingsTree, SummaryCounts, Warnings, duration } from "../keel";
import { Empty, StatusPill, ago, enterStyle, match, useSearch, when } from "../ui";

// Failed first, then what is about to change, then what changed.
const statusRank: Record<string, number> = { failed: 0, would_change: 1, changed: 2, skipped: 3, ok: 4 };
const statusLabel: Record<string, string> = { failed: "Failed", would_change: "Would change", changed: "Changed", skipped: "Skipped", ok: "OK" };

export function useKeelDevice(serial: string) {
  const [keel, setKeel] = useState<KeelDeviceDetail | null>(null);
  useEffect(() => {
    if (!serial) return;
    let stop = false;
    const load = () => {
      api.keelDevice(serial)
        .then((next) => { if (!stop) setKeel(next); })
        .catch(() => { if (!stop) setKeel(null); });
    };
    load();
    const t = setInterval(load, 30000);
    return () => { stop = true; clearInterval(t); };
  }, [serial]);
  return keel;
}

function chainOf(keel: KeelDeviceDetail) {
  return keel.report?.roles?.map((r) => r.name) ?? keel.last_run?.roles ?? [];
}

function matchOf(keel: KeelDeviceDetail) {
  const roles = keel.report?.roles ?? [];
  return roles.length ? roles[roles.length - 1].match : keel.last_run?.leaf_match;
}

export function KeelCard({ keel, deviceId }: { keel: KeelDeviceDetail; deviceId: string }) {
  const run = keel.last_run;
  return (
    <section className="card enter" style={enterStyle(2)}>
      <div className="card-h">
        <span className="card-t">Configuration</span>
        {run ? <RunPill run={run} stale={keel.stale} /> : <span className="pill gray">Enrolled, no report yet</span>}
        <span className="grow" />
        <Link className="textlink keel-inline-link" to={`/devices/${deviceId}/configuration`}>Details</Link>
      </div>
      <div className="keel-card-body">
        <RoleChain chain={chainOf(keel)} match={matchOf(keel)} />
        {run?.warnings.length ? (
          <p className={`keel-card-warn${run.compile_error ? " hot" : ""}`}>
            {run.compile_error ? "Policy did not compile: " : ""}{run.compile_error ? run.warnings.find((w) => w.startsWith("compile: "))?.slice(9) : `${run.warnings.length} ${run.warnings.length === 1 ? "warning" : "warnings"}: ${run.warnings[0]}`}
          </p>
        ) : null}
        {run ? (
          <div className="keel-card-meta">
            <span>Last run <b>{ago(run.received_at)}</b></span>
            <span>Took <b>{duration(run.duration_ms)}</b></span>
            <span>Keel <b>{run.keel_version || "—"}</b></span>
          </div>
        ) : null}
        {run ? <SummaryCounts summary={run.summary} mode={run.mode} /> : null}
      </div>
    </section>
  );
}

function RunPill({ run, stale }: { run: KeelRun; stale: boolean }) {
  if (stale) return <span className="pill orange">Stale</span>;
  if (run.compile_error) return <span className="pill red">Compile error</span>;
  if (run.summary.failed > 0) return <span className="pill red">{run.summary.failed} failed</span>;
  if (run.mode === "plan" && run.summary.would_change > 0) return <span className="pill orange">{run.summary.would_change} pending</span>;
  return <span className="pill green">Converged</span>;
}

export function DeviceConfiguration({ keel }: { keel: KeelDeviceDetail | null }) {
  const [runs, setRuns] = useState<KeelRun[]>([]);
  useEffect(() => {
    if (!keel) return;
    let stop = false;
    api.keelRuns(keel.serial).then((page) => { if (!stop) setRuns(page.runs); }).catch(() => {});
    return () => { stop = true; };
  }, [keel?.serial, keel?.last_run?.run_id]);

  if (!keel) return <section className="card"><Empty>This Mac has not enrolled with Keel.</Empty></section>;
  const report = keel.report;
  const run = keel.last_run;
  return (
    <>
      <Warnings warnings={report?.warnings ?? run?.warnings} />
      <div className="facts">
        <div className="fact keel-fact-wide">
          <span>Roles</span>
          <b><RoleChain chain={chainOf(keel)} match={matchOf(keel)} /></b>
        </div>
        <div className="fact"><span>Last run</span><b>{run ? ago(run.received_at) : "Never"}</b></div>
        <div className="fact"><span>Mode</span><b>{run ? (run.mode === "plan" ? "Plan" : "Apply") : "—"}</b></div>
        <div className="fact"><span>Duration</span><b>{duration(run?.duration_ms)}</b></div>
      </div>
      {run ? (
        <section className="card enter" style={enterStyle(1)}>
          <div className="card-h">
            <span className="card-t">Last run</span>
            <RunPill run={run} stale={keel.stale} />
            <span className="grow" />
            <span className="faint">{when(run.started_at)} · Keel {run.keel_version || "—"}</span>
          </div>
          <SummaryCounts summary={run.summary} mode={run.mode} />
        </section>
      ) : null}
      {report?.overlays?.length ? (
        <section className="card">
          <div className="card-h"><span className="card-t">Overlays applied</span><span className="faint">{report.overlays.length}</span></div>
          <div className="keel-overlays">
            {report.overlays.map((o) => <div key={o} className="mono-v">{o}</div>)}
          </div>
        </section>
      ) : null}
      {report && !(run?.compile_error && !report.resources?.length) ? <Resources resources={report.resources ?? []} /> : null}
      {report && !(run?.compile_error && !report.profiles?.length) ? <Profiles profiles={report.profiles ?? []} /> : null}
      {report ? <Facts facts={report.facts ?? {}} /> : null}
      {runs.length > 1 ? <History runs={runs} /> : null}
    </>
  );
}

function Resources({ resources }: { resources: KeelResource[] }) {
  const { q } = useSearch();
  const [status, setStatus] = useState("");
  const [profile, setProfile] = useState("");
  const statuses = useMemo(() => {
    const seen = new Map<string, number>();
    for (const r of resources) seen.set(r.status, (seen.get(r.status) ?? 0) + 1);
    return [...seen.entries()].sort((a, b) => (statusRank[a[0]] ?? 9) - (statusRank[b[0]] ?? 9));
  }, [resources]);
  const profiles = useMemo(() => [...new Set(resources.map((r) => r.profile).filter(Boolean))].sort(), [resources]);
  const rows = resources
    .filter((r) => (!status || r.status === status) && (!profile || r.profile === profile))
    .filter((r) => match(q, r.id, r.type, r.profile, r.message))
    .sort((a, b) => (statusRank[a.status] ?? 9) - (statusRank[b.status] ?? 9) || a.id.localeCompare(b.id));
  return (
    <section className="card">
      <div className="card-h">
        <span className="card-t">Resources</span>
        <span className="faint">{rows.length === resources.length ? resources.length : `${rows.length} of ${resources.length}`}</span>
        <span className="grow" />
        <select className="field select" aria-label="Profile" value={profile} onChange={(e) => setProfile(e.target.value)}>
          <option value="">All profiles</option>
          {profiles.map((p) => <option key={p} value={p}>{p}</option>)}
        </select>
      </div>
      <div className="filters keel-filter-row">
        <button type="button" className={`filter${status === "" ? " on" : ""}`} onClick={() => setStatus("")}>All</button>
        {statuses.map(([s, n]) => (
          <button key={s} type="button" className={`filter${status === s ? " on" : ""}`} onClick={() => setStatus(s)}>
            {statusLabel[s] ?? s}<span className="filter-n">{n}</span>
          </button>
        ))}
      </div>
      {rows.length === 0 ? <Empty>No resources match.</Empty> : (
        <>
          <div className="list-h cols-keel-res"><span>Status</span><span>Resource</span><span>Profile</span><span className="right">Time</span></div>
          {rows.map((r) => (
            <div key={r.id} className={`row cols-keel-res keel-res ${r.status}`}>
              <span className="wash" />
              <div><StatusPill status={r.status} /></div>
              <div className="keel-res-id">
                <div className="mono-v">{r.id}</div>
                {r.message ? <div className={`subline keel-msg${r.status === "failed" ? " err" : ""}`}>{r.message}</div> : null}
              </div>
              <div className="muted">{r.profile || "—"}</div>
              <div className="right tnum faint">{duration(r.duration_ms)}</div>
            </div>
          ))}
        </>
      )}
    </section>
  );
}

function Profiles({ profiles }: { profiles: { name: string; enabled: boolean; settings: unknown }[] }) {
  const sorted = [...profiles].sort((a, b) => Number(b.enabled) - Number(a.enabled) || a.name.localeCompare(b.name));
  return (
    <section className="card">
      <div className="card-h">
        <span className="card-t">Effective settings</span>
        <span className="faint">{profiles.filter((p) => p.enabled).length} of {profiles.length} profiles enabled</span>
      </div>
      {sorted.length === 0 ? <Empty>No profiles in this report.</Empty> : sorted.map((p) => (
        <details key={p.name} className="keel-profile" open={p.enabled && sorted.length <= 6}>
          <summary>
            <span className="tree-caret" aria-hidden="true">›</span>
            <span className="name">{p.name}</span>
            {p.enabled ? <span className="pill green">Enabled</span> : <span className="pill gray">Disabled</span>}
          </summary>
          <div className="keel-profile-body"><SettingsTree value={p.settings} /></div>
        </details>
      ))}
    </section>
  );
}

function Facts({ facts }: { facts: Record<string, unknown> }) {
  const keys = Object.keys(facts).sort();
  return (
    <section className="card">
      <div className="card-h"><span className="card-t">Facts</span><span className="faint">{keys.length}</span></div>
      {keys.length === 0 ? <Empty>No facts in this report.</Empty> : (
        <div className="table-wrap">
          <table className="result keel-facts">
            <tbody>
              {keys.map((k) => (
                <tr key={k}>
                  <th scope="row">{k}</th>
                  <td><FactValue value={facts[k]} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

function FactValue({ value }: { value: unknown }) {
  if (Array.isArray(value)) {
    if (value.length === 0) return <span className="faint">none</span>;
    if (value.every((v) => typeof v !== "object" || v === null)) {
      return <span className="tree-list">{value.map((v, i) => (typeof v === "string" && v === "[redacted]" ? <Scalar key={i} value={v} /> : <span key={i} className="chip">{String(v)}</span>))}</span>;
    }
  }
  if (typeof value === "object" && value !== null) return <SettingsTree value={value} depth={1} />;
  return <Scalar value={value} />;
}

function History({ runs }: { runs: KeelRun[] }) {
  return (
    <section className="card">
      <div className="card-h"><span className="card-t">Recent runs</span><span className="faint">{runs.length}</span></div>
      <div className="list-h cols-keel-run"><span>Started</span><span>Mode</span><span className="right">OK</span><span className="right">Changed</span><span className="right">Failed</span><span className="right">Took</span></div>
      {runs.slice(0, 12).map((r) => (
        <div key={r.run_id} className="row cols-keel-run">
          <span className="wash" />
          <div>{when(r.started_at)}</div>
          <div className="muted">{r.mode === "plan" ? "Plan" : "Apply"}</div>
          <div className="right tnum">{r.summary.ok}</div>
          <div className="right tnum">{r.mode === "plan" ? r.summary.would_change : r.summary.changed}</div>
          <div className={`right tnum${r.summary.failed ? " keel-hot" : ""}`}>{r.summary.failed}</div>
          <div className="right tnum faint">{duration(r.duration_ms)}</div>
        </div>
      ))}
    </section>
  );
}
