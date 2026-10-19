import { FormEvent, useEffect, useState } from "react";
import { Link, NavLink, useParams } from "react-router-dom";
import {
  api,
  type AffectedDevice,
  type IssueEvent,
  type IssueFix,
  type VulnerabilityDetail,
  type VulnerabilityIssue,
  type VulnerabilitySummary,
} from "../api";
import { Icon } from "../icons";
import { Empty, Page, Toolbar, ago, enterStyle, useSearch } from "../ui";

const severities = ["critical", "high", "medium", "low"] as const;
const statuses = [
  ["open", "Open"],
  ["in_progress", "In progress"],
  ["risk_accepted", "Risk accepted"],
  ["fixed", "Fixed"],
] as const;

export function VulnerabilitiesPage() {
  const { id = "" } = useParams();
  const { q } = useSearch();
  const [kev, setKev] = useState(false);
  const [severity, setSeverity] = useState("");
  const [status, setStatus] = useState("");
  const [hasFix, setHasFix] = useState(false);
  const [data, setData] = useState<{ issues: VulnerabilityIssue[]; summary: VulnerabilitySummary; total: number } | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    let stop = false;
    const load = () => {
      api.vulnerabilityIssues({
        kev: kev ? true : undefined,
        severity,
        status,
        hasFix: hasFix ? true : undefined,
        active: status === "" || status !== "fixed",
        q,
        limit: 200,
      })
        .then((next) => { if (!stop) { setData(next); setError(""); } })
        .catch((err: Error) => { if (!stop) setError(err.message); });
    };
    load();
    const t = setInterval(load, 8000);
    return () => { stop = true; clearInterval(t); };
  }, [kev, severity, status, hasFix, q]);

  const summary = data?.summary;
  return (
    <Page>
      <Toolbar
        title="Vulnerabilities"
        lede="Installed software matched to NVD, CISA KEV, EPSS, and Apple security releases."
      />
      <div className="content fleet vuln-page">
        {error ? <p className="note">{error}</p> : null}
        <div className="vuln-stats">
          <Stat k="Open" v={summary ? String(summary.open) : "—"} note={summary ? `${summary.opened_this_week} opened this week` : "Loading"} />
          <Stat k="CISA KEV" v={summary ? String(summary.kev) : "—"} hot note={summary ? `affecting ${summary.kev_devices} devices` : ""} />
          <Stat k="Fix in Munki" v={percent(summary?.with_fix, summary?.open)} note={summary ? `${summary.with_fix} of ${summary.open} open` : ""} />
          <Stat k="Within SLA" v={percent(summary?.within_sla, summary?.open)} note={summary ? `${summary.due_this_week} due this week` : ""} warn={!!summary && summary.due_this_week > 0} />
        </div>
        <div className="filters">
          <Filter on={!kev && !severity && !status && !hasFix} onClick={() => { setKev(false); setSeverity(""); setStatus(""); setHasFix(false); }}>Open</Filter>
          <Filter on={kev} onClick={() => setKev((v) => !v)}>KEV</Filter>
          <Filter on={hasFix} onClick={() => setHasFix((v) => !v)}>Fix in Munki</Filter>
          {severities.map((item) => (
            <Filter key={item} on={severity === item} onClick={() => setSeverity(severity === item ? "" : item)}>{label(item)}</Filter>
          ))}
          {statuses.map(([value, text]) => (
            <Filter key={value} on={status === value} onClick={() => setStatus(status === value ? "" : value)}>{text}</Filter>
          ))}
        </div>
        <div className={id ? "vuln-split" : "vuln-split solo"}>
          <section className="card vuln-list">
            <div className="card-h">
              <span className="card-t">{status === "fixed" ? "Fixed issues" : "Open issues"}</span>
              <span className="faint">sorted by KEV, EPSS, CVSS, then devices</span>
            </div>
            {!data && !error ? <Empty>Loading issues.</Empty> : null}
            {data && data.issues.length === 0 ? <Empty>Nothing matches this filter.</Empty> : null}
            {data && data.issues.length > 0 ? (
              <div className="vuln-rows">
                <div className="vuln-h">
                  <span>CVE</span><span>CVSS</span><span>EPSS</span><span>Software</span><span className="right">Devices</span><span>Fix</span><span>Status</span>
                </div>
                {data.issues.map((issue, index) => (
                  <IssueRow key={issue.id} issue={issue} index={index} selected={issue.id === id} />
                ))}
              </div>
            ) : null}
          </section>
          {id ? <IssueDetail id={id} /> : null}
        </div>
      </div>
    </Page>
  );
}

export function DeviceVulnerabilities({ id }: { id: string }) {
  const [issues, setIssues] = useState<VulnerabilityIssue[] | null>(null);
  const [error, setError] = useState("");
  useEffect(() => {
    let stop = false;
    const load = () => {
      api.deviceVulnerabilities(id)
        .then((next) => { if (!stop) { setIssues(next.issues); setError(""); } })
        .catch((err: Error) => { if (!stop) setError(err.message); });
    };
    load();
    const t = setInterval(load, 8000);
    return () => { stop = true; clearInterval(t); };
  }, [id]);
  return (
    <section className="card vuln-device enter" style={enterStyle(1)}>
      <div className="card-h">
        <span className="card-t">Vulnerabilities</span>
        <span className="faint">{issues ? `${issues.length} still match this Mac` : ""}</span>
      </div>
      {error ? <p className="note">{error}</p> : null}
      {!issues && !error ? <Empty>Loading vulnerabilities.</Empty> : null}
      {issues && issues.length === 0 ? <Empty>No active vulnerabilities on this Mac.</Empty> : null}
      {issues?.map((issue) => (
        <Link key={issue.id} className="row vuln-device-row" to={`/vulnerabilities/${issue.id}`}>
          <span className="wash" />
          <span className="who">
            <AppMark name={issue.software_name} />
            <span className="id">
              <span className="name">{issue.cve_id}{issue.kev ? <Kev /> : null}</span>
              <span className="subline">{issue.software_name}</span>
            </span>
          </span>
          <Score score={issue.cvss_score} />
          <StatusPill status={issue.status} />
          <span className="subline">{fixShort(issue.fix)}</span>
        </Link>
      ))}
    </section>
  );
}

function IssueRow({ issue, index, selected }: { issue: VulnerabilityIssue; index: number; selected: boolean }) {
  return (
    <NavLink
      to={`/vulnerabilities/${issue.id}`}
      className={`vuln-row enter${selected ? " on" : ""}`}
      style={enterStyle(index)}
      aria-current={selected ? "true" : undefined}
    >
      <span className="vuln-cve">
        <span className="mono name">{issue.cve_id}{issue.kev ? <Kev /> : null}</span>
        <span className="subline">{issue.description}</span>
      </span>
      <Score score={issue.cvss_score} />
      <Epss issue={issue} />
      <span className="who">
        <AppMark name={issue.software_name} />
        <span className="id">
          <span className="name">{issue.software_name || "Software"}</span>
          <span className="subline mono">{boundText(issue.fix)}</span>
        </span>
      </span>
      <span className="right tnum name">{issue.device_count}</span>
      <FixPill fix={issue.fix} />
      <StatusPill status={issue.status} />
    </NavLink>
  );
}

function IssueDetail({ id }: { id: string }) {
  const [issue, setIssue] = useState<VulnerabilityDetail | null>(null);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState(false);
  const load = () => {
    api.vulnerabilityIssue(id)
      .then((next) => { setIssue(next); setError(""); })
      .catch((err: Error) => setError(err.message));
  };
  useEffect(() => {
    let stop = false;
    const tick = () => {
      api.vulnerabilityIssue(id)
        .then((next) => { if (!stop) { setIssue(next); setError(""); } })
        .catch((err: Error) => { if (!stop) setError(err.message); });
    };
    tick();
    const t = setInterval(tick, 8000);
    return () => { stop = true; clearInterval(t); };
  }, [id]);

  const run = () => {
    setBusy(true);
    setNotice("");
    api.runVulnerabilityRecipe(id)
      .then(() => { setNotice("Recipe queued."); load(); })
      .catch((err: Error) => setNotice(err.message))
      .finally(() => setBusy(false));
  };

  return (
    <aside className="card vuln-detail" aria-label="Issue">
      <div className="vuln-detail-h">
        {issue ? (
          <>
            <div className="vuln-idline">
              <span className="mono name">{issue.cve_id}</span>
              {issue.kev ? <Kev /> : null}
              <Score score={issue.cvss_score} />
              <span className="pill gray">{epssLabel(issue)}</span>
              <NavLink className="vuln-close" to="/vulnerabilities" aria-label="Close issue"><Icon name="x" size={16} /></NavLink>
            </div>
            <h2>{titleFrom(issue)}</h2>
            <p className="sub">{issue.device_count} devices · {evidenceLine(issue)}{issue.source === "fixture" ? " · fixture ranges until a feed sync replaces them" : ""}</p>
          </>
        ) : <div className="sub">{error || "Loading issue."}</div>}
      </div>
      {issue ? (
        <>
          <FixCard issue={issue} busy={busy} notice={notice} onRun={run} />
          <WorkForm issue={issue} onSaved={() => { setNotice(""); load(); }} />
          <div className="vuln-block">
            <div className="sec">Affected devices</div>
            {issue.devices.length === 0 ? <p className="sub">No device still matches.</p> : issue.devices.slice(0, 8).map((device) => (
              <DeviceLine key={device.id} device={device} />
            ))}
            {issue.devices.length > 8 ? <p className="sub">{issue.devices.length - 8} more on this issue.</p> : null}
          </div>
          <div className="vuln-block">
            <div className="sec">Activity</div>
            {(issue.events ?? []).length === 0 ? <p className="sub">No timeline yet.</p> : issue.events.map((event) => (
              <div key={event.id} className="vuln-event">
                <span><b>{event.actor || "system"}</b> {eventText(event)}</span>
                <span className="faint">{ago(event.at)}</span>
              </div>
            ))}
          </div>
        </>
      ) : null}
    </aside>
  );
}

function FixCard({ issue, busy, notice, onRun }: { issue: VulnerabilityDetail; busy: boolean; notice: string; onRun: () => void }) {
  const fix = issue.fix;
  return (
    <div className="fix-card">
      <div className="who">
        <AppMark name={issue.software_name} large />
        <div>
          <div className="name">{fixHeadline(issue)}</div>
          <div className="sub">{fixDetail(fix)}</div>
        </div>
      </div>
      {fix.action === "promote" || fix.action === "require_install" ? <FixSteps action={fix.action} /> : null}
      <div className="fix-actions">
        {fix.pr_url ? (
          <a className="capsule primary" href={fix.pr_url} target="_blank" rel="noreferrer">
            <Icon name="pr" size={14} />{prLabel(fix.action)}
          </a>
        ) : null}
        {fix.action === "run_recipe" ? (
          <button className="capsule primary" type="button" disabled={busy} onClick={onRun}>
            <Icon name="play" size={14} />{busy ? "Queuing" : "Run recipe now"}
          </button>
        ) : null}
        {fix.action === "recipe_pending" ? <span className="pill blue">Recipe queued</span> : null}
        {fix.action === "unmanaged" ? <span className="pill gray">No managed fix</span> : null}
      </div>
      {fix.pr_url ? <p className="faint fix-note"><Icon name="pr" size={12} /> Opens a pull request on Arequ/terraform-mission-control. This does not change the catalog.</p> : null}
      {notice ? <p className="sub">{notice}</p> : null}
    </div>
  );
}

function FixSteps({ action }: { action: string }) {
  const production = action === "require_install";
  return (
    <div className="fix-steps" aria-hidden="true">
      <span className="step done">AutoPKG</span>
      <i className="step-line done" />
      <span className={`step${production ? " done" : " now"}`}>Testing</span>
      <i className={`step-line${production ? " done" : ""}`} />
      <span className={`step${production ? " now" : ""}`}>Production</span>
    </div>
  );
}

function WorkForm({ issue, onSaved }: { issue: VulnerabilityDetail; onSaved: () => void }) {
  const [status, setStatus] = useState(issue.status);
  const [assignee, setAssignee] = useState(issue.assignee);
  const [notes, setNotes] = useState(issue.notes);
  const [risk, setRisk] = useState(dateInput(issue.risk_until));
  const [seen, setSeen] = useState(issue.revision);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  if (issue.revision !== seen) {
    setSeen(issue.revision);
    setStatus(issue.status);
    setAssignee(issue.assignee);
    setNotes(issue.notes);
    setRisk(dateInput(issue.risk_until));
  }
  const due = slaText(issue);
  const submit = (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError("");
    api.updateVulnerabilityIssue(issue.id, {
      status,
      assignee,
      notes,
      risk_until: status === "risk_accepted" && risk ? new Date(`${risk}T23:59:59`).toISOString() : null,
      revision: issue.revision,
    })
      .then(() => onSaved())
      .catch((err: Error) => setError(err.message))
      .finally(() => setBusy(false));
  };
  return (
    <form className="vuln-work" onSubmit={submit}>
      <label>
        <span className="sec">Owner</span>
        <input className="field" value={assignee} onChange={(event) => setAssignee(event.target.value)} placeholder="Unassigned" aria-label="Assignee" />
      </label>
      <label>
        <span className="sec">Due · SLA {issue.sla_days} days{issue.kev ? " · KEV" : ""}</span>
        <span className="vuln-due">
          <b>{due.when}</b>
          <span className={`pill ${due.tone}`}>{due.left}</span>
        </span>
      </label>
      <label>
        <span className="sec">Status</span>
        <select className="field" value={status} onChange={(event) => setStatus(event.target.value)} aria-label="Status">
          {statuses.map(([value, text]) => <option key={value} value={value}>{text}</option>)}
        </select>
      </label>
      {status === "risk_accepted" ? (
        <label>
          <span className="sec">Risk acceptance expires</span>
          <input className="field" type="date" required value={risk} onChange={(event) => setRisk(event.target.value)} aria-label="Risk acceptance expiry" />
        </label>
      ) : null}
      <label className="span-2">
        <span className="sec">Notes</span>
        <textarea className="field" rows={2} value={notes} onChange={(event) => setNotes(event.target.value)} aria-label="Notes" />
      </label>
      <div className="span-2 vuln-save">
        <button className="capsule primary" type="submit" disabled={busy}>{busy ? "Saving" : "Save"}</button>
        {error ? <span className="note">{error}</span> : null}
      </div>
    </form>
  );
}

function DeviceLine({ device }: { device: AffectedDevice }) {
  const name = device.computer_name || device.hostname || device.serial;
  const version = device.build ? `${device.version} (${device.build})` : device.version;
  return (
    <div className="aff-row">
      <Icon name="laptop" size={13} />
      <Link to={`/devices/${device.id}/vulnerabilities`}>{name}</Link>
      <span className="mono faint">{version}</span>
      <span className="faint">· {evidenceLabel(device.evidence)}</span>
    </div>
  );
}

function Stat({ k, v, note, hot, warn }: { k: string; v: string; note: string; hot?: boolean; warn?: boolean }) {
  return (
    <div className="card vuln-stat">
      <span className="sec">{k}</span>
      <b className={hot ? "hot" : ""}>{v}</b>
      <span className={warn ? "warn" : ""}>{note}</span>
    </div>
  );
}

function Filter({ on, onClick, children }: { on: boolean; onClick: () => void; children: string }) {
  return <button className={`filter${on ? " on" : ""}`} type="button" aria-pressed={on} onClick={onClick}>{children}</button>;
}

function Kev() {
  return <span className="kev"><Icon name="flame" size={10} />KEV</span>;
}

function Score({ score }: { score: number }) {
  if (!score) return <span className="cvss none">—</span>;
  const tone = score >= 9 ? "crit" : score >= 7 ? "high" : score >= 4 ? "mid" : "low";
  return <span className={`cvss ${tone}`}>{score.toFixed(1).replace(/\.0$/, "")}</span>;
}

function Epss({ issue }: { issue: VulnerabilityIssue }) {
  if (!issue.epss_known) return <span className="epss"><b>—</b></span>;
  const pct = Math.max(0, Math.min(100, issue.epss * 100));
  const tone = pct > 50 ? "hot" : pct > 10 ? "warn" : "";
  return (
    <span className="epss">
      <b className="tnum">{pct.toFixed(1)}%</b>
      <span className={`bar ${tone}`}><i style={{ ["--p" as string]: pct / 100 }} /></span>
    </span>
  );
}

function StatusPill({ status }: { status: string }) {
  const tone = status === "in_progress" ? "blue" : status === "risk_accepted" ? "orange" : status === "fixed" ? "green" : "gray";
  return <span className={`pill ${tone}`}>{statusLabel(status)}</span>;
}

function FixPill({ fix }: { fix: IssueFix }) {
  const tone = fix.action === "promote" || fix.action === "run_recipe" || fix.action === "recipe_pending" ? "blue"
    : fix.action === "require_install" ? "green"
      : fix.action === "os_update" ? "purple" : "gray";
  return <span className={`pill ${tone}`}>{fixShort(fix)}</span>;
}

function AppMark({ name, large }: { name: string; large?: boolean }) {
  const key = name.toLowerCase();
  const tone = key.includes("chrome") ? "chrome"
    : key.includes("firefox") ? "firefox"
      : key.includes("zoom") ? "zoom"
        : key.includes("slack") ? "slack"
          : key.includes("macos") || key.includes("safari") ? "apple"
            : "app";
  const letter = (name.trim()[0] || "?").toUpperCase();
  return <span className={`appic ${tone}${large ? " lg" : ""}`}>{tone === "chrome" || tone === "apple" ? "" : letter}</span>;
}

function percent(part?: number, whole?: number) {
  if (part == null || !whole) return "—";
  return `${Math.round((part / whole) * 100)}%`;
}

function label(value: string) {
  return value.slice(0, 1).toUpperCase() + value.slice(1);
}

function statusLabel(status: string) {
  return statuses.find(([value]) => value === status)?.[1] ?? status;
}

function epssLabel(issue: VulnerabilityIssue) {
  if (!issue.epss_known) return "EPSS —";
  const pct = (issue.epss * 100).toFixed(1);
  const p = issue.epss_percentile ? ` · p${Math.round(issue.epss_percentile * 100)}` : "";
  return `EPSS ${pct}%${p}`;
}

function boundText(fix: IssueFix) {
  if (fix.required_os) return fix.required_os;
  if (fix.fixed_version) return `< ${fix.fixed_version}`;
  return "—";
}

function fixShort(fix: IssueFix) {
  switch (fix.action) {
    case "promote": return `Testing · ${fix.catalog_version || fix.fixed_version || ""}`.trim();
    case "require_install": return "Production";
    case "run_recipe": return "Run recipe";
    case "recipe_pending": return "Recipe queued";
    case "os_update": return fix.required_os ? `macOS ${fix.required_os}` : "OS update";
    default: return "No managed fix";
  }
}

function fixHeadline(issue: VulnerabilityDetail) {
  const fix = issue.fix;
  if (fix.action === "os_update") return `Update macOS to ${fix.required_os || fix.fixed_version}`;
  if (fix.fixed_version) return `Fix available · ${issue.software_name} ${fix.catalog_version || fix.fixed_version}`;
  return issue.software_name || issue.cve_id;
}

function fixDetail(fix: IssueFix) {
  if (fix.action === "promote") return `${fix.catalog_version} is in testing. Promote it with a pull request.`;
  if (fix.action === "require_install") return `${fix.catalog_version} is in production. Open a pull request to install it on the affected Macs.`;
  if (fix.action === "run_recipe") return `${fix.recipe_name || "The recipe"} last ${fix.recipe_status || "has no run"}. Running it does not promote a catalog.`;
  if (fix.action === "recipe_pending") return `${fix.recipe_name || "Recipe"} is ${fix.recipe_status}.`;
  if (fix.action === "os_update") return "The required build comes from the Apple security release. Open a pull request for the OS policy.";
  return "No Munki item or AutoPKG recipe clears this yet.";
}

function prLabel(action: string) {
  if (action === "require_install") return "Open PR to install";
  if (action === "os_update") return "Open PR for the OS update";
  return "Open PR to promote";
}

function titleFrom(issue: VulnerabilityIssue) {
  const text = issue.description.split(". ")[0];
  return text.length > 110 ? `${text.slice(0, 107)}…` : text;
}

function evidenceLine(issue: VulnerabilityDetail) {
  const both = issue.devices.filter((device) => device.evidence === "both").length;
  const only = issue.devices.filter((device) => device.evidence === "rapid7").length;
  if (both || only) return `${both} agree with Rapid7${only ? `, ${only} Rapid7 only` : ""}`;
  return "from inventory";
}

function evidenceLabel(value: string) {
  if (value === "both") return "inventory and Rapid7";
  if (value === "rapid7") return "Rapid7 only";
  return "inventory";
}

function eventText(event: IssueEvent) {
  const detail = event.detail ?? {};
  const from = String(detail.from ?? "");
  const to = String(detail.to ?? "");
  switch (event.action) {
    case "opened": return `opened the issue${detail.devices != null ? ` · ${detail.devices} devices` : ""}`;
    case "updated": return `set ${from ? statusLabel(from) : "status"} to ${statusLabel(to || "")}${detail.assignee ? ` · ${detail.assignee}` : ""}`;
    case "note": return "added a note";
    case "auto_resolved": return "resolved it · no device still matches";
    case "reopened": return "reopened it · a device matches again";
    case "risk_expired": return "moved it back to open · the acceptance expired";
    case "risk_accepted": return "accepted the risk";
    default: return event.action.replaceAll("_", " ");
  }
}

function slaText(issue: VulnerabilityIssue) {
  const due = new Date(issue.sla_due);
  const days = Math.ceil((due.getTime() - Date.now()) / 86400000);
  const when = Number.isNaN(due.getTime()) ? "—" : due.toLocaleDateString(undefined, { month: "short", day: "numeric", year: "numeric" });
  if (!issue.within_sla || days < 0) return { when, left: "Overdue", tone: "red" };
  if (days <= 7) return { when, left: `${days}d left`, tone: "orange" };
  return { when, left: `${days}d left`, tone: "gray" };
}

function dateInput(value?: string) {
  if (!value) return "";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "";
  return date.toISOString().slice(0, 10);
}
