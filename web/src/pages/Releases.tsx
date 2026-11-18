import { useEffect, useState, type CSSProperties } from "react";
import { api, can, type ReleaseCVE, type ReleaseDecision, type ReleaseReview } from "../api";
import { Icon } from "../icons";
import { Empty, Mark, MunkiSeg, Page, Toolbar, enterStyle, match, useSearch, useSession, when } from "../ui";

type Filter = "pending" | "";

const DECISIONS: Record<ReleaseDecision, { label: string; confirm: string; tone: string }> = {
  rush: { label: "Rush to production", confirm: "Move this build to production now, skipping the soak?", tone: "rush" },
  normal: { label: "Normal track", confirm: "Leave this build on the normal soak schedule?", tone: "" },
  reject: { label: "Reject", confirm: "Pull this build from every catalog? Clients stop seeing it.", tone: "danger" },
};

const STATUS: Record<ReleaseReview["status"], { label: string; kind: string }> = {
  pending: { label: "Waiting for review", kind: "orange" },
  rushed: { label: "Rushed to production", kind: "red" },
  normal: { label: "Normal track", kind: "blue" },
  rejected: { label: "Rejected", kind: "gray" },
  superseded: { label: "Superseded", kind: "gray" },
};

export function ReleasesPage() {
  const { q } = useSearch();
  const user = useSession();
  const canDecide = can(user, "releases:update");
  const canRush = can(user, "rush:update");
  const [filter, setFilter] = useState<Filter>("pending");
  const [reviews, setReviews] = useState<ReleaseReview[]>([]);
  const [loaded, setLoaded] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    let stop = false;
    const load = () => {
      api.releaseReviews(filter)
        .then((r) => {
          if (stop) return;
          setReviews(r.reviews);
          setLoaded(true);
          setError("");
        })
        .catch((err: Error) => { if (!stop) setError(err.message); });
    };
    load();
    const t = setInterval(load, 5000);
    return () => { stop = true; clearInterval(t); };
  }, [filter]);

  const shown = reviews.filter((r) =>
    match(q, r.name, r.display_name, r.version, r.priority, ...r.fixed.map((c) => c.cve), ...r.notes.cves));
  const high = reviews.filter((r) => r.status === "pending" && r.priority === "high").length;

  const replace = (next: ReleaseReview) =>
    setReviews((list) => list.map((r) => (r.id === next.id ? next : r)).filter((r) => filter === "" || r.status === filter));

  return (
    <Page>
      <Toolbar
        title="Releases"
        lede="Every new AutoPkg build waits here. Priority comes from NVD, KEV, and EPSS. Claude's read of the release notes is advice. A person decides."
        extra={<MunkiSeg />}
      />
      <div className="content">
        {error ? <p className="note">{error}</p> : null}
        <section className="card enter" style={enterStyle(0)}>
          <div className="card-h">
            <span className="card-t">{filter === "pending" ? "Waiting for review" : "All reviews"}</span>
            <span className="faint">{shown.length}</span>
            {high > 0 ? <span className="pill red"><Icon name="flame" size={11} />{high} high</span> : null}
            <div className="seg release-filter" style={{ "--n": 2, "--i": filter === "pending" ? 0 : 1, marginLeft: "auto" } as CSSProperties}>
              <span className="seg-thumb" />
              <button type="button" className={filter === "pending" ? "on" : undefined} onClick={() => setFilter("pending")}>Pending</button>
              <button type="button" className={filter === "" ? "on" : undefined} onClick={() => setFilter("")}>All</button>
            </div>
          </div>
          {!loaded ? null : shown.length === 0 ? (
            <Empty>{reviews.length === 0 ? (filter === "pending" ? "Nothing waiting. New AutoPkg builds show up here." : "No releases yet.") : "Nothing matches."}</Empty>
          ) : (
            <div className="releases">
              {shown.map((r, i) => (
                <ReviewCard key={r.id} review={r} index={i} canDecide={canDecide} canRush={canRush} onDecided={replace} onError={setError} />
              ))}
            </div>
          )}
        </section>
        {!canDecide && loaded ? (
          <p className="faint release-perm">You can see reviews. Deciding needs the releases:update permission from a role binding.</p>
        ) : null}
      </div>
    </Page>
  );
}

function ReviewCard({ review: r, index, canDecide, canRush, onDecided, onError }: {
  review: ReleaseReview; index: number; canDecide: boolean; canRush: boolean;
  onDecided: (r: ReleaseReview) => void; onError: (msg: string) => void;
}) {
  const [pending, setPending] = useState<ReleaseDecision | null>(null);
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);
  // The server enforces the same rules: rush needs rush:update and a HIGH
  // priority from the feeds; normal and reject need releases:update.
  const rushable = r.status === "pending" && r.priority === "high" && canRush;
  const actions: ReleaseDecision[] =
    r.status === "pending" ? [...(rushable ? ["rush" as const] : []), "normal", "reject"]
      : r.status === "rushed" || r.status === "normal" ? ["reject"] : [];
  const rushNote = r.status === "pending" && r.priority === "high" && !canRush
    ? "Rushing to production needs the rush:update permission." : "";
  const status = STATUS[r.status];

  const decide = () => {
    if (!pending) return;
    setBusy(true);
    api.decideRelease(r.id, pending, note.trim())
      .then((next) => { onDecided(next); setPending(null); setNote(""); onError(""); })
      .catch((err: Error) => onError(`${r.display_name}: ${err.message}`))
      .finally(() => setBusy(false));
  };

  return (
    <article className={`release enter${r.priority === "high" && r.status === "pending" ? " hot" : ""}`} style={enterStyle(Math.min(index, 10))}>
      <header className="release-h">
        <Mark name={r.display_name} />
        <div className="release-id">
          <div className="name">{r.display_name}</div>
          <div className="subline mono">
            {r.baseline_version ? `${r.baseline_version} → ` : ""}{r.version}
            <span className="faint"> · in {r.catalog}</span>
          </div>
        </div>
        <span className={`prio ${r.priority}`}>{r.priority === "high" ? <Icon name="flame" size={12} /> : null}{r.priority.toUpperCase()}</span>
        <span className={`pill ${status.kind}`}>{status.label}</span>
      </header>

      <ul className="release-reasons">
        {r.reasons.map((reason) => <li key={reason}>{reason}</li>)}
      </ul>

      {r.fixed.length > 0 ? (
        <div className="cve-row">
          <span className="faint cve-label">Fixes</span>
          {r.fixed.map((c) => <CVEChip key={c.cve} c={c} />)}
        </div>
      ) : null}
      {r.still_open.length > 0 ? (
        <div className="cve-row">
          <span className="faint cve-label">Still open</span>
          {r.still_open.map((c) => <CVEChip key={c.cve} c={c} />)}
        </div>
      ) : null}

      <Notes review={r} />

      {r.status !== "pending" && r.decided_by ? (
        <div className="subline release-decided">
          {status.label} by {r.decided_by} {when(r.decided_at)}{r.decision_note ? ` · “${r.decision_note}”` : ""}
        </div>
      ) : null}

      {canDecide && actions.length > 0 ? (
        pending ? (
          <div className="release-confirm">
            <span>{DECISIONS[pending].confirm}</span>
            <input className="field" placeholder="Note for the audit log (optional)" value={note} maxLength={2000} onChange={(e) => setNote(e.target.value)} />
            <div className="release-actions">
              <button className="capsule" type="button" onClick={() => setPending(null)} disabled={busy}>Cancel</button>
              <button className={`capsule primary ${DECISIONS[pending].tone}`} type="button" onClick={decide} disabled={busy}>
                {DECISIONS[pending].label}
              </button>
            </div>
          </div>
        ) : (
          <div className="release-actions">
            {rushNote ? <span className="faint rush-note">{rushNote}</span> : null}
            {actions.map((d) => (
              <button key={d} type="button"
                className={`capsule${d === "rush" ? " primary rush" : ""}${d === "normal" && !rushable ? " primary" : ""}${d === "reject" ? " danger-text" : ""}`}
                onClick={() => setPending(d)}>
                {d === "rush" ? <Icon name="rocket" size={12} /> : null}
                {DECISIONS[d].label}
              </button>
            ))}
          </div>
        )
      ) : null}
    </article>
  );
}

function Notes({ review: r }: { review: ReleaseReview }) {
  const n = r.notes;
  if (r.status === "superseded") return null;
  if (n.status === "pending" || n.status === "leased") {
    return (
      <div className="notes waiting">
        <Icon name="spark" size={12} />
        {n.status === "leased" ? "Claude is reading the release notes…" : "Release notes not read yet. They are read when mc-advisor runs."}
      </div>
    );
  }
  if (n.status === "failed") {
    return <div className="notes waiting"><Icon name="alert" size={12} />Couldn't read the release notes ({n.attempts} tries): {n.error}</div>;
  }
  // Reads from older advisors carry only the long form: lead with its first sentence.
  const headline = n.headline || firstSentence(n.summary);
  const hosts = uniqueHosts(n.sources);
  return (
    <div className="notes">
      <div className="notes-h">
        <Icon name="spark" size={12} />
        <span>Claude's read</span>
        {n.recommendation ? <span className={`advice ${n.recommendation}`}>advises {n.recommendation}</span> : null}
        {n.exploited ? <span className="advice high">exploited</span> : null}
        <span className="faint notes-meta" title={n.model}>{shortModel(n.model)}{n.model ? " · " : ""}{when(n.at)}</span>
      </div>
      <div className="notes-headline">{headline}</div>
      {n.highlights.length > 0 ? (
        <ul className="notes-points">{n.highlights.map((h) => <li key={h}>{h}</li>)}</ul>
      ) : null}
      {n.caveats.length > 0 ? (
        <ul className="notes-caveats">{n.caveats.map((c) => <li key={c}><Icon name="alert" size={11} />{c}</li>)}</ul>
      ) : null}
      {n.rationale ? <div className="notes-why"><span className="faint">Why</span>{n.rationale}</div> : null}
      {hosts.length > 0 ? (
        <div className="notes-sources">
          <span className="faint">Sources</span>
          {hosts.map(([host, url]) => <a key={host} href={url} target="_blank" rel="noreferrer noopener">{host}</a>)}
        </div>
      ) : null}
      {n.summary && n.summary !== headline ? (
        <details className="notes-more">
          <summary>More details</summary>
          <p>{n.summary}</p>
          {n.sources.length > hosts.length ? (
            <ul className="notes-urls">{n.sources.map((u) => <li key={u}><a href={u} target="_blank" rel="noreferrer noopener">{u}</a></li>)}</ul>
          ) : null}
        </details>
      ) : null}
    </div>
  );
}

function firstSentence(s: string) {
  const m = s.match(/^.*?[.!?](\s|$)/);
  return (m ? m[0] : s).trim();
}

function uniqueHosts(urls: string[]): [string, string][] {
  const seen = new Map<string, string>();
  for (const u of urls) {
    const h = hostOf(u);
    if (!seen.has(h)) seen.set(h, u);
  }
  return [...seen.entries()];
}

/** The CLI reports every model it used (a small one summarises fetched pages); show the main one. */
function shortModel(models?: string) {
  if (!models) return "";
  const list = models.split(",");
  return list.find((m) => !m.includes("haiku")) ?? list[0];
}

function CVEChip({ c }: { c: ReleaseCVE }) {
  const sev = c.kev ? "red" : c.cvss >= 9 ? "red" : c.cvss >= 7 ? "orange" : c.scored ? "gray" : "gray";
  const bits = [
    c.scored ? c.cvss.toFixed(1) : "unscored",
    c.epss_known && c.epss >= 0.01 ? `EPSS ${Math.round(c.epss * 100)}%` : "",
  ].filter(Boolean).join(" · ");
  return (
    <a className={`cve-chip ${sev}`} href={`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(c.cve)}`} target="_blank" rel="noreferrer noopener"
      title={c.source === "release_notes" ? "Named in the release notes" : "From NVD affected versions"}>
      <span className="mono">{c.cve}</span>
      <span className="cve-score">{bits}</span>
      {c.kev ? <span className="kev">KEV</span> : null}
    </a>
  );
}

function hostOf(raw: string) {
  try {
    return new URL(raw).host;
  } catch {
    return raw;
  }
}
