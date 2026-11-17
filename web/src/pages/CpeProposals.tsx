import { useEffect, useRef, useState, type CSSProperties } from "react";
import { api, type CPECandidate, type CPEProposal } from "../api";
import { Icon } from "../icons";
import { Empty, Mark, MunkiSeg, Page, ProposeChange, Toolbar, ago, enterStyle, match, useSearch } from "../ui";

type Filter = "proposed" | "";

const CONFIDENCE: Record<CPEProposal["confidence"], { label: string; kind: string }> = {
  high: { label: "Clear match", kind: "green" },
  medium: { label: "Needs a person", kind: "orange" },
  low: { label: "Weak match", kind: "orange" },
  none: { label: "No match", kind: "gray" },
};

// Read-only: a proposal becomes a mapping only when the cpe_override block is
// added to the config repo. This page never writes config.
export function CpeProposalsPage() {
  const { q } = useSearch();
  const [filter, setFilter] = useState<Filter>("proposed");
  const [data, setData] = useState<{ proposals: CPEProposal[]; waiting: number } | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    let stop = false;
    const load = () => {
      api.cpeProposals()
        .then((next) => { if (!stop) { setData(next); setError(""); } })
        .catch((err: Error) => { if (!stop) setError(err.message); });
    };
    load();
    const t = setInterval(load, 15000);
    return () => { stop = true; clearInterval(t); };
  }, []);

  const all = data?.proposals ?? [];
  const shown = all
    .filter((p) => filter === "" || p.status === "proposed")
    .filter((p) => match(q, p.name, p.display_name, p.developer, p.bundle_id, p.vendor, p.product));
  const proposed = all.filter((p) => p.status === "proposed").length;

  return (
    <Page>
      <Toolbar
        title="NVD mappings"
        lede="Munki items with no NVD product get a suggested CPE from the NVD dictionary. Release reviews use version ranges only after the mapping is in the config repo."
        extra={<MunkiSeg />}
      />
      <div className="content">
        {error ? <p className="note">{error}</p> : null}
        <section className="card enter" style={enterStyle(0)}>
          <div className="card-h">
            <span className="card-t">{filter === "proposed" ? "Proposed mappings" : "All lookups"}</span>
            <span className="faint">{shown.length}</span>
            {data && data.waiting > 0 ? (
              <span className="pill gray" title="Looked up with each vulnerability sync, paced for NVD's rate limit">{data.waiting} waiting for lookup</span>
            ) : null}
            <div className="seg release-filter" style={{ "--n": 2, "--i": filter === "proposed" ? 0 : 1, marginLeft: "auto" } as CSSProperties}>
              <span className="seg-thumb" />
              <button type="button" className={filter === "proposed" ? "on" : undefined} onClick={() => setFilter("proposed")}>Proposed</button>
              <button type="button" className={filter === "" ? "on" : undefined} onClick={() => setFilter("")}>All</button>
            </div>
          </div>
          {!data ? null : shown.length === 0 ? (
            <Empty>{all.length === 0 ? "Nothing to map. Every Munki item has an NVD product, or none has been looked up yet." : proposed === 0 && filter === "proposed" ? "No proposals yet. Lookups that found nothing are under All." : "Nothing matches."}</Empty>
          ) : (
            <div className="releases">
              {shown.map((p, i) => <ProposalCard key={p.name} p={p} index={i} />)}
            </div>
          )}
        </section>
        <p className="faint release-perm">
          Mappings are Terraform config. Copy the block into <span className="mono">missioncontrol_vulnerability_settings</span> in the config repo. Nothing here changes a mapping.
        </p>
      </div>
    </Page>
  );
}

function ProposalCard({ p, index }: { p: CPEProposal; index: number }) {
  const [copied, setCopied] = useState<"" | "done" | "select">("");
  const pre = useRef<HTMLPreElement>(null);
  const conf = p.status === "error" ? { label: "Lookup failed", kind: "red" } : CONFIDENCE[p.confidence];
  const title = p.display_name || p.name;
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(p.terraform);
      setCopied("done");
    } catch {
      // No clipboard permission: select the block so the person can copy it.
      const sel = window.getSelection();
      if (pre.current && sel) {
        const range = document.createRange();
        range.selectNodeContents(pre.current);
        sel.removeAllRanges();
        sel.addRange(range);
      }
      setCopied("select");
    }
    window.setTimeout(() => setCopied(""), 2500);
  };
  return (
    <article className="release cpe enter" style={enterStyle(Math.min(index, 10))}>
      <header className="release-h">
        <Mark name={title} />
        <div className="release-id">
          <div className="name">{title}</div>
          <div className="subline">
            <span className="mono">{p.name}</span>
            {p.developer ? <span className="faint"> · {p.developer}</span> : null}
            {p.bundle_id ? <span className="faint mono"> · {p.bundle_id}</span> : null}
          </div>
        </div>
        {p.vendor ? <span className="cpe-key mono">{p.vendor}:{p.product}</span> : null}
        <span className={`pill ${conf.kind}`}>{p.confidence === "high" && p.status === "proposed" ? <Icon name="check" size={11} /> : null}{conf.label}</span>
      </header>

      {p.status === "error" ? (
        <div className="notes waiting"><Icon name="alert" size={12} />{p.error}</div>
      ) : (
        <ul className="release-reasons">
          {p.evidence.map((e) => <li key={e}>{e}</li>)}
        </ul>
      )}

      {p.needs_review && p.candidates.length > 1 ? <Candidates list={p.candidates} chosen={`${p.vendor}:${p.product}`} /> : null}

      {p.terraform ? (
        <div className="cpe-hcl-wrap">
          {p.needs_review ? (
            <div className="notes-caveats cpe-caveat"><Icon name="alert" size={11} />The block uses the top candidate. Check it against the candidates before you paste it.</div>
          ) : null}
          <pre ref={pre} className="cpe-hcl" aria-label="cpe_override block">{p.terraform}</pre>
          <div className="release-actions">
            <span className="faint cpe-meta">searched “{p.keyword}” {ago(p.looked_up_at)}</span>
            <button className="capsule" type="button" onClick={copy}>{copied === "done" ? "Copied" : copied === "select" ? "Press ⌘C to copy" : "Copy block"}</button>
            <ProposeChange kind="cpe_override" />
          </div>
        </div>
      ) : (
        <div className="subline cpe-meta">{p.keyword ? `searched “${p.keyword}” ${ago(p.looked_up_at)}` : ago(p.looked_up_at)}</div>
      )}
    </article>
  );
}

function Candidates({ list, chosen }: { list: CPECandidate[]; chosen: string }) {
  return (
    <details className="notes-more cpe-cands">
      <summary>{list.length} candidates</summary>
      <div className="cpe-cand-rows">
        {list.map((c) => {
          const key = `${c.vendor}:${c.product}`;
          return (
            <div key={key} className={`cpe-cand${key === chosen ? " on" : ""}`}>
              <span className="mono">{key}</span>
              <span className="faint">{c.title}</span>
              <span className="faint cpe-score">score {c.score} · {c.entries} CPE{c.entries === 1 ? "" : "s"}</span>
            </div>
          );
        })}
      </div>
    </details>
  );
}
