import { useEffect, useState, type CSSProperties } from "react";
import { NavLink, useLocation } from "react-router-dom";
import { api, type OsqueryPack, type OsqueryQuery } from "../api";
import { Empty, Managed, Page, Toolbar, enterStyle, match, useSearch } from "../ui";
import { LiveQueryPanel } from "./LiveQuery";

export function QueriesPage() {
  return (
    <Page>
      <Toolbar
        title="Queries"
        badge
        lede="Queries and packs are applied by Terraform."
        extra={<QuerySeg />}
      />
      <QueryCatalog />
    </Page>
  );
}

export function LiveQueryPage() {
  return (
    <Page>
      <Toolbar
        title="Live query"
        lede="Runs through osquery distributed queries. This is not saved as config."
        extra={<QuerySeg />}
      />
      <div className="content fleet">
        <LiveQueryPanel />
      </div>
    </Page>
  );
}

function QuerySeg() {
  const { pathname } = useLocation();
  const live = pathname.startsWith("/queries/live");
  const items = [
    { to: "/queries", label: "Queries", on: !live },
    { to: "/queries/live", label: "Live query", on: live },
  ];
  return (
    <div className="seg" style={{ "--n": 2, "--i": live ? 1 : 0 } as CSSProperties}>
      <span className="seg-thumb" />
      {items.map((item) => (
        <NavLink key={item.to} to={item.to} end className={item.on ? "on" : undefined}>{item.label}</NavLink>
      ))}
    </div>
  );
}

function QueryCatalog() {
  const { q } = useSearch();
  const [queries, setQueries] = useState<OsqueryQuery[]>([]);
  const [packs, setPacks] = useState<OsqueryPack[]>([]);
  const [error, setError] = useState("");

  useEffect(() => {
    Promise.all([api.queries(), api.packs()])
      .then(([qs, ps]) => { setQueries(qs.queries); setPacks(ps.packs); })
      .catch((err: Error) => setError(err.message));
  }, []);

  const shownQ = queries.filter((item) => match(q, item.name, item.description, item.sql, item.platform));
  const shownP = packs.filter((item) => match(q, item.name, item.description, item.platform, ...(item.labels ?? [])));

  return (
    <div className="content fleet">
      {error ? <p className="note">{error}</p> : null}
      <section className="card enter" style={enterStyle(0)}>
        <div className="card-h">
          <span className="card-t">Packs</span>
          <span className="faint">{shownP.length}</span>
          <span className="grow" />
          <Managed small />
        </div>
        {shownP.length === 0 ? <Empty>No packs yet. They appear when Terraform applies.</Empty> : shownP.map((pack) => (
          <div key={pack.id} className="row cols-pack loose">
            <span className="wash" />
            <div>
              <div className="name">{pack.name}{pack.enabled ? "" : " · disabled"}</div>
              <div className="subline">{pack.description || "No description"}</div>
            </div>
            <div className="muted">{(pack.labels ?? []).length ? pack.labels.join(", ") : "All hosts"}</div>
            <div className="muted">{(pack.queries ?? []).map((item) => item.name).join(", ") || "—"}</div>
            <div className="end faint">{pack.platform || "any"}</div>
          </div>
        ))}
      </section>
      <section className="card enter" style={enterStyle(1)}>
        <div className="card-h">
          <span className="card-t">Queries</span>
          <span className="faint">{shownQ.length}</span>
          <span className="grow" />
          <Managed small />
        </div>
        {shownQ.length === 0 ? <Empty>No queries yet.</Empty> : (
          <>
            <div className="list-h cols-query">
              <span>Query</span><span>SQL</span><span>Schedule</span><span></span>
            </div>
            {shownQ.map((item) => (
              <div key={item.id} className="row cols-query loose">
                <span className="wash" />
                <div>
                  <div className="name">{item.name}</div>
                  <div className="subline">{item.description || item.platform || "any platform"}</div>
                </div>
                <div className="subline mono">{item.sql}</div>
                <div className="muted">{every(item.interval)} · {item.snapshot ? "snapshot" : "differential"}</div>
                <div className="end faint">{item.scheduled ? "global" : "pack"}</div>
              </div>
            ))}
          </>
        )}
      </section>
    </div>
  );
}

function every(seconds: number) {
  if (seconds % 3600 === 0) return `${seconds / 3600}h`;
  if (seconds % 60 === 0) return `${seconds / 60}m`;
  return `${seconds}s`;
}
