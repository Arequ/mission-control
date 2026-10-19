import { useEffect, useState, type ReactNode } from "react";
import { Link, useParams } from "react-router-dom";
import { api, type CoverageDevice, type CoverageMatrix, type SourceConnector } from "../api";
import { Empty, Mark, Page, Toolbar, ago, enterStyle, useSearch, when } from "../ui";

const missingSources = [
  ["crowdstrike", "CrowdStrike"],
  ["rapid7", "Rapid7"],
  ["netskope", "Netskope"],
  ["proofpoint", "Proofpoint"],
  ["blastshield", "BlastShield"],
  ["kolide", "Kolide"],
] as const;

export function CoveragePage() {
  const { q } = useSearch();
  const [filter, setFilter] = useState("all");
  const [source, setSource] = useState("");
  const [data, setData] = useState<CoverageMatrix | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    let stop = false;
    const load = () => {
      api.coverageMatrix({ filter: filter === "all" ? "" : filter, source, staleDays: 7, q, limit: 100 })
        .then((next) => { if (!stop) { setData(next); setError(""); } })
        .catch((err: Error) => { if (!stop) setError(err.message); });
    };
    load();
    const t = setInterval(load, 8000);
    return () => { stop = true; clearInterval(t); };
  }, [filter, source, q]);

  const choose = (next: string, src = "") => {
    setFilter(next);
    setSource(src);
  };

  return (
    <Page>
      <Toolbar
        title="Security Coverage"
        lede={data ? `${data.total} endpoints · ${data.gaps} with a gap` : "Which tools see each endpoint"}
        extra={<Link className="capsule" to="/coverage/connectors">Connectors</Link>}
      />
      <div className="content fleet">
        {error ? <p className="note">{error}</p> : null}
        <div className="filters">
          <Filter on={filter === "all"} onClick={() => choose("all")}>All</Filter>
          <Filter on={filter === "gaps"} onClick={() => choose("gaps")}>Has gaps</Filter>
          <Filter on={filter === "ghost"} onClick={() => choose("ghost")}>Ghosts</Filter>
          <Filter on={filter === "single"} onClick={() => choose("single")}>One source</Filter>
          <Filter on={filter === "stale" && !source} onClick={() => choose("stale")}>Stale &gt; 7 days</Filter>
          {missingSources.map(([key, label]) => (
            <Filter key={key} on={filter === "missing" && source === key} onClick={() => choose("missing", key)}>
              Missing {label}
            </Filter>
          ))}
        </div>
        <section className="card">
          {!data || data.rows.length === 0 ? (
            <Empty>{error ? "Could not load coverage." : "Nothing matches this filter."}</Empty>
          ) : (
            <div className="table-wrap">
              <div className="cov-table">
                <div className="cov-head">
                  <span>Device</span>
                  {data.sources.map((src) => (
                    <span key={src.key} className="cov-h" title={src.name}>
                      {src.short}
                      <b>{src.percent.toFixed(1)}%</b>
                    </span>
                  ))}
                  <span className="cov-h">Seen</span>
                </div>
                {data.rows.map((row, index) => (
                  <Link key={row.id} to={`/coverage/devices/${row.id}`} className="cov-row enter" style={enterStyle(index)}>
                    <span className="who">
                      <Mark name={row.name || row.hostname || row.serial} />
                      <span>
                        <span className="name">{row.name || row.hostname || row.serial}</span>
                        <span className="subline">
                          {row.kind === "ghost" ? "Ghost · " : row.kind === "conflict" ? "Conflict · " : ""}
                          {[row.user, row.serial].filter(Boolean).join(" · ") || "No serial"}
                        </span>
                      </span>
                    </span>
                    {row.cells.map((cell) => (
                      <span key={cell.source} className={`cov-cell ${cell.state}`} title={`${cell.source}: ${cell.state}`}>
                        <i />
                      </span>
                    ))}
                    <span className="cov-count">{row.seen}/{row.total}</span>
                  </Link>
                ))}
              </div>
            </div>
          )}
        </section>
      </div>
    </Page>
  );
}

function Filter({ on, onClick, children }: { on: boolean; onClick: () => void; children: ReactNode }) {
  return (
    <button type="button" className={`filter${on ? " on" : ""}`} onClick={onClick}>{children}</button>
  );
}

export function CoverageDevicePage() {
  const { id = "" } = useParams();
  const [device, setDevice] = useState<CoverageDevice | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    let stop = false;
    const load = () => {
      api.coverageDevice(id)
        .then((next) => { if (!stop) { setDevice(next); setError(""); } })
        .catch((err: Error) => { if (!stop) setError(err.message); });
    };
    load();
    const t = setInterval(load, 8000);
    return () => { stop = true; clearInterval(t); };
  }, [id]);

  return (
    <Page>
      <div className="content fleet coverage-device">
        <Link className="back" to="/coverage">Security Coverage</Link>
        {error ? <p className="note">{error}</p> : null}
        {device ? (
          <>
            <header className="hero enter" style={enterStyle(0)}>
              <span className="hero-mark">{(device.name || device.hostname || "?").trim().charAt(0).toUpperCase()}</span>
              <div className="hero-copy">
                <div className="hero-title">
                  <h1>{device.name || device.hostname || device.serial}</h1>
                  <span className={`pill ${device.kind === "device" ? "green" : device.kind === "conflict" ? "red" : "orange"}`}>
                    {device.kind === "device" ? "Enrolled" : device.kind === "conflict" ? "Conflict" : "Ghost"}
                  </span>
                  <span className="coverage-chip quiet">Coverage {device.seen}/{device.total}</span>
                </div>
                <div className="sub">{[device.user, device.model, device.os_version, device.serial].filter(Boolean).join("  ·  ")}</div>
                <p className="match-note">{device.match.note}</p>
              </div>
            </header>
            <div className="cov-tiles">
              {device.sources.map((src, index) => (
                <article key={src.key} className={`cov-tile enter ${src.state}`} style={enterStyle(index)}>
                  <div className="cov-tile-h">
                    <span className="initials">{src.short}</span>
                    <div>
                      <div className="name">{src.name}</div>
                      <div className={`subline state-${src.state}`}>{labelState(src.state)}</div>
                    </div>
                  </div>
                  <div className="cov-meta">
                    <span>Last seen</span>
                    <b>{src.last_seen_at ? ago(src.last_seen_at) : "—"}</b>
                  </div>
                  <div className="cov-meta">
                    <span>Native ID</span>
                    <b className="mono">{src.native_id || "—"}</b>
                  </div>
                </article>
              ))}
            </div>
            <section className="card">
              <div className="card-h"><span className="card-t">Field comparison</span></div>
              {device.fields.map((field) => {
                const disagree = field.values.filter((value) => value.disagrees);
                return (
                  <div key={field.field} className="cov-field">
                    <div>
                      <div className="name">{field.label}</div>
                      <div className="subline">{field.unified || "—"}</div>
                    </div>
                    {disagree.length === 0 ? (
                      <span className="pill green">Agrees</span>
                    ) : (
                      <div className="disagree">
                        {disagree.map((value) => (
                          <span key={value.source} className="pill orange">{value.source} {value.value}</span>
                        ))}
                      </div>
                    )}
                  </div>
                );
              })}
            </section>
            <section className="card">
              <div className="card-h"><span className="card-t">Changes</span></div>
              {device.events.length === 0 ? <Empty>No coverage changes yet.</Empty> : device.events.map((event) => (
                <div key={event.id} className="row cols-event">
                  <span className="wash" />
                  <div>
                    <div className="name">{eventLine(event.source, event.kind, event.detail)}</div>
                    <div className="subline">{when(event.at)}</div>
                  </div>
                </div>
              ))}
            </section>
          </>
        ) : null}
      </div>
    </Page>
  );
}

export function CoverageConnectorsPage() {
  const [items, setItems] = useState<SourceConnector[]>([]);
  const [error, setError] = useState("");

  useEffect(() => {
    let stop = false;
    const load = () => {
      api.coverageConnectors()
        .then((next) => { if (!stop) { setItems(next.connectors); setError(""); } })
        .catch((err: Error) => { if (!stop) setError(err.message); });
    };
    load();
    const t = setInterval(load, 8000);
    return () => { stop = true; clearInterval(t); };
  }, []);

  return (
    <Page>
      <Toolbar
        title="Connectors"
        lede="Poll health. Credentials stay in Terraform."
        extra={<Link className="capsule" to="/coverage">Matrix</Link>}
      />
      <div className="content fleet">
        {error ? <p className="note">{error}</p> : null}
        <section className="card">
          {items.length === 0 ? <Empty>{error ? "Could not load connectors." : "No connectors configured."}</Empty> : items.map((item, index) => (
            <div key={item.id} className="row cols-connector enter" style={enterStyle(index)}>
              <span className="wash" />
              <span className="initials">{initials(item.source)}</span>
              <div>
                <div className="name">{item.name}</div>
                <div className="subline">{item.mode} · stale after {Math.round(item.stale_after_seconds / 3600)}h</div>
              </div>
              <span className={`pill ${statusKind(item.last_sync_status)}`}>{item.last_sync_status || "pending"}</span>
              <div>
                <div className="name">{item.last_sync_at ? ago(item.last_sync_at) : "Not synced"}</div>
                <div className="subline">{item.last_sync_count} records{item.last_sync_error ? ` · ${item.last_sync_error}` : ""}</div>
              </div>
            </div>
          ))}
        </section>
      </div>
    </Page>
  );
}

function labelState(state: string) {
  if (state === "seen") return "Seen";
  if (state === "stale") return "Stale";
  return "Missing";
}

function initials(source: string) {
  const known: Record<string, string> = {
    osquery: "OQ", munki: "MU", crowdstrike: "CS", rapid7: "R7",
    netskope: "NS", proofpoint: "PP", blastshield: "BS", kolide: "KO",
  };
  return known[source] ?? source.slice(0, 2).toUpperCase();
}

function statusKind(status: string) {
  if (status === "ok") return "green";
  if (status === "degraded") return "orange";
  if (status === "error") return "red";
  return "gray";
}

function eventLine(source: string, kind: string, detail: Record<string, unknown>) {
  const value = detail.value == null ? "" : String(detail.value);
  const field = detail.field == null ? "" : String(detail.field).replaceAll("_", " ");
  switch (kind) {
    case "source_seen":
      return `${source} started seeing this endpoint`;
    case "source_lost":
      return `${source} stopped seeing this endpoint`;
    case "field_disagreement":
      return `${source} ${field} disagrees${value ? `: ${value}` : ""}`;
    case "rematched":
      return `${source} was matched again`;
    case "identity_conflict":
      return `${source} identity conflict`;
    default:
      return `${source} ${kind.replaceAll("_", " ")}`;
  }
}
