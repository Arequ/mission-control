import { useEffect, useState, type CSSProperties } from "react";
import { Link, NavLink, useLocation, useParams } from "react-router-dom";
import { api, type Device, type DeviceEvent } from "../api";
import { Icon } from "../icons";
import { LiveQueryPanel } from "./LiveQuery";
import { DeviceVulnerabilities } from "./Vulnerabilities";
import { Empty, Page, StatusPill, ago, enterStyle, gigabytes, match, uptime, useSearch } from "../ui";

export function DevicePage() {
  const { id = "" } = useParams();
  const { pathname } = useLocation();
  const [device, setDevice] = useState<Device | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    let stop = false;
    const load = () => {
      api.device(id)
        .then((next) => { if (!stop) { setDevice(next); setError(""); } })
        .catch((err: Error) => { if (!stop) setError(err.message); });
    };
    load();
    const t = setInterval(load, 8000);
    return () => { stop = true; clearInterval(t); };
  }, [id]);

  const tab = pathname.endsWith("/software")
    ? "software"
    : pathname.endsWith("/queries")
      ? "queries"
      : pathname.endsWith("/vulnerabilities")
        ? "vulnerabilities"
        : "overview";

  return (
    <Page>
      <div className="content fleet device-page">
        {error ? <p className="note">{error}</p> : null}
        {device ? (
          <>
            <header className="hero enter" style={enterStyle(0)}>
              <span className="hero-mark"><Icon name="laptop" size={28} /></span>
              <div className="hero-copy">
                <div className="hero-title">
                  <h1>{device.computer_name || device.hostname}</h1>
                  <StatusPill status={device.status} />
                  {device.coverage ? (
                    <Link className="coverage-chip" to={`/coverage/devices/${device.id}`}>
                      Coverage {device.coverage.seen}/{device.coverage.total}
                    </Link>
                  ) : null}
                  <Link className="coverage-chip quiet" to={`/logs?device=${device.id}`}>Logs for this device</Link>
                </div>
                <div className="sub">
                  {[device.username, device.model_name || device.hardware_model, device.cpu_brand, device.os_display || device.os_version]
                    .filter(Boolean)
                    .join("  ·  ")}
                </div>
              </div>
            </header>
            <DeviceTabs id={device.id} tab={tab} />
            {tab === "overview" ? <DeviceOverview device={device} /> : null}
            {tab === "software" ? <DeviceSoftware device={device} /> : null}
            {tab === "queries" ? <LiveQueryPanel deviceId={device.id} deviceName={device.computer_name || device.hostname} /> : null}
            {tab === "vulnerabilities" ? <DeviceVulnerabilities id={device.id} /> : null}
          </>
        ) : null}
      </div>
    </Page>
  );
}

function DeviceTabs({ id, tab }: { id: string; tab: string }) {
  const items = [
    { to: `/devices/${id}`, label: "Overview", on: tab === "overview" },
    { to: `/devices/${id}/software`, label: "Software", on: tab === "software" },
    { to: `/devices/${id}/queries`, label: "Queries", on: tab === "queries" },
    { to: `/devices/${id}/vulnerabilities`, label: "Vulnerabilities", on: tab === "vulnerabilities" },
  ];
  const index = Math.max(0, items.findIndex((item) => item.on));
  return (
    <div className="seg" style={{ "--n": items.length, "--i": index } as CSSProperties}>
      <span className="seg-thumb" />
      {items.map((item) => (
        <NavLink key={item.to} to={item.to} end className={item.on ? "on" : undefined}>{item.label}</NavLink>
      ))}
    </div>
  );
}

function DeviceOverview({ device }: { device: Device }) {
  const enc = device.disk_encrypted == null ? "Unknown" : device.disk_encrypted ? "FileVault on" : "FileVault off";
  return (
    <>
      <div className="facts">
        <Fact k="Serial" v={device.serial || "—"} />
        <Fact k="Memory" v={gigabytes(device.physical_memory)} />
        <Fact k="Disk" v={enc} />
        <Fact k="Last seen" v={ago(device.last_seen_at)} />
        <Fact k="Address" v={device.primary_ip || "—"} />
        <Fact k="Uptime" v={uptime(device.uptime_seconds)} />
        <Fact k="osquery" v={device.osquery_version || "—"} />
        <Fact k="Labels" v={device.labels?.length ? device.labels.join(", ") : "None"} />
      </div>
      <section className="card">
        <div className="card-h"><span className="card-t">Recent changes</span></div>
        {(device.events ?? []).length === 0 ? <Empty>No changes recorded yet.</Empty> : (
          device.events!.map((event) => (
            <div key={event.id} className="row cols-event">
              <span className="wash" />
              <div>
                <div className="name">{eventLine(event)}</div>
                <div className="subline">{ago(event.at)}</div>
              </div>
            </div>
          ))
        )}
      </section>
    </>
  );
}

function Fact({ k, v }: { k: string; v: string }) {
  return (
    <div className="fact">
      <span>{k}</span>
      <b>{v}</b>
    </div>
  );
}

function eventLine(event: DeviceEvent) {
  const d = event.detail ?? {};
  const str = (key: string) => (d[key] == null ? "" : String(d[key]));
  switch (event.action) {
    case "os_version_changed":
      return `macOS ${str("from")} → ${str("to")}`;
    case "hostname_changed":
      return `Hostname ${str("from")} → ${str("to")}`;
    case "user_changed":
      return `User ${str("from")} → ${str("to")}`;
    case "disk_encryption_changed":
      return str("to") === "true" ? "FileVault turned on" : "FileVault turned off";
    case "app_installed":
      return `${str("name")} ${str("version")} installed`;
    case "app_updated":
      return `${str("name")} ${str("from")} → ${str("to")}`;
    case "app_removed":
      return `${str("name")} removed`;
    case "enrolled":
      return "Enrolled";
    case "reenrolled":
      return "Re-enrolled";
    case "invalidate_node":
      return "Node key invalidated";
    default:
      return event.action.replaceAll("_", " ");
  }
}

function DeviceSoftware({ device }: { device: Device }) {
  const { q } = useSearch();
  const apps = (device.apps ?? []).filter((app) => match(q, app.name, app.bundle_id, app.version));
  return (
    <section className="card">
      <div className="card-h">
        <span className="card-t">Installed applications</span>
        <span className="faint">{apps.length}</span>
      </div>
      {apps.length === 0 ? <Empty>No applications in the latest inventory.</Empty> : (
        <>
          <div className="list-h cols-app"><span>Application</span><span className="right">Version</span></div>
          {apps.map((app) => (
            <div key={app.path || app.name} className="row cols-app loose">
              <span className="wash" />
              <div>
                <div className="name">{app.name}</div>
                <div className="subline mono">{app.bundle_id}</div>
              </div>
              <div className="right tnum">{app.version}</div>
            </div>
          ))}
        </>
      )}
    </section>
  );
}
