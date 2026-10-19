import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, type Device, type OsqueryLabel } from "../api";
import { Empty, Mark, Page, StatusPill, Toolbar, ago, enterStyle, useSearch } from "../ui";

const pageSize = 25;

export function DevicesPage() {
  const { q } = useSearch();
  const [status, setStatus] = useState("");
  const [label, setLabel] = useState("");
  const [labels, setLabels] = useState<OsqueryLabel[]>([]);
  const [devices, setDevices] = useState<Device[]>([]);
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(0);
  const [error, setError] = useState("");
  const filters = `${q}\0${status}\0${label}`;
  const [filterSnap, setFilterSnap] = useState(filters);
  if (filterSnap !== filters) {
    setFilterSnap(filters);
    if (offset !== 0) setOffset(0);
  }

  useEffect(() => {
    api.labels().then((res) => setLabels(res.labels)).catch(() => {});
  }, []);

  useEffect(() => {
    let stop = false;
    const load = () => {
      api.devices({ q, status, label, limit: pageSize, offset })
        .then((res) => {
          if (stop) return;
          setDevices(res.devices);
          setTotal(res.total);
          setError("");
        })
        .catch((err: Error) => { if (!stop) setError(err.message); });
    };
    load();
    const t = setInterval(load, 8000);
    return () => { stop = true; clearInterval(t); };
  }, [q, status, label, offset]);

  return (
    <Page>
      <Toolbar title="Devices" lede={total ? `${total} enrolled` : "Enrolled Macs"} />
      <div className="content fleet">
        {error ? <p className="note">{error}</p> : null}
        <div className="filters">
          {["", "online", "offline"].map((value) => (
            <button
              key={value || "all"}
              type="button"
              className={`filter${status === value ? " on" : ""}`}
              onClick={() => setStatus(value)}
            >
              {value === "" ? "All" : value === "online" ? "Online" : "Offline"}
            </button>
          ))}
          <select className="field select" aria-label="Label" value={label} onChange={(e) => setLabel(e.target.value)}>
            <option value="">Any label</option>
            {labels.map((item) => (
              <option key={item.id} value={item.name}>{item.name}</option>
            ))}
          </select>
        </div>
        <section className="card">
          {devices.length === 0 ? (
            <Empty>{error ? "Could not load devices." : "No devices match."}</Empty>
          ) : (
            <>
              <div className="list-h cols-device">
                <span>Device</span><span>User</span><span>macOS</span><span>Seen</span><span></span>
              </div>
              {devices.map((device, index) => (
                <Link key={device.id} to={`/devices/${device.id}`} className="row cols-device loose enter" style={enterStyle(index)}>
                  <span className="wash" />
                  <div className="who">
                    <Mark name={device.computer_name || device.hostname} />
                    <div className="id">
                      <div className="name">{device.computer_name || device.hostname}</div>
                      <div className="subline">{device.model_name || device.hardware_model} · {device.serial}</div>
                    </div>
                  </div>
                  <div className="muted">{device.username || "—"}</div>
                  <div>
                    <div>{device.os_display || device.os_version || "—"}</div>
                    <div className="subline">{device.os_build}</div>
                  </div>
                  <div className="muted">{ago(device.last_seen_at)}</div>
                  <div className="end"><StatusPill status={device.status} /></div>
                </Link>
              ))}
              <div className="pager">
                <span className="faint">{total === 0 ? "Showing 0" : `Showing ${offset + 1}–${offset + devices.length} of ${total}`}</span>
                <span className="grow" />
                <button className="capsule" type="button" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - pageSize))}>Previous</button>
                <button className="capsule" type="button" disabled={offset + pageSize >= total} onClick={() => setOffset(offset + pageSize)}>Next</button>
              </div>
            </>
          )}
        </section>
      </div>
    </Page>
  );
}
