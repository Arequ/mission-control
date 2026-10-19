import { FormEvent, useEffect, useMemo, useState } from "react";
import { api, type Device, type LiveQuery, type OsqueryLabel } from "../api";
import { Empty, StatusPill, enterStyle } from "../ui";

export function LiveQueryPanel({
  deviceId,
  deviceName,
}: {
  deviceId?: string;
  deviceName?: string;
}) {
  const [sql, setSql] = useState("SELECT hostname, uuid, cpu_brand FROM system_info;");
  const [labels, setLabels] = useState<OsqueryLabel[]>([]);
  const [devices, setDevices] = useState<Device[]>([]);
  const [label, setLabel] = useState("");
  const [picked, setPicked] = useState(deviceId ?? "");
  const [timeoutSec, setTimeoutSec] = useState(30);
  const [query, setQuery] = useState<LiveQuery | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => { setPicked(deviceId ?? ""); }, [deviceId]);

  useEffect(() => {
    if (deviceId) return;
    api.labels().then((res) => setLabels(res.labels)).catch(() => {});
    api.devices({ limit: 100 }).then((res) => setDevices(res.devices)).catch(() => {});
  }, [deviceId]);

  const queryId = query?.id;
  const queryStatus = query?.status;
  useEffect(() => {
    if (!queryId || queryStatus === "complete") return;
    const t = setInterval(() => {
      api.liveQuery(queryId)
        .then(setQuery)
        .catch((err: Error) => setError(err.message));
    }, 800);
    return () => clearInterval(t);
  }, [queryId, queryStatus]);

  const columns = useMemo(() => {
    const rows = query?.rows ?? [];
    const keys: string[] = [];
    for (const row of rows) {
      for (const key of Object.keys(row)) {
        if (!keys.includes(key)) keys.push(key);
      }
    }
    keys.sort((a, b) => (a === "mc_device" ? -1 : b === "mc_device" ? 1 : a.localeCompare(b)));
    return keys;
  }, [query]);

  const submit = (event: FormEvent) => {
    event.preventDefault();
    const device_ids = (deviceId || picked) ? [deviceId || picked] : [];
    const labelNames = label ? [label] : [];
    if (device_ids.length === 0 && labelNames.length === 0) {
      setError("Choose a device or a label.");
      return;
    }
    setBusy(true);
    setError("");
    api.runLive({ sql, device_ids, labels: labelNames, timeout_seconds: timeoutSec })
      .then((next) => { setQuery(next); })
      .catch((err: Error) => setError(err.message))
      .finally(() => setBusy(false));
  };

  const waiting = query && query.status !== "complete" && (query.rows ?? []).length === 0;

  return (
    <div className="stack">
      <form className="card enter" style={enterStyle(0)} onSubmit={submit}>
        <div className="card-h">
          <span className="card-t">{deviceName ? `Live query · ${deviceName}` : "Live query"}</span>
        </div>
        <div className="pad">
          <textarea className="sql" value={sql} onChange={(e) => setSql(e.target.value)} aria-label="SQL" spellCheck={false} />
          <div className="filters">
            {deviceId ? null : (
              <>
                <select className="field select" aria-label="Device" value={picked} onChange={(e) => setPicked(e.target.value)}>
                  <option value="">All devices in a label</option>
                  {devices.map((device) => (
                    <option key={device.id} value={device.id}>{device.computer_name || device.hostname}</option>
                  ))}
                </select>
                <select className="field select" aria-label="Label" value={label} onChange={(e) => setLabel(e.target.value)}>
                  <option value="">No label</option>
                  {labels.map((item) => (
                    <option key={item.id} value={item.name}>{item.name}</option>
                  ))}
                </select>
              </>
            )}
            <label className="timeout">
              Timeout
              <input
                className="field timeout-in"
                type="number"
                min={1}
                max={3600}
                value={timeoutSec}
                aria-label="Timeout seconds"
                onChange={(e) => setTimeoutSec(Number(e.target.value) || 30)}
              />
              <span className="faint">s</span>
            </label>
            <button className="capsule primary" type="submit" disabled={busy}>Run</button>
          </div>
          {error ? <p className="note">{error}</p> : null}
        </div>
      </form>
      {query ? (
        <section className="card enter" style={enterStyle(1)}>
          <div className="card-h">
            <span className="card-t">Results</span>
            <span className="faint">{(query.rows ?? []).length} rows</span>
            <span className="grow" />
            {(query.targets ?? []).slice(0, 4).map((target) => (
              <StatusPill key={target.device_id} status={target.status} />
            ))}
          </div>
          {waiting ? <Empty>Waiting for the agent…</Empty> : null}
          {!waiting && (query.rows ?? []).length === 0 ? <Empty>The query finished with no rows.</Empty> : null}
          {(query.rows ?? []).length > 0 ? (
            <div className="table-wrap">
              <table className="result">
                <thead>
                  <tr>{columns.map((col) => <th key={col}>{col === "mc_device" ? "Device" : col}</th>)}</tr>
                </thead>
                <tbody>
                  {query.rows!.map((row, index) => (
                    <tr key={index}>
                      {columns.map((col) => <td key={col} className={col === "mc_device" ? "" : "mono"}>{row[col] ?? ""}</td>)}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : null}
        </section>
      ) : null}
    </div>
  );
}
