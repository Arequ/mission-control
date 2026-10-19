import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState, type CSSProperties, type UIEvent } from "react";
import { Link, useParams, useSearchParams } from "react-router-dom";
import { api, type Device, type LogContext, type LogLine, type LogPage, type LogView } from "../api";
import { Icon } from "../icons";
import { Empty, Managed, Page, ProposeChange, Toolbar, enterStyle, match, useSearch } from "../ui";

const WINDOWS = ["15m", "1h", "6h", "24h", "7d", "30d"] as const;
const ROW = 24;
const PAGE_SIZE = 800;
const MAX_KEPT = 100_000;

export function LogsPage() {
  const { q } = useSearch();
  const [params] = useSearchParams();
  const deviceId = params.get("device") ?? "";
  const [views, setViews] = useState<LogView[]>([]);
  const [device, setDevice] = useState<Device | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    api.logViews().then((res) => setViews(res.views)).catch((err: Error) => setError(err.message));
  }, []);
  useEffect(() => {
    if (!deviceId) return;
    api.device(deviceId).then(setDevice).catch(() => setDevice(null));
  }, [deviceId]);

  const shown = views.filter((view) => match(q, view.name, view.description, ...view.sources.map((src) => src.label)));
  const query = deviceId ? `?device=${encodeURIComponent(deviceId)}` : "";

  return (
    <Page>
      <Toolbar
        title="Logs"
        badge
        lede="Named views. The lines read the way they do in the file."
        extra={<ProposeChange />}
      />
      <div className="content fleet">
        {error ? <p className="note">{error}</p> : null}
        {device ? (
          <div className="card log-device-banner enter">
            <Icon name="laptop" size={16} />
            <div>
              <div className="name">Logs for {device.computer_name || device.hostname}</div>
              <div className="subline">{[device.serial, device.hostname].filter(Boolean).join(" · ")} · device-scoped views bind this record</div>
            </div>
          </div>
        ) : null}
        <section className="card enter" style={enterStyle(1)}>
          <div className="card-h">
            <span className="card-t">Views</span>
            <span className="faint">{shown.length}</span>
            <span className="grow" />
            <Managed small />
          </div>
          {shown.length === 0 ? <Empty>No log views yet. They appear when Terraform applies.</Empty> : shown.map((view) => (
            <Link key={view.id} className="row log-view-row" to={`/logs/${view.id}${query}`}>
              <span className="wash" />
              <div className="log-view-name">
                <div className="name">{view.name}</div>
                <div className="subline">{view.description || "Merged message lines"}</div>
              </div>
              <div className="source-pills">
                {view.sources.map((src) => (
                  <span key={src.label} className="source-pill">
                    <i style={{ background: src.color || "var(--accent)" }} />
                    {src.label}
                  </span>
                ))}
              </div>
              <span className="faint tnum">{view.default_window}</span>
              <span className={`pill ${view.device_scoped ? "blue" : "gray"}`}>{view.device_scoped ? "Device" : "Fleet"}</span>
            </Link>
          ))}
        </section>
      </div>
    </Page>
  );
}

export function LogViewerPage() {
  const { id = "" } = useParams();
  const [params, setParams] = useSearchParams();
  const [view, setView] = useState<LogView | null>(null);
  const [devices, setDevices] = useState<Device[]>([]);
  const [deviceId, setDeviceId] = useState(params.get("device") ?? "");
  const [win, setWin] = useState("1h");
  const [winReady, setWinReady] = useState(false);
  const [lines, setLines] = useState<LogLine[]>([]);
  const [hasBefore, setHasBefore] = useState(false);
  const [hasAfter, setHasAfter] = useState(false);
  const [truncated, setTruncated] = useState(false);
  const [tail, setTail] = useState(false);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [copied, setCopied] = useState(false);
  const [jump, setJump] = useState("");
  const [context, setContext] = useState<LogContext | null>(null);
  const [focus, setFocus] = useState("");
  const [fresh, setFresh] = useState<string[]>([]);
  const [scrollTop, setScrollTop] = useState(0);
  const [height, setHeight] = useState(480);
  const cursor = useRef("");
  const beforeRef = useRef(false);
  const afterRef = useRef(false);
  const busy = useRef(false);
  const stick = useRef(true);
  const gen = useRef(0);
  const adjust = useRef(0);
  const scroller = useRef<HTMLDivElement>(null);

  useEffect(() => {
    let stop = false;
    setWinReady(false);
    api.logView(id).then((next) => {
      if (stop) return;
      setView(next);
      setWin(next.default_window || "1h");
      setWinReady(true);
    }).catch((err: Error) => { if (!stop) setError(err.message); });
    return () => { stop = true; };
  }, [id]);

  useEffect(() => {
    if (!view?.device_scoped) return;
    api.devices({ limit: 200 }).then((res) => setDevices(res.devices)).catch(() => {});
  }, [view?.device_scoped]);

  const applyPage = useCallback((page: LogPage, mode: "replace" | "prepend" | "append") => {
    cursor.current = page.cursor || cursor.current;
    if (mode === "replace") {
      setLines(page.lines ?? []);
      setHasBefore(page.has_more_before);
      setHasAfter(page.has_more_after);
      beforeRef.current = page.has_more_before;
      afterRef.current = page.has_more_after;
      setTruncated(page.truncated);
      setFresh([]);
      return;
    }
    setLines((current) => {
      const incoming = page.lines ?? [];
      const ids = new Set(current.map((line) => line.id));
      const freshLines = incoming.filter((line) => !ids.has(line.id));
      if (mode === "prepend") {
        adjust.current = freshLines.length * ROW;
        const next = [...freshLines, ...current];
        return next.length > MAX_KEPT ? next.slice(0, MAX_KEPT) : next;
      }
      setFresh(freshLines.map((line) => line.id));
      const next = [...current, ...freshLines];
      return next.length > MAX_KEPT ? next.slice(next.length - MAX_KEPT) : next;
    });
    if (mode === "prepend") {
      setHasBefore(page.has_more_before);
      beforeRef.current = page.has_more_before;
    }
    if (mode === "append") {
      setHasAfter(page.has_more_after);
      afterRef.current = page.has_more_after;
      if (page.has_more_before) {
        setHasBefore(true);
        beforeRef.current = true;
      }
    }
    if (page.truncated) setTruncated(true);
  }, []);

  const loadWindow = useCallback(async (range?: { from: string; to: string; align: string }) => {
    if (!view) return;
    if (view.device_scoped && !deviceId) {
      setLines([]);
      setError("");
      return;
    }
    const token = ++gen.current;
    setLoading(true);
    setError("");
    setContext(null);
    setFocus("");
    stick.current = (range?.align ?? "end") !== "start";
    const to = range?.to ?? new Date().toISOString();
    const from = range?.from ?? new Date(Date.now() - windowMs(win)).toISOString();
    try {
      const page = await api.queryLog(view.id, {
        from, to, limit: PAGE_SIZE, align: range?.align ?? "end",
        device_id: view.device_scoped ? deviceId : undefined,
      });
      if (token !== gen.current) return;
      applyPage(page, "replace");
    } catch (err) {
      if (token === gen.current) setError(err instanceof Error ? err.message : "log query failed");
    } finally {
      if (token === gen.current) setLoading(false);
    }
  }, [applyPage, deviceId, view, win]);

  useEffect(() => {
    if (!view || !winReady) return;
    void loadWindow();
  }, [view, win, deviceId, winReady, loadWindow]);

  const loadOlder = useCallback(async () => {
    if (!view || busy.current || !beforeRef.current || !cursor.current) return;
    busy.current = true;
    stick.current = false;
    try {
      const page = await api.queryLog(view.id, {
        cursor: cursor.current, dir: "backward", limit: PAGE_SIZE,
        device_id: view.device_scoped ? deviceId : undefined,
      });
      applyPage(page, "prepend");
    } catch (err) {
      setError(err instanceof Error ? err.message : "log query failed");
    } finally {
      busy.current = false;
    }
  }, [applyPage, deviceId, view]);

  const loadNewer = useCallback(async () => {
    if (!view || busy.current || !afterRef.current || !cursor.current) return;
    busy.current = true;
    try {
      const page = await api.queryLog(view.id, {
        cursor: cursor.current, dir: "forward", limit: PAGE_SIZE,
        device_id: view.device_scoped ? deviceId : undefined,
      });
      applyPage(page, "append");
    } catch (err) {
      setError(err instanceof Error ? err.message : "log query failed");
    } finally {
      busy.current = false;
    }
  }, [applyPage, deviceId, view]);

  useEffect(() => {
    if (!tail || !view || !cursor.current) return;
    let stop = false;
    const poll = async () => {
      if (stop || busy.current || !cursor.current) return;
      busy.current = true;
      try {
        const page = await api.tailLog(view.id, {
          cursor: cursor.current, limit: 400,
          device_id: view.device_scoped ? deviceId : undefined,
        });
        if (!stop) applyPage(page, "append");
      } catch (err) {
        if (!stop) setError(err instanceof Error ? err.message : "tail failed");
      } finally {
        busy.current = false;
      }
    };
    const timer = setInterval(() => { void poll(); }, 2000);
    return () => { stop = true; clearInterval(timer); };
  }, [applyPage, deviceId, tail, view]);

  useLayoutEffect(() => {
    const el = scroller.current;
    if (!el) return;
    if (adjust.current) {
      el.scrollTop += adjust.current;
      adjust.current = 0;
      setScrollTop(el.scrollTop);
      return;
    }
    if (stick.current) {
      el.scrollTop = el.scrollHeight;
      setScrollTop(el.scrollTop);
    }
  }, [lines]);

  useEffect(() => {
    const el = scroller.current;
    if (!el) return;
    const watch = new ResizeObserver(() => setHeight(el.clientHeight));
    watch.observe(el);
    setHeight(el.clientHeight);
    return () => watch.disconnect();
  }, [view]);

  const onScroll = (event: UIEvent<HTMLDivElement>) => {
    const el = event.currentTarget;
    setScrollTop(el.scrollTop);
    const nearBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 40;
    stick.current = nearBottom;
    if (el.scrollTop < 96) void loadOlder();
    if (nearBottom && !tail) void loadNewer();
  };

  const openContext = async (line: LogLine) => {
    if (!view) return;
    if (focus === line.id) {
      setFocus("");
      setContext(null);
      return;
    }
    setFocus(line.id);
    try {
      const next = await api.contextLog(view.id, {
        line_id: line.id, before: 40, after: 40,
        device_id: view.device_scoped ? deviceId : undefined,
      });
      setContext(next);
    } catch (err) {
      setError(err instanceof Error ? err.message : "context failed");
    }
  };

  const copyLines = async () => {
    try {
      await navigator.clipboard.writeText(plain(lines));
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1200);
    } catch {
      setError("clipboard unavailable");
    }
  };

  const download = () => {
    const blob = new Blob([plain(lines) + (lines.length ? "\n" : "")], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${(view?.name || "log").toLowerCase().replace(/[^a-z0-9]+/g, "-")}.log`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const doJump = () => {
    if (!view || !jump) return;
    const from = wallToUTC(jump, view.time_zone || "UTC");
    if (!from) return;
    const to = new Date(new Date(from).getTime() + windowMs(win)).toISOString();
    setTail(false);
    void loadWindow({ from, to, align: "start" });
  };

  const start = Math.max(0, Math.floor(scrollTop / ROW) - 10);
  const end = Math.min(lines.length, Math.ceil((scrollTop + height) / ROW) + 10);
  const slice = lines.slice(start, end);
  const multi = (view?.sources.length ?? 0) > 1;
  const zone = view?.time_zone || "UTC";
  const winIndex = Math.max(0, WINDOWS.indexOf(win as (typeof WINDOWS)[number]));

  const deviceName = useMemo(() => {
    const found = devices.find((item) => item.id === deviceId);
    return found ? (found.computer_name || found.hostname) : "";
  }, [deviceId, devices]);

  return (
    <div className="page logs-shell">
      <Toolbar
        title={view?.name || "Log"}
        badge
        lede={view?.description}
        extra={
          <>
            <Link className="capsule" to={`/logs${deviceId ? `?device=${encodeURIComponent(deviceId)}` : ""}`}>All views</Link>
            <Managed />
            <ProposeChange />
          </>
        }
      />
      <div className="log-controls">
        <div className="seg log-wins" style={{ "--n": WINDOWS.length, "--i": winIndex } as CSSProperties}>
          <span className="seg-thumb" />
          {WINDOWS.map((item) => (
            <button key={item} type="button" className={item === win ? "on" : undefined} onClick={() => { setTail(false); setWin(item); }}>
              {item}
            </button>
          ))}
        </div>
        {view?.device_scoped ? (
          <select
            className="field select"
            aria-label="Device"
            value={deviceId}
            onChange={(event) => {
              setDeviceId(event.target.value);
              setParams(event.target.value ? { device: event.target.value } : {}, { replace: true });
            }}
          >
            <option value="">Choose a device</option>
            {devices.map((item) => (
              <option key={item.id} value={item.id}>{item.computer_name || item.hostname}</option>
            ))}
          </select>
        ) : null}
        <form className="log-jump" onSubmit={(event) => { event.preventDefault(); doJump(); }}>
          <input
            className="field"
            type="datetime-local"
            aria-label={`Jump to time (${zone})`}
            value={jump}
            onChange={(event) => setJump(event.target.value)}
          />
          <button className="capsule" type="submit">Jump</button>
        </form>
        <span className="grow" />
        <button className={`capsule${tail ? " primary" : ""}`} type="button" onClick={() => setTail((on) => !on)} aria-pressed={tail}>
          <span className={`dot${tail ? " live" : ""}`} style={{ width: 6, height: 6, background: tail ? "var(--green)" : "var(--text-3)" }} />
          Live
        </button>
        <button className="capsule" type="button" onClick={() => { void copyLines(); }} disabled={lines.length === 0}>{copied ? "Copied" : "Copy"}</button>
        <button className="capsule" type="button" onClick={download} disabled={lines.length === 0}>Download</button>
      </div>
      {error ? <p className="note log-note">{error}</p> : null}
      <div className={`log-frame${context ? " with-context" : ""}`}>
        <div className="log-meta">
          <span>{loading ? "Reading…" : `${lines.length.toLocaleString()} lines`}</span>
          {deviceName ? <span>{deviceName}</span> : null}
          <span>{zone}</span>
          {truncated ? <span>Capped by max lines</span> : null}
          {hasBefore ? <span>Older lines above</span> : null}
          {hasAfter ? <span>Newer lines below</span> : null}
        </div>
        <div className="log-scroll" ref={scroller} onScroll={onScroll} role="log" aria-label={view?.name || "Log"}>
          {view?.device_scoped && !deviceId ? (
            <div className="log-empty">Choose a device to read this view.</div>
          ) : lines.length === 0 && !loading ? (
            <div className="log-empty">No lines in this window.</div>
          ) : (
            <div className="log-canvas" style={{ height: lines.length * ROW }}>
              {slice.map((line, index) => (
                <button
                  key={line.id}
                  type="button"
                  className={`log-row${multi ? " multi" : ""}${line.id === focus ? " on" : ""}${fresh.includes(line.id) ? " fresh" : ""}`}
                  style={{ transform: `translateY(${(start + index) * ROW}px)` }}
                  onClick={() => { void openContext(line); }}
                  title={`${line.host || "host"} · ${line.file || line.source}`}
                >
                  <span className="gutter" style={{ background: line.color || "var(--accent)" }} />
                  <time dateTime={line.timestamp}>{formatStamp(line.timestamp, zone)}</time>
                  {multi ? <span className="src" style={{ color: line.color || "var(--text-2)" }}>{line.source}</span> : null}
                  <span className="file">{baseName(line.file) || line.source}</span>
                  <span className="msg">{line.message}</span>
                </button>
              ))}
            </div>
          )}
        </div>
        {context ? (
          <aside className="log-context" aria-label="Context">
            <div className="log-context-h">
              <span>Context</span>
              <button className="capsule icon" type="button" aria-label="Close context" onClick={() => { setContext(null); setFocus(""); }}>
                <Icon name="x" size={14} />
              </button>
            </div>
            <div className="log-context-body">
              {context.lines.map((line, index) => (
                <div key={line.id} className={`log-context-line${index === context.focus ? " on" : ""}`}>
                  <span className="gutter" style={{ background: line.color || "var(--accent)" }} />
                  <span className="msg">{line.message}</span>
                </div>
              ))}
            </div>
          </aside>
        ) : null}
      </div>
    </div>
  );
}

function plain(lines: LogLine[]) {
  return lines.map((line) => line.message).join("\n");
}

function baseName(path: string) {
  if (!path) return "";
  const cut = path.lastIndexOf("/");
  return cut >= 0 ? path.slice(cut + 1) : path;
}

function windowMs(value: string) {
  const n = Number.parseInt(value, 10);
  if (!Number.isFinite(n) || n <= 0) return 60 * 60 * 1000;
  const unit = value.slice(-1);
  if (unit === "m") return n * 60 * 1000;
  if (unit === "h") return n * 60 * 60 * 1000;
  return n * 24 * 60 * 60 * 1000;
}

function wallToUTC(wall: string, timeZone: string) {
  const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})/.exec(wall);
  if (!match) return "";
  const [, ys, ms, ds, hs, mins] = match;
  const y = Number(ys);
  const m = Number(ms);
  const d = Number(ds);
  const h = Number(hs);
  const min = Number(mins);
  const guess = Date.UTC(y, m - 1, d, h, min, 0);
  const offset = zoneOffset(guess, timeZone);
  const corrected = guess - zoneOffset(guess - offset, timeZone);
  return new Date(corrected).toISOString();
}

function zoneOffset(utcMs: number, timeZone: string) {
  const parts = new Intl.DateTimeFormat("en-US", {
    timeZone, hourCycle: "h23",
    year: "numeric", month: "2-digit", day: "2-digit",
    hour: "2-digit", minute: "2-digit", second: "2-digit",
  }).formatToParts(new Date(utcMs));
  const get = (type: string) => Number(parts.find((part) => part.type === type)?.value ?? "0");
  const asUTC = Date.UTC(get("year"), get("month") - 1, get("day"), get("hour") % 24, get("minute"), get("second"));
  return asUTC - utcMs;
}

function formatStamp(iso: string, timeZone: string) {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  const parts = new Intl.DateTimeFormat("en-GB", {
    timeZone, hourCycle: "h23",
    month: "short", day: "2-digit",
    hour: "2-digit", minute: "2-digit", second: "2-digit",
  }).formatToParts(date);
  const get = (type: string) => parts.find((part) => part.type === type)?.value ?? "";
  const ms = String(date.getMilliseconds()).padStart(3, "0");
  return `${get("day")} ${get("month")} ${get("hour")}:${get("minute")}:${get("second")}.${ms}`;
}
