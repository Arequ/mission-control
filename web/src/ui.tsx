import { createContext, useContext, useEffect, useLayoutEffect, useState, type CSSProperties, type ReactNode } from "react";
import { flushSync } from "react-dom";
import { NavLink, Outlet, useLocation, useNavigate } from "react-router-dom";
import { api, clearToken } from "./api";
import { Icon, type IconName } from "./icons";

type Theme = "light" | "dark";
const THEME_KEY = "mc.theme";

type ThemeCtx = { theme: Theme; setTheme: (next: Theme) => void };
const ThemeContext = createContext<ThemeCtx>({ theme: "light", setTheme: () => {} });
const SearchContext = createContext({ q: "", setQ: (_value: string) => { void _value; } });

export function useTheme() {
  return useContext(ThemeContext);
}
export function useSearch() {
  return useContext(SearchContext);
}

function readTheme(): Theme {
  return document.documentElement.classList.contains("dark") ? "dark" : "light";
}

export function Providers({ children }: { children: ReactNode }) {
  const [theme, setThemeState] = useState<Theme>(readTheme);
  const [q, setQ] = useState("");
  const setTheme = (next: Theme) => {
    const apply = () => {
      document.documentElement.classList.toggle("dark", next === "dark");
      try { localStorage.setItem(THEME_KEY, next); } catch { /* private mode */ }
      setThemeState(next);
    };
    const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    const vt = document as Document & { startViewTransition?: (cb: () => void) => void };
    if (reduce || !vt.startViewTransition) {
      apply();
      return;
    }
    vt.startViewTransition(() => { flushSync(apply); });
  };
  return (
    <ThemeContext.Provider value={{ theme, setTheme }}>
      <SearchContext.Provider value={{ q, setQ }}>{children}</SearchContext.Provider>
    </ThemeContext.Provider>
  );
}

function section(path: string) {
  if (path.startsWith("/munki")) return "munki";
  if (path.startsWith("/settings")) return "settings";
  if (path.startsWith("/coverage")) return "coverage";
  if (path.startsWith("/devices")) return "devices";
  if (path.startsWith("/queries")) return "queries";
  if (path.startsWith("/autopkg") || path.startsWith("/runs") || path.startsWith("/runners")) return "autopkg";
  return "overview";
}

export function Layout() {
  const { pathname } = useLocation();
  const { theme, setTheme } = useTheme();
  const { q, setQ } = useSearch();
  const active = section(pathname);
  const [y, setY] = useState(0);
  const [ready, setReady] = useState(false);
  const [counts, setCounts] = useState({ recipes: 0, packages: 0, devices: 0 });
  const [apiOk, setApiOk] = useState(true);

  useLayoutEffect(() => {
    const el = document.getElementById(`nav-${active}`);
    if (!el) return;
    setY(el.offsetTop);
    setReady(true);
  }, [active]);

  useEffect(() => {
    const onResize = () => {
      const el = document.getElementById(`nav-${active}`);
      if (el) setY(el.offsetTop);
    };
    window.addEventListener("resize", onResize);
    return () => window.removeEventListener("resize", onResize);
  }, [active]);

  useEffect(() => {
    let stop = false;
    const load = () => {
      fetch("/healthz")
        .then((health) => { if (!stop) setApiOk(health.ok); })
        .catch(() => { if (!stop) setApiOk(false); });
      api.recipes().then((recipes) => { if (!stop) setCounts((c) => ({ ...c, recipes: recipes.recipes.length })); }).catch(() => {});
      api.packages().then((packages) => { if (!stop) setCounts((c) => ({ ...c, packages: packages.packages.length })); }).catch(() => {});
      api.summary().then((summary) => { if (!stop) setCounts((c) => ({ ...c, devices: summary.total_devices })); }).catch(() => {});
    };
    load();
    const t = setInterval(load, 8000);
    return () => { stop = true; clearInterval(t); };
  }, []);

  return (
    <div className="shell">
      <header className="topbar">
        <NavLink to="/" className="brand">
          <span className="mark"><Icon name="orbit" size={15} /></span>
          Mission Control
        </NavLink>
        <span className="slash">/</span>
        <div className="org"><span className="monogram">L</span>Local</div>
        <span className="envpill"><span className="dot" style={{ width: 6, height: 6 }} />local</span>
        <div className="top-search">
          <label className="gsearch">
            <Icon name="search" size={15} />
            <input
              value={q}
              onChange={(event) => setQ(event.target.value)}
              placeholder="Search devices, software, recipes…"
              aria-label="Search"
            />
            {q ? <button className="kbd" type="button" onClick={() => setQ("")} aria-label="Clear search">Clear</button> : null}
          </label>
        </div>
        <div className="top-actions">
          <a className="api-link" href="/api/v1/openapi.yaml">API</a>
          <button
            className="capsule icon"
            type="button"
            aria-label={theme === "dark" ? "Use light mode" : "Use dark mode"}
            onClick={() => setTheme(theme === "dark" ? "light" : "dark")}
          >
            <Icon name={theme === "dark" ? "moon" : "sun"} size={15} />
          </button>
          <NavLink to="/settings" className="avatar" aria-label="Settings">MC</NavLink>
        </div>
      </header>
      <aside className="sidebar">
        <nav className="side-nav">
          <div className="side-h">Fleet</div>
          <SideLink id="overview" to="/" icon="layout" label="Overview" active={active === "overview"} end />
          <SideLink id="devices" to="/devices" icon="laptop" label="Devices" count={counts.devices ? String(counts.devices) : ""} active={active === "devices"} />
          <SideLink id="queries" to="/queries" icon="terminal" label="Queries" active={active === "queries"} />
          <div className="side-h" style={{ marginTop: 14 }}>Security</div>
          <SideLink id="coverage" to="/coverage" icon="shield" label="Security Coverage" active={active === "coverage"} />
          <div className="side-h" style={{ marginTop: 14 }}>Software</div>
          <SideLink id="munki" to="/munki" icon="package" label="Munki" count={counts.packages ? String(counts.packages) : ""} active={active === "munki"} />
          <SideLink id="autopkg" to="/autopkg" icon="workflow" label="AutoPKG" count={counts.recipes ? String(counts.recipes) : ""} active={active === "autopkg"} />
          <div className="side-gap" />
          <SideLink id="settings" to="/settings" icon="settings" label="Settings" active={active === "settings"} />
          <div className="side-status">
            <span className="dot" style={{ width: 6, height: 6, background: apiOk ? "var(--green)" : "var(--red)" }} />
            API {apiOk ? "ok" : "unreachable"}
          </div>
          <div className={`nav-indicator${ready ? " on" : ""}`} style={{ transform: `translateY(${y}px)` }} />
        </nav>
      </aside>
      <main className="main">
        <Outlet />
      </main>
    </div>
  );
}

function SideLink({ id, to, icon, label, count, active, end }: {
  id: string; to: string; icon: IconName; label: string; count?: string; active: boolean; end?: boolean;
}) {
  return (
    <NavLink id={`nav-${id}`} to={to} end={end} className={`nav${active ? " active" : ""}`} aria-current={active ? "page" : undefined}>
      <Icon name={icon} size={16} />
      <span>{label}</span>
      {count ? <span className="cnt">{count}</span> : null}
    </NavLink>
  );
}

export function Page({ children }: { children: ReactNode }) {
  const { pathname } = useLocation();
  return <div key={pathname} className="page">{children}</div>;
}

export function Toolbar({ title, lede, badge, extra }: {
  title: string; lede?: string; badge?: boolean; extra?: ReactNode;
}) {
  return (
    <div className="toolbar">
      <div className="titles">
        <div className="title-row">
          <h1 className="title">{title}</h1>
          {badge ? <Managed /> : null}
        </div>
        {lede ? <div className="sub">{lede}</div> : null}
      </div>
      <div className="grow" />
      {extra}
    </div>
  );
}

const autopkgSeg = [
  { to: "/autopkg", label: "Recipes", on: (p: string) => p === "/autopkg" },
  { to: "/runs", label: "Runs", on: (p: string) => p === "/runs" || p.startsWith("/runs/") },
  { to: "/runners", label: "Runners", on: (p: string) => p.startsWith("/runners") },
];
const munkiSeg = [
  { to: "/munki", label: "Catalogs", on: (p: string) => p === "/munki" },
  { to: "/munki/manifests", label: "Manifests", on: (p: string) => p.startsWith("/munki/manifests") },
];

export function AutopkgSeg() { return <Segment items={autopkgSeg} />; }
export function MunkiSeg() { return <Segment items={munkiSeg} />; }

function Segment({ items }: { items: { to: string; label: string; on: (path: string) => boolean }[] }) {
  const { pathname } = useLocation();
  const index = Math.max(0, items.findIndex((item) => item.on(pathname)));
  return (
    <div className="seg" style={{ "--n": items.length, "--i": index } as CSSProperties}>
      <span className="seg-thumb" />
      {items.map((item) => (
        <NavLink key={item.to} to={item.to} end className={item.on(pathname) ? "on" : undefined}>{item.label}</NavLink>
      ))}
    </div>
  );
}

export function Managed({ small }: { small?: boolean }) {
  return <span className={`tf${small ? " sm" : ""}`}><Icon name="lock" size={11} />Managed by Terraform</span>;
}

const tone: Record<string, { kind: string; icon?: IconName; live?: boolean }> = {
  new_version: { kind: "blue", icon: "spark" },
  no_change: { kind: "gray", icon: "check" },
  trust_failed: { kind: "red", icon: "alert" },
  error: { kind: "red", icon: "x" },
  failed: { kind: "red", icon: "x" },
  promoted: { kind: "green", icon: "rocket" },
  soaking: { kind: "orange" },
  held: { kind: "orange", icon: "alert" },
  ready: { kind: "blue" },
  stable: { kind: "gray" },
  running: { kind: "teal", live: true },
  leased: { kind: "teal", live: true },
  queued: { kind: "gray" },
  succeeded: { kind: "green", icon: "check" },
  online: { kind: "green", live: true },
  offline: { kind: "red" },
  timeout: { kind: "orange", icon: "alert" },
  pending: { kind: "gray" },
  sent: { kind: "teal", live: true },
  complete: { kind: "green", icon: "check" },
};

export function StatusPill({ status, result }: { status?: string; result?: string }) {
  const key = result || status || "";
  const look = tone[key] ?? { kind: "gray" };
  const label = pretty(key || "—");
  return (
    <span key={key || "empty"} className={`pill ${look.kind} pop`}>
      {look.live ? <span className="dot live" style={{ width: 6, height: 6 }} /> : null}
      {look.icon ? <Icon name={look.icon} size={11} /> : null}
      {label}
    </span>
  );
}

export function Mark({ name }: { name: string }) {
  let h = 0;
  for (let i = 0; i < name.length; i++) h = (h * 31 + name.charCodeAt(i)) >>> 0;
  const hue = h % 360;
  const letter = name.trim().charAt(0).toUpperCase() || "•";
  return (
    <span
      className="appic"
      style={{ background: `linear-gradient(145deg, hsl(${hue} 78% 62%), hsl(${(hue + 28) % 360} 68% 42%))` }}
    >
      {letter}
    </span>
  );
}

export function ago(value?: string) {
  if (!value) return "never";
  const ms = Date.now() - new Date(value).getTime();
  if (Number.isNaN(ms)) return value;
  if (ms < 45_000) return "just now";
  const min = Math.round(ms / 60000);
  if (min < 60) return `${min}m ago`;
  const hours = Math.round(min / 60);
  if (hours < 36) return `${hours}h ago`;
  const days = Math.round(hours / 24);
  return `${days}d ago`;
}

export function gigabytes(bytes: number) {
  if (!bytes) return "—";
  const gb = bytes / 1024 ** 3;
  return `${Math.round(gb)} GB`;
}

export function uptime(seconds: number) {
  if (!seconds) return "—";
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  if (days > 0) return `${days}d ${hours}h`;
  return `${hours}h`;
}

export function when(value?: string) {
  if (!value) return "—";
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return value;
  return d.toLocaleString(undefined, { month: "short", day: "numeric", hour: "numeric", minute: "2-digit" });
}

export function left(value?: string) {
  if (!value) return "";
  const ms = new Date(value).getTime() - Date.now();
  if (Number.isNaN(ms)) return "";
  if (ms <= 0) return "due";
  const hours = Math.round(ms / 3600000);
  if (hours < 24) return `${Math.max(hours, 1)}h left`;
  const days = Math.floor(hours / 24);
  const rem = hours % 24;
  return rem ? `${days}d ${rem}h left` : `${days}d left`;
}

export function match(q: string, ...parts: (string | undefined)[]) {
  const needle = q.trim().toLowerCase();
  if (!needle) return true;
  return parts.join(" ").toLowerCase().includes(needle);
}

export function Empty({ children }: { children: string }) {
  return <div className="empty">{children}</div>;
}

export function enterStyle(index: number): CSSProperties {
  return { "--i": index } as CSSProperties;
}

function pretty(value: string) {
  if (!value || value === "—") return "—";
  const text = value.replaceAll("_", " ");
  return text.charAt(0).toUpperCase() + text.slice(1);
}

export function SignOut() {
  const navigate = useNavigate();
  return (
    <button
      className="capsule"
      type="button"
      onClick={() => {
        clearToken();
        navigate(0);
      }}
    >
      Sign out
    </button>
  );
}
