import { NavLink, Outlet, useLocation } from "react-router-dom";
import {
  Boxes,
  Laptop,
  LayoutDashboard,
  Moon,
  Package,
  ScrollText,
  Sun,
  Workflow,
} from "lucide-react";
import { useEffect, useState } from "react";
import { api } from "../lib/api";
import type { SyncStatus } from "../lib/types";
import { ago } from "../lib/format";

const nav = [
  { to: "/", label: "Fleet", icon: LayoutDashboard, end: true, section: "Overview" },
  { to: "/devices", label: "Devices", icon: Laptop, section: "Overview" },
  { to: "/queries", label: "Queries", icon: ScrollText, section: "Software" },
  { to: "/munki", label: "Munki", icon: Package, section: "Software" },
  { to: "/autopkg", label: "AutoPkg", icon: Workflow, section: "Software" },
  { to: "/config", label: "Config", icon: Boxes, section: "Control" },
];

const titles: Record<string, { title: string; sub: string }> = {
  "/": { title: "Fleet", sub: "What the enrolled Macs are doing right now." },
  "/devices": { title: "Devices", sub: "Inventory collected by osquery." },
  "/queries": { title: "Queries", sub: "Packs are declared in git. Live queries run on demand." },
  "/munki": { title: "Munki", sub: "Catalogs, manifests, and pkginfo owned by config." },
  "/autopkg": { title: "AutoPkg", sub: "Recipe pipelines, queued for Mac runners." },
  "/config": { title: "Config", sub: "The desired state Mission Control is reconciling." },
};

export function Shell({ onSignOut }: { onSignOut: () => void }) {
  const location = useLocation();
  const [dark, setDark] = useState(document.documentElement.classList.contains("dark"));
  const [sync, setSync] = useState<SyncStatus | null>(null);
  const meta = location.pathname.startsWith("/devices/")
    ? { title: "Device", sub: "Hardware, software, and the config this Mac is running." }
    : titles[location.pathname] ?? titles["/"];

  useEffect(() => {
    document.documentElement.classList.toggle("dark", dark);
    localStorage.setItem("mc.theme", dark ? "dark" : "light");
  }, [dark]);

  useEffect(() => {
    let stop = false;
    const load = () => {
      api<SyncStatus>("/api/v1/config/status")
        .then((status) => {
          if (!stop) setSync(status);
        })
        .catch(() => undefined);
    };
    load();
    const timer = window.setInterval(load, 15000);
    return () => {
      stop = true;
      window.clearInterval(timer);
    };
  }, []);

  let lastSection = "";

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="traffic" aria-hidden>
          <i /><i /><i />
        </div>
        <div className="brand">
          <div className="mark" aria-hidden>
            <svg width="20" height="20" viewBox="0 0 20 20" fill="none">
              <circle cx="10" cy="10" r="7.2" stroke="#0A84FF" strokeWidth="1.6" />
              <circle cx="10" cy="10" r="2.2" fill="#0A84FF" />
              <path d="M10 2.5v2.2M10 15.3v2.2M2.5 10h2.2M15.3 10h2.2" stroke="#0A84FF" strokeWidth="1.4" strokeLinecap="round" />
            </svg>
          </div>
          <div>
            <h1>Mission Control</h1>
            <p>Endpoint console</p>
          </div>
        </div>
        <nav>
          {nav.map((item) => {
            const show = item.section !== lastSection;
            lastSection = item.section;
            const Icon = item.icon;
            return (
              <div key={item.to}>
                {show ? <div className="nav-label">{item.section}</div> : null}
                <NavLink to={item.to} end={item.end} className={({ isActive }) => `nav-item${isActive ? " active" : ""}`}>
                  <Icon />
                  <span>{item.label}</span>
                </NavLink>
              </div>
            );
          })}
        </nav>
        <div className="sidebar-foot">
          <div className="primary" style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <span className={`dot ${sync?.lastError ? "warn" : "on"}`} />
            <span>Config sync</span>
          </div>
          <div style={{ marginTop: 6 }}>
            {sync?.directory
              ? sync.lastError
                ? "Last sync failed"
                : `Applied ${ago(sync.lastSuccess)}`
              : "Point MC_CONFIG_DIR at a repo"}
          </div>
        </div>
      </aside>
      <section className="workspace">
        <header className="toolbar">
          <div>
            <h2>{meta.title}</h2>
            <p className="sub">{meta.sub}</p>
          </div>
          <div style={{ display: "flex", gap: 8 }}>
            <button className="icon-btn" onClick={() => setDark((value) => !value)} aria-label="Toggle appearance">
              {dark ? <Sun size={16} /> : <Moon size={16} />}
            </button>
            <button className="btn" onClick={onSignOut}>Sign out</button>
          </div>
        </header>
        <div className="content">
          <Outlet />
        </div>
      </section>
    </div>
  );
}
