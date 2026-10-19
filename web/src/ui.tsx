import { NavLink, Outlet, useNavigate } from "react-router-dom";
import { clearToken } from "./api";

export function Layout() {
  const navigate = useNavigate();
  return (
    <div className="app">
      <aside className="rail">
        <p className="brand">
          Mission Control
          <span>Munki and AutoPkg</span>
        </p>
        <nav className="nav">
          <div className="section">AutoPkg</div>
          <NavLink to="/" end>Recipes</NavLink>
          <NavLink to="/runs">Runs</NavLink>
          <NavLink to="/runners">Runners</NavLink>
          <div className="section">Munki</div>
          <NavLink to="/munki">Catalogs</NavLink>
          <NavLink to="/munki/manifests">Manifests</NavLink>
        </nav>
        <button
          className="signout"
          onClick={() => {
            clearToken();
            navigate(0);
          }}
        >
          Sign out
        </button>
      </aside>
      <main className="main">
        <Outlet />
      </main>
    </div>
  );
}

export function Managed() {
  return <span className="pill tf">Managed by Terraform</span>;
}

export function StatusPill({ status, result }: { status?: string; result?: string }) {
  const label = result || status || "—";
  const kind =
    result === "new_version" || status === "succeeded" || status === "online" || result === "promoted"
      ? "ok"
      : result === "trust_failed" || result === "error" || status === "failed" || status === "offline"
        ? "bad"
        : status === "running" || status === "leased" || status === "queued" || result === "soaking" || result === "held" || result === "ready"
          ? "warn"
          : "";
  return <span className={`pill ${kind}`}>{label.replaceAll("_", " ")}</span>;
}

export function when(value?: string) {
  if (!value) return "—";
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return value;
  return d.toLocaleString(undefined, { month: "short", day: "numeric", hour: "numeric", minute: "2-digit" });
}

export function Empty({ children }: { children: string }) {
  return <div className="empty">{children}</div>;
}
