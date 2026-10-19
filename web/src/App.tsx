import { FormEvent, useEffect, useState } from "react";
import { Navigate, Route, Routes } from "react-router-dom";
import { api, type PublicProvider, type SessionUser } from "./api";
import { Icon } from "./icons";
import { AutopkgPage } from "./pages/Autopkg";
import { DevicePage } from "./pages/Device";
import { DevicesPage } from "./pages/Devices";
import { ManifestsPage, MunkiPage } from "./pages/Munki";
import { OverviewPage } from "./pages/Overview";
import { LiveQueryPage, QueriesPage } from "./pages/Queries";
import { RunnersPage } from "./pages/Runners";
import { RunDetailPage, RunsPage } from "./pages/Runs";
import { CoverageConnectorsPage, CoverageDevicePage, CoveragePage } from "./pages/Coverage";
import { LogViewerPage, LogsPage } from "./pages/Logs";
import { VulnerabilitiesPage } from "./pages/Vulnerabilities";
import { SettingsPage } from "./pages/Settings";
import { Layout, Providers, SessionProvider, useServerMeta, useTheme } from "./ui";

export function App() {
  return (
    <Providers>
      <Authed />
    </Providers>
  );
}

function Authed() {
  const [user, setUser] = useState<SessionUser | null>(null);
  const [ready, setReady] = useState(false);
  useEffect(() => {
    let stop = false;
    api.session()
      .then((next) => { if (!stop) setUser(next); })
      .catch(() => { if (!stop) setUser(null); })
      .finally(() => { if (!stop) setReady(true); });
    return () => { stop = true; };
  }, []);
  if (!ready) return <div className="login" />;
  if (!user) return <Login onDone={setUser} />;
  return (
    <SessionProvider user={user}>
    <Routes>
      <Route element={<Layout />}>
        <Route index element={<OverviewPage />} />
        <Route path="devices" element={<DevicesPage />} />
        <Route path="devices/:id" element={<DevicePage />} />
        <Route path="devices/:id/software" element={<DevicePage />} />
        <Route path="devices/:id/queries" element={<DevicePage />} />
        <Route path="devices/:id/vulnerabilities" element={<DevicePage />} />
        <Route path="vulnerabilities" element={<VulnerabilitiesPage />} />
        <Route path="vulnerabilities/:id" element={<VulnerabilitiesPage />} />
        <Route path="coverage" element={<CoveragePage />} />
        <Route path="coverage/connectors" element={<CoverageConnectorsPage />} />
        <Route path="coverage/devices/:id" element={<CoverageDevicePage />} />
        <Route path="queries" element={<QueriesPage />} />
        <Route path="logs" element={<LogsPage />} />
        <Route path="logs/:id" element={<LogViewerPage />} />
        <Route path="queries/live" element={<LiveQueryPage />} />
        <Route path="autopkg" element={<AutopkgPage />} />
        <Route path="runs" element={<RunsPage />} />
        <Route path="runs/:id" element={<RunDetailPage />} />
        <Route path="runners" element={<RunnersPage />} />
        <Route path="munki" element={<MunkiPage />} />
        <Route path="munki/manifests" element={<ManifestsPage />} />
        <Route path="settings" element={<SettingsPage />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Route>
    </Routes>
    </SessionProvider>
  );
}

function Login({ onDone }: { onDone: (user: SessionUser) => void }) {
  const { theme, setTheme } = useTheme();
  const meta = useServerMeta();
  const [providers, setProviders] = useState<PublicProvider[]>([]);
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  useEffect(() => {
    api.providers().then((page) => setProviders(page.providers)).catch(() => setProviders([]));
  }, []);
  const local = (event: FormEvent) => {
    event.preventDefault();
    setError("");
    api.breakGlass(password).then(onDone).catch((err: Error) => setError(err.message));
  };
  return (
    <div className="login page">
      <div className="card login-card enter">
        <span className="mark"><Icon name="orbit" size={15} /></span>
        <h1>Mission Control</h1>
        <p className="sub">Sign in with your organization. Configuration stays in Terraform.</p>
        <div className="login-providers">
          {providers.map((provider) => (
            <a key={provider.id} className="capsule primary" href={`/api/v1/sso/login?provider=${encodeURIComponent(provider.id)}&return=/`}>
              Continue with {provider.name}
            </a>
          ))}
          {providers.length === 0 ? <p className="faint">No identity provider is configured yet.</p> : null}
        </div>
        {meta.break_glass ? (
          <form onSubmit={local}>
            <p className="sub">Break-glass local admin</p>
            <input
              className="field"
              type="password"
              placeholder="Local password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              aria-label="Break-glass password"
            />
            <button className="capsule" type="submit">Sign in locally</button>
          </form>
        ) : null}
        {error ? <p className="note">{error}</p> : null}
        <div className="choice" style={{ marginTop: 16 }}>
          <span className="faint">Appearance</span>
          <button className="capsule" type="button" onClick={() => setTheme(theme === "dark" ? "light" : "dark")}>
            <Icon name={theme === "dark" ? "moon" : "sun"} size={14} />
            {theme === "dark" ? "Dark" : "Light"}
          </button>
        </div>
      </div>
    </div>
  );
}
