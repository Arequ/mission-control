import { FormEvent, useState } from "react";
import { Navigate, Route, Routes } from "react-router-dom";
import { getToken, setToken } from "./api";
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
import { Layout, Providers, useTheme } from "./ui";

export function App() {
  return (
    <Providers>
      <Authed />
    </Providers>
  );
}

function Authed() {
  const [authed, setAuthed] = useState(getToken() !== "");
  if (!authed) return <Login onDone={() => setAuthed(true)} />;
  return (
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
  );
}

function Login({ onDone }: { onDone: () => void }) {
  const [token, setValue] = useState("");
  const { theme, setTheme } = useTheme();
  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (!token.trim()) return;
    setToken(token);
    onDone();
  };
  return (
    <div className="login page">
      <form className="card login-card" onSubmit={submit}>
        <span className="mark"><Icon name="orbit" size={15} /></span>
        <h1>Mission Control</h1>
        <p className="sub">Paste an API token. Configuration stays in Terraform.</p>
        <input
          className="field"
          autoFocus
          type="password"
          placeholder="API token"
          value={token}
          onChange={(event) => setValue(event.target.value)}
          aria-label="API token"
        />
        <button className="capsule primary" type="submit">Continue</button>
        <div className="choice" style={{ marginTop: 16 }}>
          <span className="faint">Appearance</span>
          <button
            className="capsule"
            type="button"
            onClick={() => setTheme(theme === "dark" ? "light" : "dark")}
          >
            <Icon name={theme === "dark" ? "moon" : "sun"} size={14} />
            {theme === "dark" ? "Dark" : "Light"}
          </button>
        </div>
      </form>
    </div>
  );
}
