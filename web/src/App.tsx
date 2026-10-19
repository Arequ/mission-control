import { useEffect, useState } from "react";
import { Navigate, Route, Routes } from "react-router-dom";
import { clearToken, getToken } from "./lib/api";
import { Shell } from "./components/Shell";
import { Login } from "./pages/Login";
import { Dashboard } from "./pages/Dashboard";
import { Devices } from "./pages/Devices";
import { DeviceDetail } from "./pages/DeviceDetail";
import { Queries } from "./pages/Queries";
import { Munki } from "./pages/Munki";
import { AutoPkg } from "./pages/AutoPkg";
import { ConfigPage } from "./pages/Config";

export default function App() {
  const [authed, setAuthed] = useState(Boolean(getToken()));

  useEffect(() => {
    const onUnauthorized = () => {
      clearToken();
      setAuthed(false);
    };
    window.addEventListener("mc-unauthorized", onUnauthorized);
    return () => window.removeEventListener("mc-unauthorized", onUnauthorized);
  }, []);

  if (!authed) {
    return <Login onSuccess={() => setAuthed(true)} />;
  }

  return (
    <Routes>
      <Route element={<Shell onSignOut={() => { clearToken(); setAuthed(false); }} />}>
        <Route index element={<Dashboard />} />
        <Route path="devices" element={<Devices />} />
        <Route path="devices/:id" element={<DeviceDetail />} />
        <Route path="queries" element={<Queries />} />
        <Route path="munki" element={<Munki />} />
        <Route path="autopkg" element={<AutoPkg />} />
        <Route path="config" element={<ConfigPage />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Route>
    </Routes>
  );
}
