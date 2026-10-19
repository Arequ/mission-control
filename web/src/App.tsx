import { FormEvent, useState } from "react";
import { Navigate, Route, Routes } from "react-router-dom";
import { getToken, setToken } from "./api";
import { AutopkgPage } from "./pages/Autopkg";
import { ManifestsPage, MunkiPage } from "./pages/Munki";
import { RunDetailPage, RunsPage } from "./pages/Runs";
import { RunnersPage } from "./pages/Runners";
import { Layout } from "./ui";

export function App() {
  const [authed, setAuthed] = useState(getToken() !== "");
  if (!authed) {
    return <Login onDone={() => setAuthed(true)} />;
  }
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route index element={<AutopkgPage />} />
        <Route path="runs" element={<RunsPage />} />
        <Route path="runs/:id" element={<RunDetailPage />} />
        <Route path="runners" element={<RunnersPage />} />
        <Route path="munki" element={<MunkiPage />} />
        <Route path="munki/manifests" element={<ManifestsPage />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Route>
    </Routes>
  );
}

function Login({ onDone }: { onDone: () => void }) {
  const [token, setValue] = useState("");
  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (!token.trim()) return;
    setToken(token);
    onDone();
  };
  return (
    <div className="login">
      <form className="panel" onSubmit={submit}>
        <h1>Mission Control</h1>
        <p className="lede">Paste an API token. Configuration stays in Terraform.</p>
        <input
          autoFocus
          type="password"
          placeholder="API token"
          value={token}
          onChange={(event) => setValue(event.target.value)}
          aria-label="API token"
        />
        <button className="btn" type="submit">Continue</button>
      </form>
    </div>
  );
}
