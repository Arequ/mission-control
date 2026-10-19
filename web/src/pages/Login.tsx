import { FormEvent, useState } from "react";
import { api, setToken } from "../lib/api";
import type { Principal } from "../lib/types";

export function Login({ onSuccess }: { onSuccess: () => void }) {
  const [token, setValue] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    setToken(token.trim());
    try {
      await api<Principal>("/api/v1/me");
      onSuccess();
    } catch (err) {
      setToken("");
      setError(err instanceof Error ? err.message : "Could not sign in");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="login">
      <form className="glass login-card rise" onSubmit={submit}>
        <div className="mark" aria-hidden>
          <svg width="20" height="20" viewBox="0 0 20 20" fill="none">
            <circle cx="10" cy="10" r="7.2" stroke="#0A84FF" strokeWidth="1.6" />
            <circle cx="10" cy="10" r="2.2" fill="#0A84FF" />
          </svg>
        </div>
        <h1>Mission Control</h1>
        <p className="muted">Sign in with an API token. The local compose default is the dev bootstrap token.</p>
        <div className="stack" style={{ marginTop: 18 }}>
          <input
            className="field"
            autoFocus
            placeholder="mc_… or dev-bootstrap-token"
            value={token}
            onChange={(event) => setValue(event.target.value)}
            autoComplete="off"
          />
          {error ? <div className="error">{error}</div> : null}
          <button className="btn primary" type="submit" disabled={busy || token.trim() === ""}>
            {busy ? "Checking…" : "Continue"}
          </button>
        </div>
      </form>
    </div>
  );
}
