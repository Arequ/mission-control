import type { CSSProperties } from "react";
import { Page, SignOut, Toolbar, useTheme } from "../ui";

export function SettingsPage() {
  const { theme, setTheme } = useTheme();
  return (
    <Page>
      <Toolbar title="Settings" lede="This server has no configuration editor. Recipes, catalogs, and schedules live in Terraform." />
      <div className="content settings">
        <section className="card">
          <div className="card-h"><span className="card-t">Appearance</span></div>
          <div className="pad">
            <div className="choice">
              <span className="muted">Theme</span>
              <div className="seg" style={{ "--n": 2, "--i": theme === "dark" ? 1 : 0 } as CSSProperties}>
                <span className="seg-thumb" />
                <button type="button" className={theme === "light" ? "on" : undefined} onClick={() => setTheme("light")}>Light</button>
                <button type="button" className={theme === "dark" ? "on" : undefined} onClick={() => setTheme("dark")}>Dark</button>
              </div>
            </div>
          </div>
        </section>
        <section className="card">
          <div className="card-h"><span className="card-t">Session</span></div>
          <div className="pad">
            <div className="choice">
              <span className="muted">API token stays in this browser tab.</span>
              <SignOut />
            </div>
            <a className="api-link" href="/api/v1/openapi.yaml">OpenAPI specification</a>
          </div>
        </section>
      </div>
    </Page>
  );
}
