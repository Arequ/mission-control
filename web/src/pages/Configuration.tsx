import { useEffect, useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { api, type KeelDevice, type KeelOverview, type KeelRoleSettings } from "../api";
import { RoleChain, SettingsTree } from "../keel";
import { Empty, Page, Toolbar, ago, enterStyle, match, useSearch } from "../ui";

export function ConfigurationPage() {
  const { q } = useSearch();
  const [params, setParams] = useSearchParams();
  const [overview, setOverview] = useState<KeelOverview | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    let stop = false;
    const load = () => {
      api.keelOverview()
        .then((next) => { if (!stop) { setOverview(next); setError(""); } })
        .catch((err: Error) => { if (!stop) setError(err.message); });
    };
    load();
    const t = setInterval(load, 15000);
    return () => { stop = true; clearInterval(t); };
  }, []);

  const roles = overview?.roles ?? [];
  const leafRoles = roles.filter((r) => r.devices > 0);
  const selectedName = params.get("role") || leafRoles[0]?.name || roles[0]?.name || "";
  const role = roles.find((r) => r.name === selectedName);
  const profileName = params.get("profile") || role?.profiles[0]?.name || "";

  const select = (next: { role?: string; profile?: string }) => {
    const p = new URLSearchParams(params);
    if (next.role !== undefined) {
      p.set("role", next.role);
      p.delete("profile");
    }
    if (next.profile !== undefined) p.set("profile", next.profile);
    setParams(p, { replace: true });
  };

  const visibleRoles = roles.filter((r) => match(q, r.name, r.chain.join(" "), r.profiles.map((p) => p.name).join(" ")));

  return (
    <Page>
      <Toolbar
        title="Configuration"
        lede="Keel roles and profiles, read from each Mac's latest signed report. Roles change in the Keel repository."
      />
      <div className="content fleet">
        {error ? <p className="note">{error}</p> : null}
        <div className="vuln-stats keel-stats">
          <Stat i={0} k="Macs" v={overview?.devices} sub={overview ? `${overview.reporting} reporting` : "—"} />
          <Stat i={1} k="Failing" v={overview?.failed.length} hot={!!overview?.failed.length} sub="Failed resource or compile error" />
          <Stat i={2} k="Pending changes" v={overview?.pending.length} sub="Plan mode, would change" />
          <Stat i={3} k="Warnings" v={overview?.warned.length} sub="Latest run raised a warning" />
          <Stat i={4} k="Stale" v={overview?.stale.length} sub={`No report in ${Math.round((overview?.stale_after_seconds ?? 7200) / 3600)}h`} />
        </div>

        {overview && roles.length === 0 ? (
          <section className="card"><Empty>No Keel reports yet. Macs appear here after they enroll and finish a run.</Empty></section>
        ) : null}

        {roles.length > 0 ? (
          <div className="keel-split">
            <section className="card keel-roles">
              <div className="card-h"><span className="card-t">Roles</span><span className="faint">{roles.length}</span></div>
              {visibleRoles.length === 0 ? <Empty>No roles match.</Empty> : null}
              {visibleRoles.map((r, index) => (
                <button
                  key={r.name}
                  type="button"
                  className={`row keel-role-row enter${r.name === selectedName ? " on" : ""}`}
                  style={enterStyle(index)}
                  onClick={() => select({ role: r.name })}
                >
                  <span className="wash" />
                  <div className="keel-role-id">
                    <div className="name">{r.name}</div>
                    <div className="subline"><RoleChain chain={r.chain} /></div>
                  </div>
                  <div className="right">
                    <div className="tnum name">{r.devices}</div>
                    <div className="subline">{r.inherited > r.devices ? `${r.inherited} inherit` : r.devices === 1 ? "Mac" : "Macs"}</div>
                  </div>
                </button>
              ))}
            </section>

            {role ? <RoleDetail key={role.name} roleName={role.name} overview={overview!} profile={profileName} onProfile={(p) => select({ profile: p })} /> : null}
          </div>
        ) : null}

        {overview && roles.length > 0 ? (
          <div className="keel-health">
            <HealthList title="Failing" devices={overview.failed} empty="No failures in the latest runs." detail={(d) => (d.last_run?.compile_error ? "Policy did not compile" : `${d.last_run?.summary.failed ?? 0} failed`)} tone="red" />
            <HealthList title="Pending changes" devices={overview.pending} empty="No plan-mode Mac has pending changes." detail={(d) => `${d.last_run?.summary.would_change ?? 0} would change`} tone="orange" />
            <HealthList title="Warnings" devices={overview.warned} empty="No warnings in the latest runs." detail={(d) => d.last_run?.warnings[0] ?? ""} tone="orange" />
            <HealthList title="Stale" devices={overview.stale} empty="Every Mac reported recently." detail={(d) => (d.last_run ? "" : "Enrolled, never reported")} tone="gray" />
          </div>
        ) : null}
      </div>
    </Page>
  );
}

function Stat({ i, k, v, sub, hot }: { i: number; k: string; v?: number; sub: string; hot?: boolean }) {
  return (
    <section className="card vuln-stat enter" style={enterStyle(i)}>
      <span className="sec">{k}</span>
      <b className={hot ? "hot" : undefined}>{v ?? "—"}</b>
      <span>{sub}</span>
    </section>
  );
}

function RoleDetail({ roleName, overview, profile, onProfile }: {
  roleName: string; overview: KeelOverview; profile: string; onProfile: (name: string) => void;
}) {
  const role = overview.roles.find((r) => r.name === roleName)!;
  const [settings, setSettings] = useState<KeelRoleSettings | null>(null);
  const [devices, setDevices] = useState<KeelDevice[]>([]);
  const [error, setError] = useState("");

  useEffect(() => {
    let stop = false;
    api.keelDevices({ role: roleName })
      .then((page) => { if (!stop) setDevices(page.devices.filter((d) => d.last_run?.leaf_role === roleName)); })
      .catch(() => { if (!stop) setDevices([]); });
    return () => { stop = true; };
  }, [roleName]);

  useEffect(() => {
    let stop = false;
    setSettings(null);
    setError("");
    if (!profile || role.devices === 0) return;
    api.keelRoleSettings(roleName, profile)
      .then((next) => { if (!stop) setSettings(next); })
      .catch((err: Error) => { if (!stop) setError(err.message); });
    return () => { stop = true; };
  }, [roleName, profile, role.devices]);

  const variants = settings?.variants ?? [];
  const parents = role.parents.length ? role.parents.join(", ") : "none";
  const sorted = useMemo(() => [...role.profiles].sort((a, b) => a.name.localeCompare(b.name)), [role.profiles]);

  return (
    <section className="card keel-detail" key={roleName}>
      <div className="keel-detail-h">
        <div className="sec">Role</div>
        <h2>{role.name}</h2>
        <div className="keel-meta">
          <RoleChain chain={role.chain} />
          <span className="faint">Parents: {parents}</span>
        </div>
        <div className="keel-meta">
          <span><b className="tnum">{role.devices}</b> <span className="faint">{role.devices === 1 ? "Mac has" : "Macs have"} this as the leaf role</span></span>
          {role.inherited > role.devices ? <span><b className="tnum">{role.inherited}</b> <span className="faint">inherit it</span></span> : null}
        </div>
      </div>

      {role.devices === 0 ? (
        <p className="keel-note faint">No Mac reports {role.name} as its leaf role, so there are no effective settings to show. Pick a more specific role.</p>
      ) : (
        <>
          <div className="keel-block">
            <div className="sec">Profiles enabled</div>
            {sorted.length === 0 ? <p className="faint">No profile is enabled for this role.</p> : (
              <div className="filters keel-profiles">
                {sorted.map((p) => (
                  <button key={p.name} type="button" className={`filter${p.name === profile ? " on" : ""}`} onClick={() => onProfile(p.name)}>
                    {p.name}
                    {p.devices !== role.devices ? <span className="filter-n">{p.devices}/{role.devices}</span> : null}
                  </button>
                ))}
              </div>
            )}
          </div>
          {profile ? (
            <div className="keel-block">
              <div className="sec">Effective settings · {profile}</div>
              {error ? <p className="note">{error}</p> : null}
              {settings && variants.length > 1 ? (
                <p className="keel-warn"><span className="pill orange">{variants.length} variants</span> Macs in {role.name} disagree on {profile}. Each variant is below with its count.</p>
              ) : null}
              {settings && settings.missing > 0 ? (
                <p className="faint keel-small">{settings.missing} of {settings.devices} Macs did not report {profile}.</p>
              ) : null}
              {variants.map((v, i) => (
                <div key={i} className="keel-variant enter" style={enterStyle(i)}>
                  <div className="keel-variant-h">
                    <span className="tnum"><b>{v.devices}</b> <span className="faint">{v.devices === 1 ? "Mac" : "Macs"}</span></span>
                    {!v.enabled ? <span className="pill gray">Disabled</span> : null}
                    <span className="grow" />
                    <span className="faint keel-serials">{v.serials.slice(0, 4).join(", ")}{v.serials.length > 4 ? ` +${v.devices - 4}` : ""}</span>
                  </div>
                  <SettingsTree value={v.settings} />
                </div>
              ))}
            </div>
          ) : null}
          <div className="keel-block">
            <div className="sec">Macs</div>
            {devices.map((d) => <DeviceLine key={d.serial} d={d} />)}
          </div>
        </>
      )}
    </section>
  );
}

function DeviceLine({ d, detail }: { d: KeelDevice; detail?: string }) {
  const body = (
    <>
      <span className="wash" />
      <div className="keel-role-id">
        <div className="name">{d.hostname || d.serial}</div>
        <div className="subline">{d.serial}{d.last_run?.leaf_role ? ` · ${d.last_run.leaf_role}` : ""}</div>
        {detail ? <div className="keel-line-detail">{detail}</div> : null}
      </div>
      <div className="right">
        <div className="muted">{d.last_run ? ago(d.last_run.received_at) : "never"}</div>
        {d.last_run ? <div className="subline">{d.last_run.mode}</div> : null}
      </div>
    </>
  );
  if (d.device_id) {
    return <Link to={`/devices/${d.device_id}/configuration`} className="row keel-device-row">{body}</Link>;
  }
  return <div className="row keel-device-row">{body}</div>;
}

function HealthList({ title, devices, empty, detail, tone }: {
  title: string; devices: KeelDevice[]; empty: string; detail: (d: KeelDevice) => string; tone: string;
}) {
  return (
    <section className="card">
      <div className="card-h">
        <span className="card-t">{title}</span>
        {devices.length ? <span className={`pill ${tone}`}>{devices.length}</span> : <span className="pill green">None</span>}
      </div>
      {devices.length === 0 ? <p className="keel-note faint">{empty}</p> : devices.map((d) => <DeviceLine key={d.serial} d={d} detail={detail(d)} />)}
    </section>
  );
}
