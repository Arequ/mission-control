import { useEffect, useState, type CSSProperties } from "react";
import { api, type Catalog, type Manifest, type Package, type PromotionRule } from "../api";
import { Empty, Managed, Mark, MunkiSeg, Page, StatusPill, Toolbar, enterStyle, left, match, useSearch, when } from "../ui";

function soakCopy(pkg: Package, rules: PromotionRule[]) {
  if (pkg.soak_status === "soaking") return left(pkg.soak_ends_at);
  if (pkg.soak_status === "promoted" && pkg.promoted_at) return when(pkg.promoted_at);
  if (pkg.soak_status === "ready") return "Ready to promote";
  const rule = rules.find((item) => item.from_catalog === pkg.catalog);
  if (pkg.soak_status === "held" && rule) return `${rule.name} is holding`;
  return "";
}

function soakProgress(pkg: Package, rules: PromotionRule[]) {
  if (pkg.soak_status === "promoted" || pkg.soak_status === "stable") return 1;
  if (pkg.soak_status === "ready") return 1;
  const rule = rules.find((item) => item.from_catalog === pkg.catalog && item.enabled);
  if (!pkg.soak_ends_at || !rule || rule.soak_days <= 0) return pkg.soak_status === "soaking" ? 0.08 : 0;
  const end = new Date(pkg.soak_ends_at).getTime();
  const start = end - rule.soak_days * 86400000;
  if (!Number.isFinite(end) || end <= start) return 1;
  return Math.min(1, Math.max(0.04, (Date.now() - start) / (end - start)));
}

export function MunkiPage() {
  const { q } = useSearch();
  const [catalogs, setCatalogs] = useState<Catalog[]>([]);
  const [packages, setPackages] = useState<Package[]>([]);
  const [rules, setRules] = useState<PromotionRule[]>([]);
  const [error, setError] = useState("");
  useEffect(() => {
    let stop = false;
    const load = () => {
      Promise.all([api.catalogs(), api.packages(), api.rules()])
        .then(([c, p, r]) => {
          if (stop) return;
          setCatalogs(c.catalogs);
          setPackages(p.packages);
          setRules(r.promotion_rules);
        })
        .catch((err: Error) => { if (!stop) setError(err.message); });
    };
    load();
    const t = setInterval(load, 4000);
    return () => { stop = true; clearInterval(t); };
  }, []);
  const rule = rules.find((item) => item.enabled) ?? rules[0];
  const ordered = [...catalogs].sort((a, b) => (a.name === "testing" ? -1 : b.name === "testing" ? 1 : a.name.localeCompare(b.name)));
  return (
    <Page>
      <Toolbar
        title="Catalogs"
        badge={rule?.managed_by === "terraform"}
        lede={rule ? `New builds land in ${rule.from_catalog}. ${rule.from_catalog} moves to ${rule.to_catalog} after ${rule.soak_days} day${rule.soak_days === 1 ? "" : "s"}${rule.manual_hold ? ", unless the rule is holding" : ""}.` : "Packages promoted between catalogs."}
        extra={<MunkiSeg />}
      />
      <div className="content">
        {error ? <p className="note">{error}</p> : null}
        <div className="catalogs">
          {ordered.map((catalog, index) => {
            const items = packages.filter((pkg) => pkg.catalog === catalog.name && match(q, pkg.name, pkg.version, pkg.catalog, pkg.soak_status));
            return (
              <section key={catalog.name} className="card enter" style={enterStyle(index)}>
                <div className="card-h">
                  <span className="card-t">{catalog.name}</span>
                  <span className="catalog-count">{catalog.item_count}</span>
                </div>
                {items.length === 0 ? (
                  <Empty>{packages.some((pkg) => pkg.catalog === catalog.name) ? "Nothing matches." : "Nothing in this catalog."}</Empty>
                ) : items.map((pkg) => {
                  const progress = soakProgress(pkg, rules);
                  const done = pkg.soak_status === "promoted" || pkg.soak_status === "stable";
                  return (
                    <div key={pkg.id} className="row cols-pkg">
                      <span className="wash" />
                      <div className="who">
                        <Mark name={pkg.name} />
                        <div className="id">
                          <div className="name">{pkg.name}</div>
                          <div className="subline mono">{pkg.version}</div>
                        </div>
                      </div>
                      <div className="soak-meta">
                        <SoakBar progress={progress} done={done} />
                        <span className="faint" style={{ minWidth: 72 }}>{soakCopy(pkg, rules)}</span>
                      </div>
                      <div className="end"><StatusPill result={pkg.soak_status} /></div>
                    </div>
                  );
                })}
              </section>
            );
          })}
        </div>
      </div>
    </Page>
  );
}

function SoakBar({ progress, done }: { progress: number; done: boolean }) {
  const [scale, setScale] = useState(0);
  useEffect(() => {
    const id = requestAnimationFrame(() => setScale(progress));
    return () => cancelAnimationFrame(id);
  }, [progress]);
  return (
    <div className={`bar${done ? " done" : ""}`}>
      <i style={{ "--p": scale } as CSSProperties} />
    </div>
  );
}

export function ManifestsPage() {
  const { q } = useSearch();
  const [manifests, setManifests] = useState<Manifest[]>([]);
  const [error, setError] = useState("");
  useEffect(() => {
    api.manifests()
      .then((res) => setManifests(res.manifests))
      .catch((err: Error) => setError(err.message));
  }, []);
  const shown = manifests.filter((manifest) => match(q, manifest.name, manifest.catalogs.join(" "), manifest.managed_installs.join(" ")));
  return (
    <Page>
      <Toolbar
        title="Manifests"
        badge
        lede="Served to Munki clients at /repo/manifests. There is no editor here."
        extra={<MunkiSeg />}
      />
      <div className="content">
        {error ? <p className="note">{error}</p> : null}
        <section className="card">
          {shown.length === 0 ? (
            <Empty>{manifests.length === 0 ? "No manifests yet." : "Nothing matches."}</Empty>
          ) : (
            <>
              <div className="list-h cols-manifest">
                <span>Name</span><span>Catalogs</span><span>Managed installs</span><span></span>
              </div>
              {shown.map((manifest, index) => (
                <div key={manifest.id} className="row cols-manifest enter" style={enterStyle(index)}>
                  <span className="wash" />
                  <div className="name">{manifest.name}</div>
                  <div className="chips">
                    {manifest.catalogs.map((catalog) => <span key={catalog} className={`pill ${catalog === "production" ? "green" : "blue"}`}>{catalog}</span>)}
                  </div>
                  <div className="muted">{manifest.managed_installs.join(", ") || "—"}</div>
                  <div className="end">{manifest.managed_by === "terraform" ? <Managed small /> : <span className="pill gray">{manifest.managed_by}</span>}</div>
                </div>
              ))}
            </>
          )}
        </section>
      </div>
    </Page>
  );
}
