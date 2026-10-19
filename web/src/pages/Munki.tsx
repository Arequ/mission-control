import { useEffect, useState } from "react";
import { api, type Catalog, type Manifest, type Package, type PromotionRule } from "../api";
import { Empty, Managed, StatusPill, when } from "../ui";

function soakCopy(pkg: Package, rules: PromotionRule[]) {
  if (pkg.soak_status === "soaking" && pkg.soak_ends_at) {
    return `until ${when(pkg.soak_ends_at)}`;
  }
  if (pkg.soak_status === "promoted" && pkg.promoted_at) {
    return when(pkg.promoted_at);
  }
  const rule = rules.find((r) => r.from_catalog === pkg.catalog);
  if (pkg.soak_status === "held" && rule) return `${rule.name} is holding`;
  return "";
}

export function MunkiPage() {
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
        .catch((err: Error) => {
          if (!stop) setError(err.message);
        });
    };
    load();
    const t = setInterval(load, 4000);
    return () => {
      stop = true;
      clearInterval(t);
    };
  }, []);
  const ordered = [...catalogs].sort((a, b) => (a.name === "testing" ? -1 : b.name === "testing" ? 1 : a.name.localeCompare(b.name)));
  return (
    <>
      <h1>Catalogs</h1>
      <p className="lede">
        New builds land in the testing catalog. Promotion rules move them after the soak.
        {rules[0] ? ` ${rules[0].from_catalog} → ${rules[0].to_catalog}, ${rules[0].soak_days} day soak${rules[0].manual_hold ? ", manual hold" : ""}.` : ""}
      </p>
      {error && <p className="lede">{error}</p>}
      <div className="grid">
        {ordered.map((catalog) => {
          const items = packages.filter((pkg) => pkg.catalog === catalog.name);
          return (
            <section key={catalog.name} className="panel catalog">
              <h2>
                {catalog.name}
                <span className="count">{catalog.item_count}</span>
              </h2>
              {items.length === 0 ? (
                <Empty>Nothing in this catalog.</Empty>
              ) : (
                <table>
                  <tbody>
                    {items.map((pkg) => (
                      <tr key={pkg.id}>
                        <td>
                          <div className="name">{pkg.name}</div>
                          <div className="sub">{pkg.version}</div>
                        </td>
                        <td>
                          <StatusPill result={pkg.soak_status} />
                          <div className="sub">{soakCopy(pkg, rules)}</div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </section>
          );
        })}
      </div>
    </>
  );
}

export function ManifestsPage() {
  const [manifests, setManifests] = useState<Manifest[]>([]);
  const [error, setError] = useState("");
  useEffect(() => {
    api.manifests()
      .then((res) => setManifests(res.manifests))
      .catch((err: Error) => setError(err.message));
  }, []);
  return (
    <>
      <h1>Manifests</h1>
      <p className="lede">Served to Munki clients at /repo/manifests/&lt;name&gt;. There is no editor here.</p>
      {error && <p className="lede">{error}</p>}
      <div className="panel">
        {manifests.length === 0 ? (
          <Empty>No manifests yet.</Empty>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Catalogs</th>
                <th>Managed installs</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {manifests.map((manifest) => (
                <tr key={manifest.id}>
                  <td className="name">{manifest.name}</td>
                  <td className="sub">{manifest.catalogs.join(", ") || "—"}</td>
                  <td className="sub">{manifest.managed_installs.join(", ") || "—"}</td>
                  <td>{manifest.managed_by === "terraform" ? <Managed /> : <span className="pill">{manifest.managed_by}</span>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </>
  );
}
