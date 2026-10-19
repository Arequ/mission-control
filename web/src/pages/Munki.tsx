import { useEffect, useState } from "react";
import { api } from "../lib/api";
import type { Resource } from "../lib/types";

export function Munki() {
  const [catalogs, setCatalogs] = useState<Resource[]>([]);
  const [manifests, setManifests] = useState<Resource[]>([]);
  const [packages, setPackages] = useState<Resource[]>([]);
  const [error, setError] = useState("");

  useEffect(() => {
    Promise.all([
      api<{ catalogs: Resource[] }>("/api/v1/munki/catalogs"),
      api<{ manifests: Resource[] }>("/api/v1/munki/manifests"),
      api<{ packages: Resource[] }>("/api/v1/munki/packages"),
    ]).then(([c, m, p]) => {
      setCatalogs(c.catalogs);
      setManifests(m.manifests);
      setPackages(p.packages);
    }).catch((err: Error) => setError(err.message));
  }, []);

  return (
    <div className="rise">
      <div className="phase">
        Client repo serving is phase 2. Catalogs, manifests, and pkginfo below are the real declared resources — Munki clients cannot fetch them from <span className="mono">/munki/repo</span> yet.
      </div>
      {error ? <div className="error">{error}</div> : null}
      <div className="stat-grid" style={{ gridTemplateColumns: "1fr 1fr 1fr" }}>
        <Column title="Catalogs" resources={catalogs} detail={(item) => String(item.spec.displayName ?? item.spec.description ?? "")} />
        <Column title="Manifests" resources={manifests} detail={(item) => `catalog ${String(item.spec.catalog ?? "")}`} />
        <Column title="Packages" resources={packages} detail={(item) => `${String(item.spec.name ?? "")} ${String(item.spec.version ?? "")}`} />
      </div>
    </div>
  );
}

function Column({ title, resources, detail }: { title: string; resources: Resource[]; detail: (item: Resource) => string }) {
  return (
    <section className="glass panel">
      <h3>{title}</h3>
      {resources.length === 0 ? <div className="empty">Nothing declared.</div> : resources.map((item) => (
        <div key={item.metadata.name} className="list-row" style={{ gridTemplateColumns: "1fr" }}>
          <div className="primary">{item.metadata.name}</div>
          <div className="secondary">{detail(item)}</div>
        </div>
      ))}
    </section>
  );
}
