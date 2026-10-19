// Paths match internal/configrepo/links.go. The server meta response replaces
// these once it loads, so a configured slug and branch win.

export type ConfigKind =
  | "recipe"
  | "schedule"
  | "pipeline"
  | "runner_pool"
  | "munki_catalog"
  | "munki_manifest"
  | "munki_promotion"
  | "os_policy"
  | "osquery_pack"
  | "osquery_query"
  | "osquery_label"
  | "source_connector"
  | "log_view"
  | "vulnerability_settings"
  | "cpe_override"
  | "sla";

type Target = { path?: string; dir: string };

export const CONFIG_TARGETS: Record<ConfigKind, Target> = {
  recipe: { path: "autopkg/recipes.tf", dir: "autopkg" },
  schedule: { path: "autopkg/schedules.tf", dir: "autopkg" },
  pipeline: { path: "autopkg/pipeline.tf", dir: "autopkg" },
  runner_pool: { path: "autopkg/runners.tf", dir: "autopkg" },
  munki_catalog: { path: "munki/catalogs.tf", dir: "munki" },
  munki_manifest: { path: "munki/manifests.tf", dir: "munki" },
  munki_promotion: { path: "munki/promotion.tf", dir: "munki" },
  os_policy: { path: "munki/os_policy.tf", dir: "munki" },
  osquery_pack: { path: "osquery/packs.tf", dir: "osquery" },
  osquery_query: { path: "osquery/queries.tf", dir: "osquery" },
  osquery_label: { path: "osquery/labels.tf", dir: "osquery" },
  source_connector: { path: "sources/connectors.tf", dir: "sources" },
  log_view: { path: "logs/views.tf", dir: "logs" },
  vulnerability_settings: { path: "vulnerabilities/settings.tf", dir: "vulnerabilities" },
  cpe_override: { path: "vulnerabilities/settings.tf", dir: "vulnerabilities" },
  sla: { path: "vulnerabilities/settings.tf", dir: "vulnerabilities" },
};

export const DEFAULT_REPO = "Arequ/terraform-mission-control";
export const DEFAULT_BRANCH = "main";

function validSlug(slug: string): boolean {
  const [owner, name, extra] = slug.split("/");
  if (!owner || name == null || extra != null) return false;
  if (owner.length > 39 || name.length > 100 || owner.includes("--") || name.startsWith(".") || name.toLowerCase().endsWith(".git")) return false;
  const ownerOK = /^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$/.test(owner);
  const nameOK = /^[A-Za-z0-9_][A-Za-z0-9._-]*$/.test(name);
  return ownerOK && nameOK;
}

function validBranch(branch: string): boolean {
  if (!branch || branch.length > 255 || branch.startsWith("/") || branch.endsWith("/") || branch.includes("//") || branch.includes("..")) return false;
  return branch.split("/").every((part) => /^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(part));
}

export function proposeHref(repo: string, branch: string, kind: ConfigKind): string {
  const target = CONFIG_TARGETS[kind];
  const ref = branch.split("/").map((part) => encodeURIComponent(part)).join("%2F");
  const root = `https://github.com/${repo}`;
  if (target.path) return `${root}/edit/${ref}/${target.path}`;
  return `${root}/tree/${ref}/${target.dir}`;
}

export function defaultLinks(): Record<ConfigKind, string> {
  const links = {} as Record<ConfigKind, string>;
  (Object.keys(CONFIG_TARGETS) as ConfigKind[]).forEach((kind) => {
    links[kind] = proposeHref(DEFAULT_REPO, DEFAULT_BRANCH, kind);
  });
  return links;
}

export const DEFAULT_LINKS = defaultLinks();

export type ServerMeta = {
  config_repo: string;
  config_branch: string;
  config_links: Partial<Record<ConfigKind, string>>;
  break_glass?: boolean;
  sso_enabled?: boolean;
};

export const FALLBACK_META: ServerMeta = {
  config_repo: DEFAULT_REPO,
  config_branch: DEFAULT_BRANCH,
  config_links: DEFAULT_LINKS,
};

export function safeGitHubLink(value: string | undefined, kinds: Array<"edit" | "tree" | "compare">, repo?: string): string {
  if (!value) return "";
  let u: URL;
  try {
    u = new URL(value);
  } catch {
    return "";
  }
  if (u.protocol !== "https:" || u.hostname !== "github.com" || u.username !== "" || u.password !== "") return "";
  if (repo && !u.pathname.startsWith(`/${repo}/`)) return "";
  const path = u.pathname;
  const ok = kinds.some((kind) => path.includes(`/${kind}/`) || (kind === "compare" && path.includes("/compare")));
  return ok ? value : "";
}

export function acceptMeta(body: unknown): ServerMeta | null {
  if (!body || typeof body !== "object") return null;
  const rec = body as { config_repo?: unknown; config_branch?: unknown; config_links?: unknown };
  if (typeof rec.config_repo !== "string" || !validSlug(rec.config_repo)) return null;
  if (typeof rec.config_branch !== "string" || !validBranch(rec.config_branch)) return null;
  if (!rec.config_links || typeof rec.config_links !== "object") return null;
  const links: Partial<Record<ConfigKind, string>> = {};
  for (const key of Object.keys(CONFIG_TARGETS) as ConfigKind[]) {
    const value = (rec.config_links as Record<string, unknown>)[key];
    const safe = typeof value === "string" ? safeGitHubLink(value, ["edit", "tree"], rec.config_repo) : "";
    links[key] = safe || proposeHref(rec.config_repo, rec.config_branch, key);
  }
  const extra = body as { break_glass?: unknown; sso_enabled?: unknown };
  return {
    config_repo: rec.config_repo,
    config_branch: rec.config_branch,
    config_links: links,
    break_glass: extra.break_glass === true,
    sso_enabled: extra.sso_enabled === true,
  };
}
