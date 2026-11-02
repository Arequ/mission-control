const base = import.meta.env.VITE_API_BASE ?? "";

export type JobSummary = {
  id: string;
  status: string;
  result?: string;
  trigger: string;
  finished_at?: string;
  created_at: string;
};

export type Recipe = {
  id: string;
  identifier: string;
  name: string;
  enabled: boolean;
  labels: string[];
  managed_by: string;
  last_job?: JobSummary;
};

export type Schedule = {
  id: string;
  name: string;
  recipe_id: string;
  recipe_identifier?: string;
  cron: string;
  timezone?: string;
  enabled: boolean;
  managed_by: string;
};

export type Pipeline = {
  max_concurrency: number;
  per_runner_parallelism: number;
  timeout_seconds: number;
  max_retries: number;
  lease_seconds: number;
  managed_by: string;
};

export type Job = {
  id: string;
  recipe_id: string;
  recipe_identifier?: string;
  recipe_name?: string;
  trigger: string;
  status: string;
  result?: string;
  attempt: number;
  max_attempts: number;
  runner_name?: string;
  error?: string;
  started_at?: string;
  finished_at?: string;
  created_at: string;
  logs?: { id: number; stream: string; line: string; at: string }[];
};

export type Runner = {
  id: string;
  name: string;
  pool_name?: string;
  labels: string[];
  hostname: string;
  os_version: string;
  autopkg_version: string;
  last_heartbeat_at?: string;
  status: string;
  active_jobs: number;
};

export type Package = {
  id: string;
  name: string;
  version: string;
  catalog: string;
  filename: string;
  soak_status: string;
  soak_ends_at?: string;
  promoted_at?: string;
  created_at: string;
};

export type Catalog = { name: string; item_count: number; generated_at?: string };

export type Manifest = {
  id: string;
  name: string;
  catalogs: string[];
  included_manifests: string[];
  managed_installs: string[];
  optional_installs: string[];
  managed_uninstalls: string[];
  managed_by: string;
};

export type PromotionRule = {
  id: string;
  name: string;
  from_catalog: string;
  to_catalog: string;
  soak_days: number;
  manual_hold: boolean;
  enabled: boolean;
  managed_by: string;
};

export type FleetSummary = {
  total_devices: number;
  online_devices: number;
  enrolled_this_week: number;
  offline_after_seconds: number;
  macos_versions: { version: string; name: string; count: number }[];
  autopkg: {
    recipes: number;
    enabled: number;
    testing_packages: number;
    production_packages: number;
    last_recipe?: string;
    last_result?: string;
    last_finished_at?: string;
  };
};

export type DeviceApp = { name: string; path: string; bundle_id: string; version: string };

export type DeviceEvent = {
  id: number;
  at: string;
  action: string;
  detail: Record<string, unknown>;
};

export type Device = {
  id: string;
  hostname: string;
  computer_name: string;
  serial: string;
  platform: string;
  os_version: string;
  os_build: string;
  os_display?: string;
  hardware_model: string;
  model_name?: string;
  cpu_brand: string;
  cpu_type: string;
  cpu_physical_cores: number;
  physical_memory: number;
  primary_ip: string;
  primary_mac: string;
  username: string;
  disk_encrypted: boolean | null;
  uptime_seconds: number;
  osquery_version: string;
  last_seen_at?: string;
  enrolled_at: string;
  status?: string;
  labels?: string[];
  apps?: DeviceApp[];
  events?: DeviceEvent[];
  coverage?: { seen: number; total: number };
  munki?: MunkiCard;
};

export type MunkiCard = {
  status: string;
  last_run_start?: string;
  last_run_end?: string;
  pending: number;
  pending_installs: string[];
  pending_removals: string[];
  errors: string[];
  warnings: string[];
  munki_version: string;
  console_user: string;
  manifest: string;
};

export type OsqueryQuery = {
  id: string;
  name: string;
  description: string;
  sql: string;
  platform: string;
  interval: number;
  snapshot: boolean;
  removed: boolean;
  scheduled: boolean;
  managed_by: string;
};

export type OsqueryPack = {
  id: string;
  name: string;
  description: string;
  platform: string;
  interval?: number;
  labels: string[];
  queries?: { name: string; interval: number; snapshot: boolean }[];
  enabled: boolean;
  managed_by: string;
};

export type OsqueryLabel = {
  id: string;
  name: string;
  description: string;
  kind: string;
  members?: number;
};

export type CoverageCell = {
  source: string;
  state: "seen" | "stale" | "missing" | string;
  last_seen_at?: string;
  native_id?: string;
};

export type CoverageRow = {
  id: string;
  kind: string;
  name: string;
  hostname: string;
  serial: string;
  user: string;
  os_version: string;
  seen: number;
  total: number;
  cells: CoverageCell[];
};

export type CoverageMatrix = {
  sources: { key: string; name: string; short: string; percent: number; stale_after_seconds: number }[];
  rows: CoverageRow[];
  total: number;
  gaps: number;
  limit: number;
  offset: number;
};

export type CoverageDevice = {
  id: string;
  kind: string;
  name: string;
  hostname: string;
  serial: string;
  user: string;
  os_version: string;
  model?: string;
  device_id?: string;
  match: { confidence: string; matched_on: string[]; note: string };
  seen: number;
  total: number;
  sources: {
    key: string;
    name: string;
    short: string;
    state: string;
    last_seen_at?: string;
    native_id?: string;
    confidence?: string;
    matched_on?: string[];
  }[];
  fields: {
    field: string;
    label: string;
    unified: string;
    values: { source: string; value: string; disagrees: boolean }[];
  }[];
  events: { id: number; at: string; source: string; kind: string; detail: Record<string, unknown> }[];
};

export type SourceConnector = {
  id: string;
  name: string;
  source: string;
  mode: string;
  enabled: boolean;
  stale_after_seconds: number;
  last_sync_at?: string;
  last_sync_status: string;
  last_sync_error: string;
  last_sync_count: number;
};

export type LiveQuery = {
  id: string;
  sql: string;
  status: string;
  timeout_seconds: number;
  created_at: string;
  finished_at?: string;
  targets?: { device_id: string; hostname?: string; computer_name?: string; status: string; error?: string }[];
  rows?: Record<string, string>[];
};

export type LogSource = {
  label: string;
  color: string;
  index_pattern: string;
  kql: string;
  message_field: string;
  timestamp_field: string;
  file_field: string;
  host_field: string;
  sequence_field: string;
};

export type LogView = {
  id: string;
  name: string;
  description: string;
  default_window: string;
  max_lines: number;
  device_scoped: boolean;
  time_zone: string;
  elastic_url: string;
  connector_id: string;
  managed_by: string;
  has_elastic_api_key: boolean;
  sources: LogSource[];
};

export type LogLine = {
  id: string;
  timestamp: string;
  source: string;
  color: string;
  file: string;
  host: string;
  message: string;
};

export type LogPage = {
  lines: LogLine[];
  cursor: string;
  has_more_before: boolean;
  has_more_after: boolean;
  truncated: boolean;
  from: string;
  to: string;
};

export type LogContext = { lines: LogLine[]; focus: number };

export type LogQuery = {
  from?: string;
  to?: string;
  device_id?: string;
  limit?: number;
  cursor?: string;
  dir?: string;
  align?: string;
};

export type IssueFix = {
  action: string;
  fixed_version?: string;
  fixed_build?: string;
  catalog?: string;
  catalog_version?: string;
  recipe_id?: string;
  recipe_name?: string;
  recipe_status?: string;
  required_os?: string;
  pr_url?: string;
  pr_title?: string;
  pr_body?: string;
};

export type VulnerabilityIssue = {
  id: string;
  cve_id: string;
  software_key: string;
  software_name: string;
  status: string;
  assignee: string;
  notes: string;
  risk_until?: string;
  opened_at: string;
  updated_at: string;
  resolved_at?: string;
  auto_resolved: boolean;
  revision: number;
  description: string;
  cvss_score: number;
  cvss_vector: string;
  severity: string;
  kev: boolean;
  kev_name?: string;
  epss: number;
  epss_percentile: number;
  epss_known: boolean;
  source: string;
  device_count: number;
  sla_days: number;
  sla_due: string;
  within_sla: boolean;
  fix: IssueFix;
};

export type VulnerabilitySummary = {
  open: number;
  kev: number;
  kev_devices: number;
  with_fix: number;
  within_sla: number;
  due_this_week: number;
  opened_this_week: number;
};

export type AffectedDevice = {
  id: string;
  hostname: string;
  computer_name: string;
  serial: string;
  username: string;
  version: string;
  build: string;
  evidence: string;
};

export type IssueEvent = {
  id: string;
  at: string;
  actor: string;
  action: string;
  detail: Record<string, unknown>;
};

export type VulnerabilityDetail = VulnerabilityIssue & {
  devices: AffectedDevice[];
  events: IssueEvent[];
  installs: number;
  affected: number;
};

export type IssueQuery = {
  kev?: boolean;
  severity?: string;
  status?: string;
  hasFix?: boolean;
  active?: boolean;
  q?: string;
  limit?: number;
  offset?: number;
};

export type SessionUser = {
  email: string;
  name: string;
  role: string;
  csrf_token: string;
};

export type PublicProvider = { id: string; name: string; issuer: string };

let csrfToken = "";

export function currentCSRF(): string {
  return csrfToken;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const headers = new Headers(init?.headers);
  const method = (init?.method ?? "GET").toUpperCase();
  if (csrfToken && method !== "GET" && method !== "HEAD") headers.set("X-CSRF-Token", csrfToken);
  if (init?.body && !headers.has("Content-Type")) headers.set("Content-Type", "application/json");
  const res = await fetch(base + path, { ...init, headers, credentials: "include" });
  if (res.status === 401) {
    csrfToken = "";
    throw new Error("unauthorized");
  }
  if (!res.ok) {
    let message = res.statusText;
    try {
      const body = (await res.json()) as { error?: string };
      if (body.error) message = body.error;
    } catch {
      /* ignore */
    }
    throw new Error(message);
  }
  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}

export const api = {
  session: async () => {
    const user = await request<SessionUser>("/api/v1/session");
    csrfToken = user.csrf_token;
    return user;
  },
  providers: () => request<{ providers: PublicProvider[] }>("/api/v1/sso/providers"),
  breakGlass: async (password: string) => {
    const user = await request<SessionUser>("/api/v1/session/break-glass", {
      method: "POST",
      body: JSON.stringify({ password }),
    });
    csrfToken = user.csrf_token;
    return user;
  },
  signOut: async () => {
    const res = await request<{ ok: boolean; logout_url?: string }>("/api/v1/session/logout", { method: "POST" });
    csrfToken = "";
    const next = res.logout_url ?? "";
    if (next.startsWith("https://") || next.startsWith("http://")) {
      window.location.assign(next);
      return;
    }
    window.location.assign("/");
  },
  recipes: () => request<{ recipes: Recipe[] }>("/api/v1/recipes"),
  schedules: () => request<{ schedules: Schedule[] }>("/api/v1/schedules"),
  pipeline: () => request<Pipeline>("/api/v1/pipeline-settings"),
  jobs: () => request<{ jobs: Job[] }>("/api/v1/jobs?limit=100"),
  job: (id: string) => request<Job>(`/api/v1/jobs/${id}`),
  runNow: (recipeId: string) =>
    request<Job>("/api/v1/jobs", { method: "POST", body: JSON.stringify({ recipe_id: recipeId }) }),
  runners: () => request<{ runners: Runner[] }>("/api/v1/runners"),
  catalogs: () => request<{ catalogs: Catalog[] }>("/api/v1/catalogs"),
  packages: () => request<{ packages: Package[] }>("/api/v1/packages"),
  manifests: () => request<{ manifests: Manifest[] }>("/api/v1/manifests"),
  rules: () => request<{ promotion_rules: PromotionRule[] }>("/api/v1/promotion-rules"),
  summary: () => request<FleetSummary>("/api/v1/fleet/summary"),
  devices: (params: { q?: string; status?: string; label?: string; limit?: number; offset?: number }) => {
    const q = new URLSearchParams();
    if (params.q) q.set("q", params.q);
    if (params.status) q.set("status", params.status);
    if (params.label) q.set("label", params.label);
    q.set("limit", String(params.limit ?? 100));
    if (params.offset) q.set("offset", String(params.offset));
    return request<{ devices: Device[]; total: number }>(`/api/v1/devices?${q}`);
  },
  device: (id: string) => request<Device>(`/api/v1/devices/${id}`),
  queries: () => request<{ queries: OsqueryQuery[] }>("/api/v1/osquery/queries"),
  packs: () => request<{ packs: OsqueryPack[] }>("/api/v1/osquery/packs"),
  labels: () => request<{ labels: OsqueryLabel[] }>("/api/v1/osquery/labels"),
  runLive: (body: { sql: string; device_ids?: string[]; labels?: string[]; timeout_seconds: number }) =>
    request<LiveQuery>("/api/v1/live-queries", { method: "POST", body: JSON.stringify(body) }),
  liveQuery: (id: string) => request<LiveQuery>(`/api/v1/live-queries/${id}`),
  coverageMatrix: (params: { filter?: string; source?: string; staleDays?: number; q?: string; limit?: number; offset?: number }) => {
    const q = new URLSearchParams();
    if (params.filter) q.set("filter", params.filter);
    if (params.source) q.set("source", params.source);
    if (params.staleDays) q.set("stale_days", String(params.staleDays));
    if (params.q) q.set("q", params.q);
    q.set("limit", String(params.limit ?? 100));
    if (params.offset) q.set("offset", String(params.offset));
    return request<CoverageMatrix>(`/api/v1/coverage/matrix?${q}`);
  },
  coverageDevice: (id: string) => request<CoverageDevice>(`/api/v1/coverage/devices/${id}`),
  coverageConnectors: () => request<{ connectors: SourceConnector[] }>("/api/v1/coverage/connectors"),
  logViews: () => request<{ views: LogView[] }>("/api/v1/log-views"),
  logView: (id: string) => request<LogView>(`/api/v1/log-views/${id}`),
  queryLog: (id: string, body: LogQuery) =>
    request<LogPage>(`/api/v1/log-views/${id}/query`, { method: "POST", body: JSON.stringify(body) }),
  tailLog: (id: string, body: { device_id?: string; limit?: number; cursor: string }) =>
    request<LogPage>(`/api/v1/log-views/${id}/tail`, { method: "POST", body: JSON.stringify(body) }),
  contextLog: (id: string, body: { device_id?: string; line_id: string; before: number; after: number }) =>
    request<LogContext>(`/api/v1/log-views/${id}/context`, { method: "POST", body: JSON.stringify(body) }),
  vulnerabilityIssues: (params: IssueQuery = {}) => {
    const q = new URLSearchParams();
    if (params.kev != null) q.set("kev", String(params.kev));
    if (params.severity) q.set("severity", params.severity);
    if (params.status) q.set("status", params.status);
    if (params.hasFix != null) q.set("has_fix", String(params.hasFix));
    if (params.active) q.set("active", "true");
    if (params.q) q.set("q", params.q);
    q.set("limit", String(params.limit ?? 200));
    if (params.offset) q.set("offset", String(params.offset));
    return request<{ issues: VulnerabilityIssue[]; summary: VulnerabilitySummary; total: number; limit: number; offset: number }>(`/api/v1/vulnerability-issues?${q}`);
  },
  vulnerabilityIssue: (id: string) => request<VulnerabilityDetail>(`/api/v1/vulnerability-issues/${id}`),
  updateVulnerabilityIssue: (id: string, body: { status: string; assignee: string; notes: string; risk_until: string | null; revision: number }) =>
    request<VulnerabilityIssue>(`/api/v1/vulnerability-issues/${id}`, { method: "POST", body: JSON.stringify(body) }),
  runVulnerabilityRecipe: (id: string) =>
    request<Job>(`/api/v1/vulnerability-issues/${id}/run-recipe`, { method: "POST" }),
  deviceVulnerabilities: (id: string) => request<{ issues: VulnerabilityIssue[] }>(`/api/v1/devices/${id}/vulnerabilities`),
};
