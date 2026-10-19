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

const TOKEN_KEY = "mc.token";

export function getToken(): string {
  return sessionStorage.getItem(TOKEN_KEY) ?? "";
}

export function setToken(token: string) {
  sessionStorage.setItem(TOKEN_KEY, token.trim());
}

export function clearToken() {
  sessionStorage.removeItem(TOKEN_KEY);
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const headers = new Headers(init?.headers);
  const token = getToken();
  if (token) headers.set("Authorization", `Bearer ${token}`);
  if (init?.body && !headers.has("Content-Type")) headers.set("Content-Type", "application/json");
  const res = await fetch(base + path, { ...init, headers });
  if (res.status === 401) {
    clearToken();
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
  devices: (params: { q?: string; status?: string; label?: string; limit?: number }) => {
    const q = new URLSearchParams();
    if (params.q) q.set("q", params.q);
    if (params.status) q.set("status", params.status);
    if (params.label) q.set("label", params.label);
    q.set("limit", String(params.limit ?? 100));
    return request<{ devices: Device[]; total: number }>(`/api/v1/devices?${q}`);
  },
  device: (id: string) => request<Device>(`/api/v1/devices/${id}`),
  queries: () => request<{ queries: OsqueryQuery[] }>("/api/v1/osquery/queries"),
  packs: () => request<{ packs: OsqueryPack[] }>("/api/v1/osquery/packs"),
  labels: () => request<{ labels: OsqueryLabel[] }>("/api/v1/osquery/labels"),
  runLive: (body: { sql: string; device_ids?: string[]; labels?: string[]; timeout_seconds: number }) =>
    request<LiveQuery>("/api/v1/live-queries", { method: "POST", body: JSON.stringify(body) }),
  liveQuery: (id: string) => request<LiveQuery>(`/api/v1/live-queries/${id}`),
};
