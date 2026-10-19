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
};
