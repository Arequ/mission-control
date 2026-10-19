export interface Principal {
  id: string;
  name: string;
  role: string;
}

export interface Device {
  id: string;
  hostIdentifier: string;
  hostname: string;
  computerName: string;
  uuid: string;
  hardwareSerial: string;
  hardwareModel: string;
  hardwareVendor: string;
  cpuBrand: string;
  cpuPhysicalCores: number;
  physicalMemory: number;
  platform: string;
  osName: string;
  osVersion: string;
  osBuild: string;
  osqueryVersion: string;
  primaryUser: string;
  configHash: string;
  configDrift: boolean;
  labels: string[];
  lastSeenAt?: string;
  enrolledAt: string;
}

export interface AppItem {
  name: string;
  bundleId: string;
  path: string;
  version: string;
}

export interface QueryResult {
  name: string;
  collectedAt: string;
}

export interface NamedCount {
  name: string;
  count: number;
}

export interface FleetSummary {
  devices: number;
  online: number;
  offline: number;
  configDrift: number;
  platforms: NamedCount[];
  osVersions: NamedCount[];
  models: NamedCount[];
  topApps: { name: string; devices: number }[];
  recent: Device[];
}

export interface Resource {
  apiVersion: string;
  kind: string;
  metadata: { name: string; namespace?: string; labels?: Record<string, string> };
  spec: Record<string, unknown>;
  status?: {
    managedBy?: string;
    generation?: number;
    specHash?: string;
    sourcePath?: string;
    appliedAt?: string;
  };
  sourcePath?: string;
}

export interface SyncStatus {
  directory: string;
  gitPull: boolean;
  lastAttempt?: string;
  lastSuccess?: string;
  lastError?: string;
  summary: { create: number; update: number; delete: number; unchanged: number };
}

export interface LiveQuery {
  id: string;
  sql: string;
  createdAt: string;
  targets?: {
    deviceId: string;
    hostname: string;
    status: string;
    results?: unknown;
    osqueryStatus?: number;
  }[];
}

export interface Job {
  id: string;
  pipelineName: string;
  status: string;
  runnerId?: string;
  logs?: string;
  createdAt: string;
  finishedAt?: string;
}

export interface Runner {
  id: string;
  name: string;
  autopkgVersion?: string;
  osVersion?: string;
  lastSeenAt?: string;
}
