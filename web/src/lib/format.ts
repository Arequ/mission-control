export function displayName(device: { computerName?: string; hostname?: string; hostIdentifier?: string }) {
  return device.computerName || device.hostname || device.hostIdentifier || "Unknown Mac";
}

export function formatBytes(bytes: number): string {
  if (!bytes) return "—";
  const gb = bytes / 1024 ** 3;
  if (gb >= 1) return `${gb >= 10 ? Math.round(gb) : gb.toFixed(1)} GB`;
  const mb = bytes / 1024 ** 2;
  return `${Math.round(mb)} MB`;
}

export function ago(iso?: string): string {
  if (!iso) return "never";
  const seconds = Math.round((Date.now() - new Date(iso).getTime()) / 1000);
  if (Number.isNaN(seconds)) return "—";
  if (seconds < 45) return "just now";
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}

export function isOnline(iso?: string): boolean {
  if (!iso) return false;
  return Date.now() - new Date(iso).getTime() < 30 * 60 * 1000;
}

export function osLabel(device: { osName?: string; osVersion?: string }): string {
  return [device.osName, device.osVersion].filter(Boolean).join(" ") || "Unknown";
}
