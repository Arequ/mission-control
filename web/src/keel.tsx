import { Fragment, type ReactNode } from "react";
import type { KeelSummary } from "./api";
import { Icon } from "./icons";

// Keel always serializes a secret as this literal. It renders as a muted
// pill and nothing else, wherever it appears.
export const REDACTED = "[redacted]";

export function Redacted() {
  return (
    <span className="redacted" title="Secret value. Keel never reports it.">
      <Icon name="lock" size={10} />
      redacted
    </span>
  );
}

export function RoleChain({ chain, match }: { chain: string[]; match?: string }) {
  if (chain.length === 0) return <span className="faint">No role</span>;
  return (
    <span className="role-chain">
      {chain.map((name, i) => (
        <Fragment key={`${name}-${i}`}>
          {i > 0 ? <span className="role-sep" aria-hidden="true">→</span> : null}
          <span className={`role-chip${i === chain.length - 1 ? " leaf" : ""}`}>{name}</span>
        </Fragment>
      ))}
      {match ? <span className="role-match" title="Why this Mac is in its leaf role">{match}</span> : null}
    </span>
  );
}

export function Warnings({ warnings }: { warnings?: string[] }) {
  if (!warnings || warnings.length === 0) return null;
  const compile = warnings.some((w) => w.startsWith("compile: "));
  return (
    <section className={`card keel-warnings enter${compile ? " hot" : ""}`} role="status">
      <div className="card-h">
        <Icon name="alert" size={15} />
        <span className="card-t">{compile ? "Policy did not compile" : warnings.length === 1 ? "1 warning" : `${warnings.length} warnings`}</span>
      </div>
      <ul>
        {warnings.map((w, i) => <li key={i} className="mono-v">{w}</li>)}
      </ul>
    </section>
  );
}

export function duration(ms?: number) {
  if (ms == null) return "—";
  if (ms < 1000) return `${ms} ms`;
  const s = ms / 1000;
  if (s < 60) return `${s.toFixed(s < 10 ? 1 : 0)} s`;
  return `${Math.floor(s / 60)}m ${Math.round(s % 60)}s`;
}

export function SummaryCounts({ summary, mode }: { summary?: Partial<KeelSummary>; mode?: string }) {
  const s = summary ?? {};
  const items: { k: string; v: number; tone: string }[] = [
    { k: "Total", v: s.total ?? 0, tone: "" },
    { k: "OK", v: s.ok ?? 0, tone: "" },
    mode === "plan"
      ? { k: "Would change", v: s.would_change ?? 0, tone: (s.would_change ?? 0) > 0 ? "warn" : "" }
      : { k: "Changed", v: s.changed ?? 0, tone: (s.changed ?? 0) > 0 ? "info" : "" },
    { k: "Failed", v: s.failed ?? 0, tone: (s.failed ?? 0) > 0 ? "hot" : "" },
    { k: "Skipped", v: s.skipped ?? 0, tone: "" },
  ];
  return (
    <div className="keel-counts">
      {items.map((item) => (
        <div key={item.k} className={`keel-count ${item.tone}`}>
          <b className="tnum">{item.v}</b>
          <span>{item.k}</span>
        </div>
      ))}
    </div>
  );
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

export function Scalar({ value }: { value: unknown }) {
  if (value === REDACTED) return <Redacted />;
  if (value === null || value === undefined) return <span className="faint">null</span>;
  if (typeof value === "boolean") return <span className={`bool ${value ? "on" : "off"}`}>{value ? "true" : "false"}</span>;
  if (typeof value === "number") return <span className="tnum">{value}</span>;
  if (typeof value === "string") return value === "" ? <span className="faint">empty</span> : <span className="mono-v">{value}</span>;
  return <span className="mono-v">{JSON.stringify(value)}</span>;
}

function scalarList(list: unknown[]) {
  return list.every((v) => v === null || ["string", "number", "boolean"].includes(typeof v));
}

// A readable, collapsible view of an effective-settings object. Objects and
// arrays of objects nest; arrays of scalars render inline as chips.
export function SettingsTree({ value, depth = 0 }: { value: unknown; depth?: number }) {
  if (isRecord(value)) {
    const keys = Object.keys(value).sort();
    if (keys.length === 0) return <div className="tree-empty faint">No settings</div>;
    return (
      <div className={`tree${depth === 0 ? " root" : ""}`}>
        {keys.map((key) => <TreeNode key={key} name={key} value={value[key]} depth={depth} />)}
      </div>
    );
  }
  if (Array.isArray(value)) {
    return (
      <div className={`tree${depth === 0 ? " root" : ""}`}>
        {value.map((item, i) => <TreeNode key={i} name={`${i + 1}`} value={item} depth={depth} index />)}
      </div>
    );
  }
  return <div className="tree root"><div className="tree-leaf"><Scalar value={value} /></div></div>;
}

function TreeNode({ name, value, depth, index }: { name: string; value: unknown; depth: number; index?: boolean }) {
  const nested = (isRecord(value) && Object.keys(value).length > 0) || (Array.isArray(value) && !scalarList(value));
  if (nested) {
    const count = Array.isArray(value) ? value.length : Object.keys(value as object).length;
    return (
      <details className="tree-branch" open={depth < 2}>
        <summary>
          <span className="tree-caret" aria-hidden="true">›</span>
          <span className={`tree-k${index ? " idx" : ""}`}>{name}</span>
          <span className="faint tree-n">{count}</span>
        </summary>
        <SettingsTree value={value} depth={depth + 1} />
      </details>
    );
  }
  return (
    <div className="tree-leaf">
      <span className={`tree-k${index ? " idx" : ""}`}>{name}</span>
      <span className="tree-v">{renderInline(value)}</span>
    </div>
  );
}

function renderInline(value: unknown): ReactNode {
  if (Array.isArray(value)) {
    if (value.length === 0) return <span className="faint">none</span>;
    return (
      <span className="tree-list">
        {value.map((item, i) => (
          item === REDACTED ? <Redacted key={i} /> : <span key={i} className="chip">{item === null ? "null" : String(item)}</span>
        ))}
      </span>
    );
  }
  if (isRecord(value)) return <span className="faint">{"{}"}</span>;
  return <Scalar value={value} />;
}
