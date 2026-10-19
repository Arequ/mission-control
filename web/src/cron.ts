const weekday = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"];

function clock(hour: string, minute: string): string | null {
  if (!/^\d{1,2}$/.test(hour) || !/^\d{1,2}$/.test(minute)) return null;
  const h = Number(hour);
  const m = Number(minute);
  if (h > 23 || m > 59) return null;
  return `${String(h).padStart(2, "0")}:${String(m).padStart(2, "0")}`;
}

// describeCron turns a five-field cron into a short label. Unknown shapes stay as the raw expression.
export function describeCron(expr: string): string {
  const parts = expr.trim().split(/\s+/);
  if (parts.length !== 5) return expr;
  const [minute, hour, dom, month, dow] = parts;
  if (dom === "*" && month === "*" && dow === "*" && minute === "0" && hour.startsWith("*/") && /^\d+$/.test(hour.slice(2))) {
    return `Every ${hour.slice(2)} hours`;
  }
  const at = clock(hour, minute);
  if (!at || dom !== "*" || month !== "*") return expr;
  if (dow === "*") return `Daily at ${at}`;
  if (dow === "1-5") return `Weekdays at ${at}`;
  if (/^\d$/.test(dow)) {
    const name = weekday[Number(dow)];
    if (name) return `${name}s at ${at}`;
  }
  return expr;
}
