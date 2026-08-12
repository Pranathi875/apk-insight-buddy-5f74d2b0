import type { Severity } from "@/lib/analysis/types";

export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes)) return "—";
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KB", "MB", "GB"];
  let value = bytes / 1024;
  let unitIndex = 0;
  while (value >= 1024 && unitIndex < units.length - 1) {
    value /= 1024;
    unitIndex += 1;
  }
  return `${value.toFixed(value >= 100 ? 0 : 1)} ${units[unitIndex]}`;
}

export function formatDelta(bytes: number): string {
  const sign = bytes > 0 ? "+" : bytes < 0 ? "−" : "";
  return `${sign}${formatBytes(Math.abs(bytes))}`;
}

export function severityClasses(severity: Severity): string {
  switch (severity) {
    case "HIGH":
      return "bg-severity-high/15 text-severity-high border-severity-high/40";
    case "MEDIUM":
      return "bg-severity-medium/15 text-severity-medium border-severity-medium/40";
    case "LOW":
      return "bg-severity-low/15 text-severity-low border-severity-low/40";
    default:
      return "bg-muted text-muted-foreground border-border";
  }
}

export function stateClasses(state: string): string {
  switch (state) {
    case "DETECTED":
      return "bg-chart-3/15 text-chart-3 border-chart-3/40";
    case "UNCERTAIN":
      return "bg-severity-medium/15 text-severity-medium border-severity-medium/40";
    default:
      return "bg-muted text-muted-foreground border-border";
  }
}

export function scoreColor(value: number): string {
  if (value >= 80) return "text-chart-3";
  if (value >= 55) return "text-severity-medium";
  return "text-severity-high";
}

export function shortHash(hash: string): string {
  return `${hash.slice(0, 12)}…${hash.slice(-6)}`;
}

export function formatDate(value: string): string {
  return new Date(value).toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}