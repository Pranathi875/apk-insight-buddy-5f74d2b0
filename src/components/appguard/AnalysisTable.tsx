import { Link } from "@tanstack/react-router";

import { Badge } from "@/components/ui/badge";
import type { AnalysisSummaryRow } from "@/lib/appguard/store";
import { formatBytes, formatDate, scoreColor } from "@/lib/appguard/format";

export function AnalysisTable({
  rows,
  emptyMessage,
}: {
  rows: AnalysisSummaryRow[];
  emptyMessage: string;
}) {
  if (rows.length === 0) {
    return (
      <div className="rounded-lg border border-dashed border-border p-8 text-center text-sm text-muted-foreground">
        {emptyMessage}
      </div>
    );
  }

  return (
    <div className="overflow-x-auto rounded-lg border border-border">
      <table className="w-full text-sm">
        <thead className="bg-secondary/60 text-left font-mono text-[11px] uppercase tracking-wider text-muted-foreground">
          <tr>
            <th className="px-4 py-2.5">Package</th>
            <th className="px-4 py-2.5">Version</th>
            <th className="px-4 py-2.5">SDK</th>
            <th className="px-4 py-2.5">Size</th>
            <th className="px-4 py-2.5">Findings</th>
            <th className="px-4 py-2.5">Overall</th>
            <th className="px-4 py-2.5">Analyzed</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={row.id} className="border-t border-border/70 transition-colors hover:bg-accent/40">
              <td className="px-4 py-3">
                <Link to="/analysis/$id" params={{ id: row.id }} className="font-medium text-foreground hover:text-primary">
                  {row.package_name ?? row.file_name}
                </Link>
                <div className="font-mono text-[11px] text-muted-foreground">{row.file_name}</div>
              </td>
              <td className="px-4 py-3 font-mono text-xs">
                {row.version_name ?? "—"}
                {row.version_code !== null ? ` (${row.version_code})` : ""}
              </td>
              <td className="px-4 py-3 font-mono text-xs">
                {row.min_sdk ?? "?"} → {row.target_sdk ?? "?"}
              </td>
              <td className="px-4 py-3 font-mono text-xs">{formatBytes(row.file_size)}</td>
              <td className="px-4 py-3">
                <div className="flex gap-1">
                  {row.findings_high > 0 && (
                    <Badge variant="outline" className="border-severity-high/40 bg-severity-high/15 text-severity-high">
                      {row.findings_high} high
                    </Badge>
                  )}
                  {row.findings_medium > 0 && (
                    <Badge variant="outline" className="border-severity-medium/40 bg-severity-medium/15 text-severity-medium">
                      {row.findings_medium} med
                    </Badge>
                  )}
                  {row.findings_high === 0 && row.findings_medium === 0 && (
                    <span className="text-xs text-muted-foreground">{row.findings_low + row.findings_info} minor</span>
                  )}
                </div>
              </td>
              <td className={`px-4 py-3 font-display font-semibold ${scoreColor(row.overall_score)}`}>
                {row.overall_score}
              </td>
              <td className="px-4 py-3 text-xs text-muted-foreground">{formatDate(row.created_at)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}