import { createFileRoute } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { toast } from "sonner";

import { AppShell } from "@/components/appguard/AppShell";
import { Button } from "@/components/ui/button";
import { getAnalysis, listAnalyses, saveComparison } from "@/lib/appguard/store";
import { compareAnalyses, type ComparisonResult } from "@/lib/analysis/compare";
import { formatDelta, scoreColor } from "@/lib/appguard/format";

export const Route = createFileRoute("/compare")({
  head: () => ({
    meta: [
      { title: "Compare versions — AppGuard" },
      { name: "description", content: "Diff two stored APK analyses: permission, capability, component and score drift between releases." },
      { property: "og:title", content: "Compare versions — AppGuard" },
      { property: "og:description", content: "Release-to-release drift for Android packages, computed from stored analyses." },
    ],
  }),
  component: ComparePage,
});

function ComparePage() {
  const { data: rows } = useQuery({ queryKey: ["analyses", "all"], queryFn: () => listAnalyses(100) });
  const [baseId, setBaseId] = useState("");
  const [headId, setHeadId] = useState("");
  const [diff, setDiff] = useState<ComparisonResult | null>(null);
  const [busy, setBusy] = useState(false);

  const run = async () => {
    if (!baseId || !headId || baseId === headId) {
      toast.error("Pick two different analyses.");
      return;
    }
    setBusy(true);
    try {
      const [base, head] = await Promise.all([getAnalysis(baseId), getAnalysis(headId)]);
      if (!base || !head) throw new Error("One of the analyses could not be loaded.");
      const result = compareAnalyses(base.result, head.result, { baseId, headId });
      setDiff(result);
      void saveComparison(baseId, headId, result, head.result.rulesVersion).catch(() => undefined);
    } catch (error) {
      toast.error("Comparison failed", {
        description: error instanceof Error ? error.message : "Unknown error",
      });
    } finally {
      setBusy(false);
    }
  };

  const options = rows ?? [];

  return (
    <AppShell>
      <h1 className="font-display text-2xl font-semibold tracking-tight">Compare versions</h1>
      <p className="mt-1 text-sm text-muted-foreground">
        Select two stored analyses to see exactly what changed between releases.
      </p>

      <div className="mt-6 flex flex-wrap items-end gap-3">
        {(
          [
            ["Base", baseId, setBaseId],
            ["Head", headId, setHeadId],
          ] as const
        ).map(([label, value, setter]) => (
          <label key={label} className="flex flex-col gap-1 text-xs text-muted-foreground">
            {label}
            <select
              value={value}
              onChange={(event) => setter(event.target.value)}
              className="min-w-72 rounded-md border border-border bg-card px-3 py-2 text-sm text-foreground"
            >
              <option value="">Select an analysis…</option>
              {options.map((row) => (
                <option key={row.id} value={row.id}>
                  {row.package_name ?? row.file_name} · v{row.version_name ?? "?"} ({row.version_code ?? "?"})
                </option>
              ))}
            </select>
          </label>
        ))}
        <Button onClick={() => void run()} disabled={busy}>
          {busy ? "Comparing…" : "Compare"}
        </Button>
      </div>

      {diff && (
        <div className="mt-8 space-y-6">
          {!diff.samePackage && (
            <p className="rounded-md border border-severity-medium/40 bg-severity-medium/10 p-3 text-sm text-severity-medium">
              These analyses are different package names — the diff is structural only.
            </p>
          )}

          <div className="grid gap-3 sm:grid-cols-3 lg:grid-cols-6">
            <div className="rounded-lg border border-border bg-card p-4">
              <p className="font-mono text-[11px] uppercase tracking-wider text-muted-foreground">Overall</p>
              <p className={`font-display text-2xl font-semibold ${scoreColor(diff.overall.to)}`}>
                {diff.overall.from} → {diff.overall.to}
              </p>
            </div>
            {diff.scores.map((score) => (
              <div key={score.key} className="rounded-lg border border-border bg-card p-4">
                <p className="font-mono text-[11px] uppercase tracking-wider text-muted-foreground">{score.label}</p>
                <p className={`font-display text-2xl font-semibold ${scoreColor(score.to)}`}>
                  {score.from} → {score.to}
                </p>
              </div>
            ))}
            <div className="rounded-lg border border-border bg-card p-4">
              <p className="font-mono text-[11px] uppercase tracking-wider text-muted-foreground">Size</p>
              <p className="font-display text-2xl font-semibold">{formatDelta(diff.sizeDelta)}</p>
            </div>
          </div>

          <div className="rounded-lg border border-border bg-card p-5">
            <h2 className="font-display text-sm font-semibold">Change log</h2>
            <ul className="mt-2 space-y-1 font-mono text-xs text-muted-foreground">
              {diff.summaryLines.length === 0 && <li>No structural differences detected.</li>}
              {diff.summaryLines.map((line) => (
                <li key={line}>• {line}</li>
              ))}
            </ul>
          </div>

          <div className="grid gap-4 md:grid-cols-2">
            <DiffCard title="Permissions" added={diff.permissions.added} removed={diff.permissions.removed} />
            <DiffCard title="Capabilities" added={diff.capabilities.added} removed={diff.capabilities.removed} />
            <DiffCard title="Libraries" added={diff.libraries.added} removed={diff.libraries.removed} />
            <DiffCard title="Components" added={diff.components.added} removed={diff.components.removed} />
          </div>
        </div>
      )}
    </AppShell>
  );
}

function DiffCard({ title, added, removed }: { title: string; added: string[]; removed: string[] }) {
  return (
    <div className="rounded-lg border border-border bg-card p-5">
      <h3 className="font-display text-sm font-semibold">{title}</h3>
      <ul className="mt-2 space-y-1 font-mono text-[11px]">
        {added.map((item) => (
          <li key={`+${item}`} className="text-chart-3">
            + {item}
          </li>
        ))}
        {removed.map((item) => (
          <li key={`-${item}`} className="text-severity-high">
            − {item}
          </li>
        ))}
        {added.length === 0 && removed.length === 0 && <li className="text-muted-foreground">no change</li>}
      </ul>
    </div>
  );
}