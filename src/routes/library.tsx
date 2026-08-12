import { createFileRoute } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";

import { AppShell } from "@/components/appguard/AppShell";
import { AnalysisTable } from "@/components/appguard/AnalysisTable";
import { listAnalyses } from "@/lib/appguard/store";

export const Route = createFileRoute("/library")({
  head: () => ({
    meta: [
      { title: "Analysis library — AppGuard" },
      { name: "description", content: "Every APK analysis stored in this AppGuard workspace, with scores and findings." },
      { property: "og:title", content: "Analysis library — AppGuard" },
      { property: "og:description", content: "Browse stored APK analyses with scores, findings and version metadata." },
    ],
  }),
  component: LibraryPage,
});

function LibraryPage() {
  const { data, isLoading } = useQuery({ queryKey: ["analyses", "all"], queryFn: () => listAnalyses(100) });

  return (
    <AppShell>
      <h1 className="font-display text-2xl font-semibold tracking-tight">Analysis library</h1>
      <p className="mt-1 mb-6 text-sm text-muted-foreground">
        Stored reports from every package analyzed in this workspace.
      </p>
      {isLoading ? (
        <div className="rounded-lg border border-border p-8 text-center text-sm text-muted-foreground">Loading…</div>
      ) : (
        <AnalysisTable rows={data ?? []} emptyMessage="Nothing stored yet." />
      )}
    </AppShell>
  );
}