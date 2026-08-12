import { createFileRoute, Link } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { FileSearch, GitCompare, ScrollText, Cpu } from "lucide-react";

import { AppShell } from "@/components/appguard/AppShell";
import { UploadPanel } from "@/components/appguard/UploadPanel";
import { AnalysisTable } from "@/components/appguard/AnalysisTable";
import { listAnalyses } from "@/lib/appguard/store";

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title: "AppGuard — Android APK Static Analysis" },
      {
        name: "description",
        content:
          "Analyze Android APKs in the browser: manifest, permissions, components, DEX capabilities, libraries, explainable findings and scoring.",
      },
      { property: "og:title", content: "AppGuard — Android APK Static Analysis" },
      {
        property: "og:description",
        content: "Explainable APK static analysis with capability detection, scoring and version comparison.",
      },
    ],
  }),
  component: Index,
});

const PIPELINE = [
  {
    icon: FileSearch,
    title: "Container & manifest",
    body: "ZIP central directory, signing artifacts, and a binary AndroidManifest.xml decoder that resolves the string pool and resource-mapped attributes.",
  },
  {
    icon: Cpu,
    title: "DEX capability inference",
    body: "Class descriptors and filtered string tokens are matched against an evidence-weighted capability catalog with explicit confidence levels.",
  },
  {
    icon: ScrollText,
    title: "Rules & explainable scoring",
    body: "Deterministic rules produce findings with cited evidence; every score shows the exact deductions that produced it.",
  },
  {
    icon: GitCompare,
    title: "Version comparison",
    body: "Diff two stored analyses for permission, capability, component and score drift between releases.",
  },
];

function Index() {
  const { data, refetch } = useQuery({
    queryKey: ["analyses", "recent"],
    queryFn: () => listAnalyses(6),
  });

  return (
    <AppShell>
      <section className="grid gap-8 lg:grid-cols-[1.05fr_1fr] lg:items-center">
        <div className="space-y-5">
          <span className="inline-flex items-center gap-2 rounded-full border border-border bg-secondary px-3 py-1 font-mono text-[11px] uppercase tracking-widest text-muted-foreground">
            Application intelligence
          </span>
          <h1 className="font-display text-4xl leading-tight font-semibold tracking-tight sm:text-5xl">
            Understand what an Android package{" "}
            <span className="text-primary">actually does</span>
          </h1>
          <p className="max-w-xl text-base text-muted-foreground">
            AppGuard decodes an APK end to end and explains its behaviour with cited evidence:
            declared permissions, exported components, inferred capabilities, bundled libraries and
            transparent quality, security and privacy indicators.
          </p>
          <div className="flex flex-wrap gap-2 font-mono text-[11px] text-muted-foreground">
            <span className="rounded border border-border px-2 py-1">no server-side upload</span>
            <span className="rounded border border-border px-2 py-1">deterministic rules</span>
            <span className="rounded border border-border px-2 py-1">exportable HTML report</span>
          </div>
        </div>

        <UploadPanel onSaved={() => void refetch()} />
      </section>

      <section className="mt-14 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {PIPELINE.map((item) => (
          <div key={item.title} className="rounded-lg border border-border bg-card p-5">
            <item.icon className="size-5 text-primary" />
            <h3 className="mt-3 font-display text-sm font-semibold">{item.title}</h3>
            <p className="mt-1.5 text-sm text-muted-foreground">{item.body}</p>
          </div>
        ))}
      </section>

      <section className="mt-14">
        <div className="mb-3 flex items-end justify-between">
          <h2 className="font-display text-lg font-semibold">Recent analyses</h2>
          <Link to="/library" className="text-sm text-primary hover:underline">
            View library
          </Link>
        </div>
        <AnalysisTable rows={data ?? []} emptyMessage="No analyses yet — upload an APK to get started." />
      </section>
    </AppShell>
  );
}
