import { createFileRoute, Link } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { useServerFn } from "@tanstack/react-start";
import { useState } from "react";
import { toast } from "sonner";
import { Download, Sparkles } from "lucide-react";

import { AppShell } from "@/components/appguard/AppShell";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { getAnalysis, saveAiSummary } from "@/lib/appguard/store";
import { summarizeAnalysis } from "@/lib/ai.functions";
import { buildHtmlReport } from "@/lib/analysis/report";
import { overallScore } from "@/lib/analysis/scoring";
import { formatBytes, formatDate, scoreColor, severityClasses, shortHash, stateClasses } from "@/lib/appguard/format";

export const Route = createFileRoute("/analysis/$id")({
  head: () => ({
    meta: [
      { title: "Analysis report — AppGuard" },
      { name: "description", content: "Full static analysis report: manifest facts, permissions, components, capabilities, libraries, findings and scores." },
      { property: "og:title", content: "Analysis report — AppGuard" },
      { property: "og:description", content: "Explainable APK analysis report with cited evidence for every finding." },
    ],
  }),
  component: AnalysisPage,
});

function AnalysisPage() {
  const { id } = Route.useParams();
  const summarize = useServerFn(summarizeAnalysis);
  const [summary, setSummary] = useState<{ text: string; notice: string | null } | null>(null);
  const [summarizing, setSummarizing] = useState(false);

  const { data, isLoading, error } = useQuery({
    queryKey: ["analysis", id],
    queryFn: async () => {
      const record = await getAnalysis(id);
      if (!record) throw new Error("This analysis no longer exists.");
      return record;
    },
  });

  if (isLoading) {
    return (
      <AppShell>
        <p className="text-sm text-muted-foreground">Loading report…</p>
      </AppShell>
    );
  }

  if (error || !data) {
    return (
      <AppShell>
        <p className="text-sm text-severity-high">{(error as Error)?.message ?? "Not found."}</p>
        <Link to="/library" className="mt-3 inline-block text-sm text-primary hover:underline">
          Back to library
        </Link>
      </AppShell>
    );
  }

  const result = data.result;
  const shownSummary = summary ?? (data.aiSummary ? { text: data.aiSummary, notice: null } : null);

  const runSummary = async () => {
    setSummarizing(true);
    try {
      const response = await summarize({
        data: {
          packageName: result.manifest.packageName,
          versionName: result.manifest.versionName,
          minSdk: result.manifest.minSdkVersion,
          targetSdk: result.manifest.targetSdkVersion,
          sizeBytes: result.file.fileSize,
          scores: result.scores.map((score) => ({ label: score.label, value: score.value })),
          findings: result.findings.map((finding) => ({
            ruleId: finding.ruleId,
            title: finding.title,
            severity: finding.severity,
            description: finding.description,
            recommendation: finding.recommendation,
            evidence: finding.evidence.slice(0, 6),
          })),
          capabilities: result.capabilities.map((capability) => ({
            label: capability.label,
            state: capability.state,
            confidence: capability.confidence,
          })),
          permissions: result.permissions.map((permission) => permission.shortName),
          libraries: result.libraries.map((library) => library.name),
          coverageNotes: result.coverage.notes,
        },
      });
      setSummary({ text: response.text, notice: response.notice });
      if (!response.degraded) void saveAiSummary(id, response.text);
    } catch (cause) {
      toast.error("Could not generate summary", {
        description: cause instanceof Error ? cause.message : "Unknown error",
      });
    } finally {
      setSummarizing(false);
    }
  };

  const downloadReport = () => {
    const html = buildHtmlReport(result);
    const url = URL.createObjectURL(new Blob([html], { type: "text/html" }));
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `appguard-${result.manifest.packageName ?? "report"}.html`;
    anchor.click();
    URL.revokeObjectURL(url);
  };

  return (
    <AppShell>
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="font-display text-2xl font-semibold tracking-tight">
            {result.manifest.packageName ?? result.file.fileName}
          </h1>
          <p className="mt-1 font-mono text-xs text-muted-foreground">
            v{result.manifest.versionName ?? "?"} ({result.manifest.versionCode ?? "?"}) · SDK{" "}
            {result.manifest.minSdkVersion ?? "?"} → {result.manifest.targetSdkVersion ?? "?"} ·{" "}
            {formatBytes(result.file.fileSize)} · sha256 {shortHash(result.file.sha256)} ·{" "}
            {formatDate(data.createdAt)}
          </p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" onClick={downloadReport}>
            <Download className="size-4" /> HTML report
          </Button>
          <Button onClick={() => void runSummary()} disabled={summarizing}>
            <Sparkles className="size-4" /> {summarizing ? "Summarizing…" : "AI summary"}
          </Button>
        </div>
      </div>

      <div className="mt-6 grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
        <div className="rounded-lg border border-border bg-card p-4">
          <p className="font-mono text-[11px] uppercase tracking-wider text-muted-foreground">Overall</p>
          <p className={`font-display text-3xl font-semibold ${scoreColor(overallScore(result.scores))}`}>
            {overallScore(result.scores)}
          </p>
        </div>
        {result.scores.map((score) => (
          <div key={score.key} className="rounded-lg border border-border bg-card p-4">
            <p className="font-mono text-[11px] uppercase tracking-wider text-muted-foreground">{score.label}</p>
            <p className={`font-display text-3xl font-semibold ${scoreColor(score.value)}`}>{score.value}</p>
            <p className="mt-1 text-[11px] text-muted-foreground">
              {score.contributions.length} deduction{score.contributions.length === 1 ? "" : "s"}
            </p>
          </div>
        ))}
      </div>

      {shownSummary && (
        <div className="mt-6 rounded-lg border border-primary/30 bg-primary/5 p-5">
          <h2 className="font-display text-sm font-semibold">Executive summary</h2>
          <p className="mt-2 text-sm whitespace-pre-line text-foreground/90">{shownSummary.text}</p>
          {shownSummary.notice && (
            <p className="mt-3 text-xs text-muted-foreground">{shownSummary.notice}</p>
          )}
        </div>
      )}

      <Tabs defaultValue="findings" className="mt-8">
        <TabsList>
          <TabsTrigger value="findings">Findings ({result.findings.length})</TabsTrigger>
          <TabsTrigger value="capabilities">Capabilities</TabsTrigger>
          <TabsTrigger value="permissions">Permissions ({result.permissions.length})</TabsTrigger>
          <TabsTrigger value="components">Components ({result.manifest.components.length})</TabsTrigger>
          <TabsTrigger value="libraries">Libraries ({result.libraries.length})</TabsTrigger>
          <TabsTrigger value="scoring">Scoring</TabsTrigger>
        </TabsList>

        <TabsContent value="findings" className="space-y-3">
          {result.findings.length === 0 && (
            <p className="text-sm text-muted-foreground">No rules fired for this package.</p>
          )}
          {result.findings.map((finding) => (
            <div key={finding.id} className="rounded-lg border border-border bg-card p-5">
              <div className="flex flex-wrap items-center gap-2">
                <Badge variant="outline" className={severityClasses(finding.severity)}>
                  {finding.severity}
                </Badge>
                <h3 className="font-display text-sm font-semibold">{finding.title}</h3>
                <span className="font-mono text-[11px] text-muted-foreground">
                  {finding.ruleId} · −{finding.weight} {finding.scoreTarget} · {finding.confidence} confidence
                </span>
              </div>
              <p className="mt-2 text-sm text-muted-foreground">{finding.description}</p>
              <p className="mt-2 text-sm">
                <span className="font-semibold">Recommendation: </span>
                {finding.recommendation}
              </p>
              {finding.evidence.length > 0 && (
                <ul className="mt-3 space-y-1 rounded-md border border-border/70 bg-secondary/40 p-3 font-mono text-[11px] text-muted-foreground">
                  {finding.evidence.map((item, index) => (
                    <li key={index}>
                      <span className="text-primary">{item.source}</span> → {item.detail}
                    </li>
                  ))}
                </ul>
              )}
            </div>
          ))}
        </TabsContent>

        <TabsContent value="capabilities" className="grid gap-3 md:grid-cols-2">
          {result.capabilities.map((capability) => (
            <div key={capability.id} className="rounded-lg border border-border bg-card p-4">
              <div className="flex items-center gap-2">
                <Badge variant="outline" className={stateClasses(capability.state)}>
                  {capability.state.replace("_", " ")}
                </Badge>
                <h3 className="font-display text-sm font-semibold">{capability.label}</h3>
              </div>
              <p className="mt-2 text-sm text-muted-foreground">{capability.explanation}</p>
              {capability.evidence.length > 0 && (
                <ul className="mt-2 font-mono text-[11px] text-muted-foreground">
                  {capability.evidence.slice(0, 5).map((item, index) => (
                    <li key={index}>
                      {item.source} → {item.detail}
                    </li>
                  ))}
                </ul>
              )}
            </div>
          ))}
        </TabsContent>

        <TabsContent value="permissions" className="space-y-2">
          {result.permissions.map((permission) => (
            <div key={permission.name} className="rounded-lg border border-border bg-card p-4">
              <div className="flex flex-wrap items-center gap-2">
                <Badge variant="outline" className={severityClasses(permission.severityHint)}>
                  {permission.category}
                </Badge>
                <span className="font-mono text-xs">{permission.shortName}</span>
                <span className="text-[11px] text-muted-foreground">{permission.group}</span>
              </div>
              <p className="mt-2 text-sm text-muted-foreground">{permission.whyItMatters}</p>
            </div>
          ))}
        </TabsContent>

        <TabsContent value="components">
          <div className="overflow-x-auto rounded-lg border border-border">
            <table className="w-full text-sm">
              <thead className="bg-secondary/60 text-left font-mono text-[11px] uppercase tracking-wider text-muted-foreground">
                <tr>
                  <th className="px-4 py-2.5">Type</th>
                  <th className="px-4 py-2.5">Name</th>
                  <th className="px-4 py-2.5">Exported</th>
                  <th className="px-4 py-2.5">Permission</th>
                  <th className="px-4 py-2.5">Intent filters</th>
                </tr>
              </thead>
              <tbody>
                {result.manifest.components.map((component) => (
                  <tr key={`${component.type}:${component.name}`} className="border-t border-border/70">
                    <td className="px-4 py-2.5 text-xs text-muted-foreground">{component.type}</td>
                    <td className="px-4 py-2.5 font-mono text-xs">{component.name}</td>
                    <td className="px-4 py-2.5 text-xs">
                      {component.exported ? (
                        <span className="text-severity-medium">exported</span>
                      ) : (
                        <span className="text-muted-foreground">internal</span>
                      )}
                    </td>
                    <td className="px-4 py-2.5 font-mono text-[11px] text-muted-foreground">
                      {component.permission ?? "—"}
                    </td>
                    <td className="px-4 py-2.5 text-xs text-muted-foreground">{component.intentFilters.length}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </TabsContent>

        <TabsContent value="libraries" className="grid gap-3 md:grid-cols-2">
          {result.libraries.length === 0 && (
            <p className="text-sm text-muted-foreground">No known library signatures matched.</p>
          )}
          {result.libraries.map((library) => (
            <div key={library.id} className="rounded-lg border border-border bg-card p-4">
              <h3 className="font-display text-sm font-semibold">{library.name}</h3>
              <p className="font-mono text-[11px] text-muted-foreground">
                {library.category} · {library.confidence} confidence
              </p>
            </div>
          ))}
        </TabsContent>

        <TabsContent value="scoring" className="space-y-4">
          {result.scores.map((score) => (
            <div key={score.key} className="rounded-lg border border-border bg-card p-5">
              <div className="flex items-baseline justify-between">
                <h3 className="font-display text-sm font-semibold">{score.label}</h3>
                <span className={`font-display text-xl font-semibold ${scoreColor(score.value)}`}>
                  {score.value}/100
                </span>
              </div>
              <p className="mt-1 text-sm text-muted-foreground">{score.methodology}</p>
              <ul className="mt-3 space-y-1 font-mono text-[11px] text-muted-foreground">
                <li>start {score.start}</li>
                {score.contributions.map((contribution) => (
                  <li key={contribution.ruleId}>
                    −{contribution.deduction} · {contribution.ruleId} · {contribution.title}
                  </li>
                ))}
              </ul>
            </div>
          ))}
          <p className="text-xs text-muted-foreground">
            Rules version {result.rulesVersion}. Coverage: {result.coverage.notes.join(" ") || "full"}
          </p>
        </TabsContent>
      </Tabs>
    </AppShell>
  );
}