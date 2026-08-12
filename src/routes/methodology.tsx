import { createFileRoute } from "@tanstack/react-router";

import { AppShell } from "@/components/appguard/AppShell";
import { LIMITATIONS } from "@/lib/analysis/analyze";
import { RULE_DEFINITIONS, RULES_VERSION } from "@/lib/analysis/config/rules";

export const Route = createFileRoute("/methodology")({
  head: () => ({
    meta: [
      { title: "Methodology & rules — AppGuard" },
      { name: "description", content: "How AppGuard scores APKs: rule catalog, severity weights, evidence sources and documented limitations." },
      { property: "og:title", content: "Methodology & rules — AppGuard" },
      { property: "og:description", content: "The full AppGuard rule catalog, scoring weights and analysis limitations." },
    ],
  }),
  component: MethodologyPage,
});

function MethodologyPage() {
  return (
    <AppShell>
      <h1 className="font-display text-2xl font-semibold tracking-tight">Methodology</h1>
      <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
        Every score starts at 100 and is reduced only by rules that fired, each with a fixed weight.
        Nothing is heuristic-weighted after the fact, so a report can always be reproduced from its
        evidence. Rule catalog version{" "}
        <span className="font-mono text-foreground">{RULES_VERSION}</span>.
      </p>

      <section className="mt-8">
        <h2 className="font-display text-lg font-semibold">Rule catalog</h2>
        <div className="mt-3 overflow-x-auto rounded-lg border border-border">
          <table className="w-full text-sm">
            <thead className="bg-secondary/60 text-left font-mono text-[11px] uppercase tracking-wider text-muted-foreground">
              <tr>
                <th className="px-4 py-2.5">Rule</th>
                <th className="px-4 py-2.5">Category</th>
                <th className="px-4 py-2.5">Severity</th>
                <th className="px-4 py-2.5">Score</th>
                <th className="px-4 py-2.5">Weight</th>
                <th className="px-4 py-2.5">What it checks</th>
              </tr>
            </thead>
            <tbody>
              {RULE_DEFINITIONS.map((rule) => (
                <tr key={rule.id} className="border-t border-border/70 align-top">
                  <td className="px-4 py-3 font-mono text-xs text-foreground">{rule.id}</td>
                  <td className="px-4 py-3 text-xs text-muted-foreground">{rule.category}</td>
                  <td className="px-4 py-3 text-xs">{rule.severity}</td>
                  <td className="px-4 py-3 text-xs text-muted-foreground">{rule.scoreTarget}</td>
                  <td className="px-4 py-3 font-mono text-xs">−{rule.weight}</td>
                  <td className="px-4 py-3 text-xs text-muted-foreground">{rule.title}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section className="mt-10 max-w-3xl">
        <h2 className="font-display text-lg font-semibold">Documented limitations</h2>
        <ul className="mt-3 space-y-2 text-sm text-muted-foreground">
          {LIMITATIONS.map((limitation) => (
            <li key={limitation} className="flex gap-2">
              <span className="text-primary">—</span>
              <span>{limitation}</span>
            </li>
          ))}
        </ul>
      </section>
    </AppShell>
  );
}